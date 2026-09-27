"""
nftables compiler.

Takes a full NFW config (with firewall rules + aliases) and emits a
complete /etc/nftables.conf. Validates with nft -c -f before returning.

Design:
  - Base chains (input, forward, output) as in Phase 1
  - LAN and WAN logical rules → nft rules appended to input chain
  - Floating rules → appended to forward chain
  - Aliases → named sets
  - NAT rules → nat table chains
"""
from __future__ import annotations

import ipaddress
import subprocess
import tempfile
import os
from typing import Any

from .model import Rule


class CompileError(ValueError):
    pass


def _load_authenticated_sessions() -> list[tuple[str, int]]:
    """Return [(ip, ttl_seconds), ...] for active captive portal sessions.

    Called at compile time so every emitted cp_authenticated_v4 set
    reflects current authorized clients. Without this, every `nft -f`
    replaces the live kernel set with an empty one and silently logs
    out every client mid-session.
    """
    import sqlite3
    import time as _t
    now = int(_t.time())
    db_path = "/var/lib/nfw/captiveportal/sessions.db"
    try:
        with sqlite3.connect(db_path, timeout=3) as con:
            con.row_factory = sqlite3.Row
            rows = con.execute(
                "SELECT ip, expires_at FROM sessions "
                "WHERE revoked_at IS NULL AND expires_at > ?",
                (now,),
            ).fetchall()
        return [(r["ip"], max(1, int(r["expires_at"]) - now)) for r in rows]
    except Exception:
        return []


def _quote(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _iface_name(config: dict, iface_key: str) -> str:
    """Resolve a logical interface role to a physical device name.

    Reads from config["_resolved_interfaces"] if present (set by the
    caller via resolve_roles()), else falls back to auto-detection.
    """
    resolved = config.get("_resolved_interfaces")
    if isinstance(resolved, dict):
        return resolved.get(iface_key, iface_key)
    try:
        import sys
        if "/opt/nfw" not in sys.path:
            sys.path.insert(0, "/opt/nfw")
        from modules.network.interfaces import resolve_roles
        resolved = resolve_roles(config.get("network", {}))
        return resolved.get(iface_key, iface_key)
    except Exception:
        return iface_key


def _resolve_iface_ips(config: dict, role: str) -> list[str]:
    """Return configured IPs for a role's device.

    Reads the config store first, then falls back to live kernel addresses.
    Returns bare IPs (no CIDR suffix).
    """
    net = config.get("network", {})
    dev = (config.get("_resolved_interfaces") or {}).get(role) or net.get(role)
    if not dev:
        return []

    out: list[str] = []
    icfg = (net.get("interfaces") or {}).get(dev, {})
    if isinstance(icfg, dict):
        v4 = icfg.get("ipv4") or {}
        if v4.get("mode") == "static" and v4.get("address"):
            out.append(v4["address"])
        v6 = icfg.get("ipv6") or {}
        if v6.get("mode") == "static" and v6.get("address"):
            out.append(v6["address"])

    if not out:
        try:
            import subprocess, json as _json
            r = subprocess.run(
                ["/usr/sbin/ip", "-j", "addr", "show", "dev", dev],
                capture_output=True, text=True, timeout=5,
            )
            for iface in _json.loads(r.stdout or "[]"):
                for a in iface.get("addr_info", []):
                    if a.get("scope") == "global":
                        out.append(a["local"])
        except Exception:
            pass
    return out


def _alias_elements(alias: dict) -> list[str]:
    """Return the set elements for an alias, or raise if unsupported."""
    t = alias.get("type", "")
    vals = alias.get("values", [])
    if t in ("host", "network", "port"):
        return [str(v) for v in vals]
    if t == "port_range":
        return [str(v) for v in vals]
    if t in ("url", "geoip"):
        try:
            from modules.firewall.aliases import load_cached
            return load_cached(alias.get("name", ""))
        except Exception as e:
            raise CompileError(f"cannot load cached alias {alias.get('name')}: {e}")
    raise CompileError(f"unknown alias type: {t}")


def _addr_sets_and_ports(
    config: dict, rules: list[Rule]
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Return (ip_sets, port_sets) of alias names → element lists."""
    ip_sets: dict[str, list[str]] = {}
    port_sets: dict[str, list[str]] = {}
    for a in config.get("firewall", {}).get("aliases", []):
        name = a.get("name", "")
        t = a.get("type", "")
        if not name:
            continue
        if t in ("host", "network", "url", "geoip"):
            ip_sets[name] = _alias_elements(a)
        elif t in ("port", "port_range"):
            port_sets[name] = _alias_elements(a)
    return ip_sets, port_sets


def _render_source(spec: str) -> str | None:
    """Return the nft source clause fragment, or None for 'any'."""
    if not spec or spec == "any":
        return None
    if spec.startswith("@"):
        return f"ip saddr @{spec[1:]}"
    # single IP or CIDR
    try:
        if "/" in spec:
            ipaddress.ip_network(spec, strict=False)
            return f"ip saddr {spec}"
        ipaddress.ip_address(spec)
        return f"ip saddr {spec}"
    except ValueError:
        raise CompileError(f"invalid source: {spec}")


def _render_dest(spec: str) -> str | None:
    if not spec or spec == "any":
        return None
    if spec.startswith("@"):
        return f"ip daddr @{spec[1:]}"
    try:
        if "/" in spec:
            ipaddress.ip_network(spec, strict=False)
            return f"ip daddr {spec}"
        ipaddress.ip_address(spec)
        return f"ip daddr {spec}"
    except ValueError:
        raise CompileError(f"invalid dest: {spec}")


def _render_dport(spec: str) -> str | None:
    if not spec:
        return None
    parts = []
    for p in spec.split(","):
        p = p.strip()
        if not p:
            continue
        if p.startswith("@"):
            return f"tcp dport @{p[1:]}"  # assume tcp; refined by caller
        parts.append(p)
    if not parts:
        return None
    if len(parts) == 1:
        return f"dport {parts[0]}"
    return "dport { " + ", ".join(parts) + " }"


def _render_proto_port(proto: str, dport: str) -> str | None:
    """Return 'tcp dport N' / 'udp dport { N, M }' / None.

    In nftables, 'dport' must be preceded by the transport protocol
    name (tcp/udp), not by 'meta l4proto tcp'. The latter produces
    'No symbol type information' from nft.
    """
    if not dport:
        return None
    spec = dport.strip()
    if not spec:
        return None
    if proto not in ("tcp", "udp"):
        raise CompileError(f"dport only valid for tcp/udp, not {proto}")
    if spec.startswith("@"):
        return f"{proto} dport @{spec[1:]}"
    items = [s.strip() for s in spec.split(",") if s.strip()]
    if not items:
        return None
    if len(items) == 1:
        return f"{proto} dport {items[0]}"
    return f"{proto} dport {{ {', '.join(items)} }}"


def _rule_to_nft(rule: Rule, config: dict) -> str:
    """Return the nft rule body for a logical rule.

    Handles basic fields plus the Phase 9.7a advanced settings:
      icmp_type, tcpflags1/2, statetype, tag/tagged, dscp, log_limit.
    The `schedule` field is resolved by the caller: rules whose schedule
    is not currently active are omitted entirely.
    """
    parts: list[str] = []
    iface = _iface_name(config, rule.interface)
    if rule.direction == "in":
        parts.append(f"iifname {_quote(iface)}")
    else:
        parts.append(f"oifname {_quote(iface)}")

    # --- TCP flags ---
    if rule.tcpflags1:
        flag_bits = "|".join(f"tcp flag {f.lower()}" for f in rule.tcpflags1.split(",") if f)
        if rule.tcpflags2:
            mask_bits = "|".join(f"tcp flag {f.lower()}" for f in rule.tcpflags2.split(",") if f)
            parts.append(f"tcp flags & ({mask_bits}) == ({flag_bits})")
        else:
            parts.append(f"tcp flags & ({flag_bits}) != 0")

    # --- Protocol / port ---
    port_clause = _render_proto_port(rule.proto, rule.dport)
    if port_clause:
        parts.append(port_clause)
    elif rule.proto in ("tcp", "udp", "icmp", "icmpv6"):
        parts.append(f"meta l4proto {rule.proto}")

    # --- ICMP type match ---
    if rule.icmp_type:
        if rule.proto == "icmpv6" or rule.icmp_type.startswith(("nd-", "neighbor-", "router-")):
            parts.append(f"icmpv6 type {rule.icmp_type}")
        else:
            parts.append(f"icmp type {rule.icmp_type}")

    # --- Conntrack state override ---
    if rule.statetype:
        parts.append(f"ct state {rule.statetype}")

    # --- Packet mark matching ---
    if rule.tagged:
        parts.append(f"meta mark {rule.tagged}")

    # --- Source / dest ---
    src_clause = _render_source(rule.source)
    if src_clause:
        parts.append(src_clause)
    dst_clause = _render_dest(rule.dest)
    if dst_clause:
        parts.append(dst_clause)

    # --- Action / mark / dscp ---
    act = {"pass": "accept", "block": "drop", "reject": "reject"}[rule.action]
    # if user set dscp, apply before the verdict
    if rule.dscp:
        parts.append(f'ip dscp set {rule.dscp}')
    if rule.tag:
        parts.append(f'meta mark set {rule.tag}')

    # --- Logging ---
    if rule.log:
        limit = rule.log_limit or "3/minute"
        parts.append(f'limit rate {limit} log prefix "NFW-{rule.id}: " level info')

    parts.append(act)
    return "        " + " ".join(parts)


def _active_schedules_now(schedules: list) -> set[str]:
    """Return the names of schedules that are active right now."""
    import datetime
    now = datetime.datetime.now()
    day_key = ["mon","tue","wed","thu","fri","sat","sun"][now.weekday()]
    hhmm = now.strftime("%H:%M")
    out: set[str] = set()
    for s in schedules or []:
        if not isinstance(s, dict) or not s.get("enabled", True):
            continue
        name = s.get("name")
        if not name:
            continue
        for r in s.get("ranges", []) or []:
            days = r.get("days", [])
            if days and day_key not in days:
                continue
            start = r.get("start", "00:00")
            end = r.get("end", "23:59")
            # handles simple HH:MM comparisons (no cross-midnight in this version)
            if start <= hhmm <= end:
                out.add(name)
                break
    return out


def compile_ruleset(config: dict) -> str:
    """
    Compile a full nftables ruleset from the config. Returns the ruleset text.

    Raises CompileError on invalid config.
    """
    fw = config.get("firewall", {})
    rules_data = fw.get("rules", []) or []
    _active_sched = _active_schedules_now(fw.get("schedules", []))
    rules = [Rule.from_dict(d) for d in rules_data]
    for r in rules:
        r.validate()

    ip_sets, port_sets = _addr_sets_and_ports(config, rules)

    lines: list[str] = []
    lines.append("#!/usr/sbin/nft -f")
    lines.append("#")
    lines.append("# NFW ruleset — GENERATED. Do not edit by hand.")
    lines.append("# Source: NFW config store")
    lines.append("#")
    # NFW owns only its own nftables tables.
    # Do NOT flush the global ruleset because other services
    # such as miniupnpd may own their own nftables objects.
    lines.append("destroy table inet nfw_filter")
    lines.append("destroy table ip nfw_nat")
    lines.append("destroy table ip6 nfw_npt")
    lines.append("")

    wan = _iface_name(config, "wan")
    lan = _iface_name(config, "lan")
    lines.append(f'define WAN_IF = {_quote(wan)}')
    lines.append(f'define LAN_IF = {_quote(lan)}')
    lines.append("")

    # --- filter table ----------------------------------------------------
    lines.append("table inet nfw_filter {")
    # PHASE-9.7B-NORM
    _norm_cfg = (fw.get("normalization", {}) or {})
    if _norm_cfg.get("syn_flood_protect", False):
        lines.append("    set syn_flood_v4 {")
        lines.append("        type ipv4_addr")
        lines.append("        flags dynamic, timeout")
        lines.append("        timeout 60s")
        lines.append("        size 65536")
        lines.append("    }")
        lines.append("")


    # CAPTIVEPORTAL-FILTER-SET
    _cp_svc = (config.get("services", {}) or {}).get("captiveportal_config", {}) or {}
    _cp_enabled = bool(_cp_svc.get("enabled", False))
    # CP-AUTO-RULES-DISABLED: when True, suppress all auto firewall rules
    # (redirect, gate, bypass set emission). Manual rules in config.firewall.rules
    # still apply. Users can build their own CP integration in that case.
    if _cp_svc.get("disable_auto_rules", False):
        _cp_enabled = False
    _cp_port = int(_cp_svc.get("portal_port", 8081))
    if _cp_enabled:
        lines.append("    set cp_authenticated_v4 {")
        lines.append("        type ipv4_addr")
        lines.append("        flags timeout")
        lines.append("        size 65536")
        _sess = _load_authenticated_sessions()
        if _sess:
            _elems = ", ".join(
                f"{ip} timeout {ttl}s" for ip, ttl in _sess)
            lines.append(f"        elements = {{ {_elems} }}")
        lines.append("    }")
        lines.append("")

    # CP-WALLED-GARDEN-PARSE
    # Parse the walled_garden config list. Entries may be bare IPs or CIDRs.
    _wg_ips: list[str] = []
    if _cp_enabled:
        import ipaddress as _ipaddr
        for _e in (_cp_svc.get("walled_garden") or []):
            _e = str(_e).strip()
            if not _e or _e.startswith("#"):
                continue
            try:
                if "/" in _e:
                    _net = _ipaddr.ip_network(_e, strict=False)
                    if _net.version == 4:
                        _wg_ips.append(str(_net))
                else:
                    _ip = _ipaddr.ip_address(_e)
                    if _ip.version == 4:
                        _wg_ips.append(str(_ip))
            except ValueError:
                continue

    # CP-BYPASS-PARSE
    # Phase 9.18b3: merge hostname-resolved IPs into walled garden, and load
    # the MAC-resolved IP set. Caches are populated by the bypass refresh
    # timer (every bypass_refresh_seconds). Missing cache = empty set.
    _cp_bypassed_ips: list[str] = []
    if _cp_enabled:
        try:
            import sys as _sys
            if "/opt/nfw" not in _sys.path:
                _sys.path.insert(0, "/opt/nfw")
            if "/opt/nfw/core" not in _sys.path:
                _sys.path.insert(0, "/opt/nfw/core")
            from modules.services import captiveportal as _cpmod
            _cp_bypassed_ips = _cpmod.load_bypass_mac_ips()
            _wg_host_ips = _cpmod.load_bypass_hostname_ips()
            # merge hostname IPs into walled garden, dedupe
            _seen_wg = set(_wg_ips)
            for _ip in _wg_host_ips:
                if _ip not in _seen_wg:
                    _wg_ips.append(_ip)
                    _seen_wg.add(_ip)
        except Exception:
            _cp_bypassed_ips = []

    # CP-WALLED-GARDEN-FILTER-SET
    if _cp_enabled and _wg_ips:
        lines.append("    set walled_garden_v4 {")
        lines.append("        type ipv4_addr")
        lines.append("        flags interval")
        lines.append(f"        elements = {{ {', '.join(_wg_ips)} }}")
        lines.append("    }")
        lines.append("")
    # CP-BYPASS-FILTER-SET
    if _cp_enabled and _cp_bypassed_ips:
        lines.append("    set cp_bypassed_v4 {")
        lines.append("        type ipv4_addr")
        lines.append("        flags interval")
        lines.append(f"        elements = {{ {', '.join(_cp_bypassed_ips)} }}")
        lines.append("    }")
        lines.append("")

    # IP aliases as sets
    for name, elems in ip_sets.items():
        if not elems:
            continue
        joined = ", ".join(elems)
        lines.append(f"    set {name} {{")
        lines.append("        type ipv4_addr")
        lines.append("        flags interval")
        lines.append(f"        elements = {{ {joined} }}")
        lines.append("    }")
        lines.append("")

    # Port aliases as sets
    for name, elems in port_sets.items():
        if not elems:
            continue
        joined = ", ".join(elems)
        lines.append(f"    set {name} {{")
        lines.append("        type inet_service")
        lines.append(f"        elements = {{ {joined} }}")
        lines.append("    }")
        lines.append("")

    # input chain
    lines.append("    chain input {")
    lines.append("        type filter hook input priority filter; policy drop;")
    lines.append("        iif lo accept")
    lines.append("        ct state established,related accept")
    lines.append("        ct state invalid drop")
    lines.append("        icmp type echo-request limit rate 5/second accept")
    lines.append("        icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert,")
    lines.append("                      nd-router-advert, nd-router-solicit } accept")
    lines.append("        icmpv6 type echo-request limit rate 5/second accept")
    # PHASE-9.7B-NORM: input-chain normalization
    if _norm_cfg.get("icmp_drop_redirects", True):
        lines.append("        icmp type redirect drop")
    if _norm_cfg.get("icmp_drop_source_quench", True):
        lines.append("        icmp type source-quench drop")
    if _norm_cfg.get("syn_flood_protect", False):
        lines.append(
            "        tcp flags & (fin|syn|rst|ack) == syn "
            "update @syn_flood_v4 { ip saddr limit rate 30/minute } accept"
        )
        lines.append("        tcp flags & (fin|syn|rst|ack) == syn drop")
    if _norm_cfg.get("log_martians", False):
        lines.append(
            '        iifname $WAN_IF ip saddr '
            '{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 127.0.0.0/8 } '
            'log prefix "NFW-MARTIAN: " level warn'
        )

    # Rule: always allow management on LAN (lockout protection)
    # Anti-lockout rule (OPNsense parity): scope by destination IP so
    # LAN clients cannot reach WAN-side management ports via local routing.
    lan_ips = _resolve_iface_ips(config, "lan")
    if lan_ips:
        for ip in lan_ips:
            family = "ip6" if ":" in ip else "ip"
            lines.append(f'        iifname $LAN_IF {family} daddr {ip} tcp dport {{ 22, 80, 443, 8080, 8443 }} accept')
        lines.append(f'        iifname $LAN_IF ip6 daddr fe80::/10 tcp dport {{ 22, 80, 443, 8080, 8443 }} accept')
    else:
        lines.append(f'        iifname $LAN_IF tcp dport {{ 22, 80, 443, 8080, 8443 }} accept')

    # LAN-DNS-ANTILOCKOUT — LAN clients must reach the firewall's resolver.
    if lan_ips:
        for ip in lan_ips:
            family = "ip6" if ":" in ip else "ip"
            lines.append(f'        iifname $LAN_IF {family} daddr {ip} udp dport 53 accept')
            lines.append(f'        iifname $LAN_IF {family} daddr {ip} tcp dport 53 accept')
    else:
        lines.append('        iifname $LAN_IF udp dport 53 accept')
        lines.append('        iifname $LAN_IF tcp dport 53 accept')

    # CAPTIVEPORTAL-INPUT
    if _cp_enabled:
        lines.append(f'        iifname $LAN_IF tcp dport {_cp_port} accept')

    # ================================================================
    # UPnP-INPUT-RULES — allow SSDP + IGD HTTP on LAN when UPnP enabled
    # ================================================================
    # When NAT UPnP is on, miniupnpd needs to:
    #   * receive SSDP M-SEARCH on udp/1900 (multicast to 239.255.255.250)
    #   * serve the IGD description + control over tcp/5000
    _upnp_cfg = (config.get("firewall", {}) or {}).get("nat", {}).get("upnp", {}) or {}
    if _upnp_cfg.get("enabled", False):
        lines.append('        iifname $LAN_IF udp dport 1900 accept')
        lines.append('        iifname $LAN_IF tcp dport 5000 accept')

    # User rules for input direction
    for r in sorted(rules, key=lambda x: x.order):
        if not r.enabled or r.direction != "in":
            continue
        if r.schedule and r.schedule not in _active_sched:
            continue
        try:
            lines.append(_rule_to_nft(r, config))
        except CompileError as e:
            raise CompileError(f"rule {r.id}: {e}")

    lines.append('        limit rate 3/minute log prefix "NFW-INPUT-DROP: " level warn')
    lines.append("    }")
    lines.append("")

    # forward chain
    lines.append("    chain forward {")
    lines.append("        type filter hook forward priority filter; policy drop;")
    lines.append("        ct state established,related accept")
    lines.append("        ct state invalid drop")

    # Phase 9.6: permit connections that have been DNATed
    # by an existing NAT facility such as port-forwarding,
    # 1:1 NAT, or UPnP.
    lines.append("        ct status dnat accept")
    # PHASE-9.7B-NORM: forward-chain normalization
    if _norm_cfg.get("mss_clamp", False):
        _mss_size = int(_norm_cfg.get("mss_clamp_size", 1452))
        lines.append(
            f"        tcp flags syn tcp option maxseg size set {_mss_size}"
        )
    if _norm_cfg.get("frag_policy", "pass") == "drop":
        lines.append("        ip frag-off & 0x1fff != 0 drop")

    # UPnP-MINIUPNPD: jump to miniupnpd's dynamic filter chain.
    # Referenced by OPNsense-style UPnP (see miniupnpd_functions.sh).

    # CAPTIVEPORTAL-FORWARD-GATE (OPNsense model)
    if _cp_enabled:
        if _cp_bypassed_ips:
            lines.append(
                '        # CP-AUTO: MAC-bypassed clients'
            )
            lines.append(
                '        iifname $LAN_IF oifname $WAN_IF '
                'ip saddr @cp_bypassed_v4 accept'
            )
        if _wg_ips:
            lines.append(
                '        # CP-AUTO: walled garden (allowed before authentication)'
            )
            lines.append(
                '        iifname $LAN_IF oifname $WAN_IF '
                'ip daddr @walled_garden_v4 accept'
            )
        lines.append(
            '        # CP-AUTO: authenticated clients'
        )
        lines.append(
            '        iifname $LAN_IF oifname $WAN_IF '
            'ip saddr @cp_authenticated_v4 accept'
        )
    else:
        lines.append(
            f'        iifname $LAN_IF oifname $WAN_IF accept'
        )

    for r in sorted(rules, key=lambda x: x.order):
        if not r.enabled or r.direction != "out":
            continue
        if r.schedule and r.schedule not in _active_sched:
            continue
        try:
            lines.append(_rule_to_nft(r, config))
        except CompileError as e:
            raise CompileError(f"rule {r.id}: {e}")

    lines.append("    }")
    lines.append("")

    # output chain
    lines.append("    chain output {")
    lines.append("        type filter hook output priority filter; policy accept;")
    lines.append("    }")
    lines.append("}")
    lines.append("")

    # --- NAT -------------------------------------------------------------

    nat = fw.get("nat", {}) or {}

    one_to_one = nat.get(
        "one_to_one",
        []
    ) or []

    npt = nat.get(
        "npt",
        []
    ) or []

    reflection = nat.get(
        "reflection",
        {}
    ) or {}

    # Resolve WAN IPs once, used by reflection rules for both
    # 1:1 NAT and port-forwards. (PF-REFLECTION-DNAT)
    _refl_wan_ips = [x for x in _resolve_iface_ips(config, "wan") if ":" not in x]


    # ================================================================
    # IPv4 NAT
    # ================================================================

    lines.append("table ip nfw_nat {")
    # CAPTIVEPORTAL-NAT-SET
    if _cp_enabled:
        lines.append("    set cp_authenticated_v4 {")
        lines.append("        type ipv4_addr")
        lines.append("        flags timeout")
        lines.append("        size 65536")
        _sess_nat = _load_authenticated_sessions()
        if _sess_nat:
            _elems_nat = ", ".join(
                f"{ip} timeout {ttl}s" for ip, ttl in _sess_nat)
            lines.append(f"        elements = {{ {_elems_nat} }}")
        lines.append("    }")
        lines.append("")
    # CP-WALLED-GARDEN-NAT-SET
    if _cp_enabled and _wg_ips:
        lines.append("    set walled_garden_v4 {")
        lines.append("        type ipv4_addr")
        lines.append("        flags interval")
        lines.append(f"        elements = {{ {', '.join(_wg_ips)} }}")
        lines.append("    }")
        lines.append("")
    # CP-BYPASS-NAT-SET
    if _cp_enabled and _cp_bypassed_ips:
        lines.append("    set cp_bypassed_v4 {")
        lines.append("        type ipv4_addr")
        lines.append("        flags interval")
        lines.append(f"        elements = {{ {', '.join(_cp_bypassed_ips)} }}")
        lines.append("    }")
        lines.append("")


    lines.append("    chain prerouting {")
    lines.append(
        "        type nat hook prerouting priority dstnat; policy accept;"
    )
    # CAPTIVEPORTAL-REDIRECT (OPNsense model: excluded from redirect if
    # authenticated, MAC-bypassed, or targeting a walled-garden destination)
    if _cp_enabled:
        lines.append(
            '        # CP-AUTO: redirect unauthenticated HTTP to the portal'
        )
        cond = 'iifname $LAN_IF ip saddr != @cp_authenticated_v4'
        if _cp_bypassed_ips:
            cond += ' ip saddr != @cp_bypassed_v4'
        if _wg_ips:
            cond += ' ip daddr != @walled_garden_v4'
        lines.append(
            f'        {cond} tcp dport 80 redirect to :{_cp_port}'
        )

    # Existing port-forward implementation is intentionally preserved.
    # It is NOT part of Phase 9.6; this code only keeps compatibility
    # with the already implemented Phase 4 NAT feature.
    for pf in nat.get(
        "port_forwards",
        []
    ) or []:

        if not pf.get(
            "enabled",
            True,
        ):
            continue

        src_iface = pf.get(
            "interface",
            "wan",
        )

        wan_if = _iface_name(
            config,
            src_iface,
        )

        proto = pf.get(
            "proto",
            "tcp",
        )

        ext_port = pf.get(
            "ext_port"
        )

        int_ip = pf.get(
            "int_ip"
        )

        int_port = pf.get(
            "int_port",
            ext_port,
        )

        desc = pf.get(
            "description",
            "",
        )

        cmt = (
            f" comment {_quote(desc)}"
            if desc
            else ""
        )

        lines.append(
            f'        iifname {_quote(wan_if)} '
            f'{proto} dport {ext_port} '
            f'dnat to {int_ip}:{int_port}'
            f'{cmt}'
        )

    # ---------------------------------------------------------------
    # 1:1 IPv4 inbound DNAT
    # ---------------------------------------------------------------

    for rule in one_to_one:

        if not rule.get(
            "enabled",
            True,
        ):
            continue

        external = str(
            rule.get(
                "external_ip",
                "",
            )
        )

        internal = str(
            rule.get(
                "internal_ip",
                "",
            )
        )

        try:
            if (
                ipaddress.ip_address(
                    external
                ).version != 4
                or
                ipaddress.ip_address(
                    internal
                ).version != 4
            ):
                raise ValueError
        except ValueError as exc:
            raise CompileError(
                f"invalid 1:1 IPv4 mapping "
                f"{external} -> {internal}"
            ) from exc

        interface = _iface_name(
            config,
            rule.get(
                "interface",
                "wan",
            ),
        )

        desc = rule.get(
            "description",
            "",
        )

        cmt = (
            f" comment {_quote(desc)}"
            if desc
            else ""
        )

        lines.append(
            f'        iifname {_quote(interface)} '
            f'ip daddr {external} '
            f'dnat to {internal}'
            f'{cmt}'
        )

    # ---------------------------------------------------------------
    # 1:1 NAT reflection inbound DNAT
    # ---------------------------------------------------------------

    if reflection.get(
        "enabled",
        True,
    ):

        lan_interface = _iface_name(
            config,
            "lan",
        )

        for rule in one_to_one:

            if not rule.get(
                "enabled",
                True,
            ):
                continue

            if not rule.get(
                "reflection",
                True,
            ):
                continue

            external = str(
                rule.get(
                    "external_ip",
                    "",
                )
            )

            internal = str(
                rule.get(
                    "internal_ip",
                    "",
                )
            )

            if not external or not internal:
                continue

            lines.append(
                f'        iifname {_quote(lan_interface)} '
                f'ip daddr {external} '
                f'dnat to {internal}'
            )

    # ---------------------------------------------------------------
    # Port-forward reflection DNAT (hairpin) — PF-REFLECTION-DNAT
    # A LAN client hitting the WAN IP on a forwarded port is redirected
    # to the internal target. Requires the WAN IPs (above).
    # ---------------------------------------------------------------

    if reflection.get("enabled", True) and nat.get("port_forwards"):

        lan_interface = _iface_name(config, "lan")

        for pf in nat.get("port_forwards", []) or []:

            if not pf.get("enabled", True):
                continue

            proto = pf.get(
                "proto",
                "tcp",
            )

            ext_port = pf.get(
                "ext_port",
            )

            int_ip = pf.get(
                "int_ip",
            )

            int_port = pf.get(
                "int_port",
                ext_port,
            )

            if not (ext_port and int_ip):
                continue

            for _ip in (_refl_wan_ips or ["0.0.0.0"]):

                lines.append(
                    f'        iifname {_quote(lan_interface)} '
                    f'ip daddr {_ip} '
                    f'{proto} dport {ext_port} '
                    f'dnat to {int_ip}:{int_port}'
                )

    # UPnP-MINIUPNPD: jump into miniupnpd's dynamic chain, then close
    # the prerouting chain and declare the target chain.
    lines.append("    }")
    lines.append("")
    lines.append("    chain prerouting_miniupnpd {")
    lines.append("    }")
    lines.append("")

    lines.append("    chain postrouting {")
    lines.append(
        "        type nat hook postrouting priority srcnat; policy accept;"
    )

    # ---------------------------------------------------------------
    # Existing explicit outbound SNAT
    # ---------------------------------------------------------------

    for r in nat.get(
        "outbound",
        []
    ) or []:

        if not r.get(
            "enabled",
            True,
        ):
            continue

        iface = _iface_name(
            config,
            r.get(
                "interface",
                "wan",
            ),
        )

        src = r.get(
            "source",
            "any",
        )

        snat_to = r.get(
            "snat_to"
        )

        if src != "any" and snat_to:

            src_clause = (
                f"ip saddr @{src[1:]}"
                if str(src).startswith("@")
                else f"ip saddr {src}"
            )

            lines.append(
                f'        oifname {_quote(iface)} '
                f'{src_clause} '
                f'snat to {snat_to}'
            )

    # ---------------------------------------------------------------
    # 1:1 IPv4 outbound SNAT
    # ---------------------------------------------------------------

    for rule in one_to_one:

        if not rule.get(
            "enabled",
            True,
        ):
            continue

        external = str(
            rule.get(
                "external_ip",
                "",
            )
        )

        internal = str(
            rule.get(
                "internal_ip",
                "",
            )
        )

        interface = _iface_name(
            config,
            rule.get(
                "interface",
                "wan",
            ),
        )

        lines.append(
            f'        oifname {_quote(interface)} '
            f'ip saddr {internal} '
            f'snat to {external}'
        )

    # ---------------------------------------------------------------
    # NAT reflection SNAT
    # ---------------------------------------------------------------

    if reflection.get(
        "enabled",
        True,
    ):

        lan_ip = next(
            (
                x
                for x in _resolve_iface_ips(
                    config,
                    "lan",
                )
                if ":" not in x
            ),
            None,
        )

        lan_interface = _iface_name(
            config,
            "lan",
        )

        if lan_ip:

            for rule in one_to_one:

                if not rule.get(
                    "enabled",
                    True,
                ):
                    continue

                if not rule.get(
                    "reflection",
                    True,
                ):
                    continue

                internal = str(
                    rule.get(
                        "internal_ip",
                        "",
                    )
                )

                if internal:

                    lines.append(
                        f'        iifname {_quote(lan_interface)} '
                        f'oifname {_quote(lan_interface)} '
                        f'ip daddr {internal} '
                        f'snat to {lan_ip}'
                    )

    # ---------------------------------------------------------------
    # Port-forward reflection SNAT (hairpin) — PF-REFLECTION-SNAT
    # After the inbound DNAT rewrote the destination to the internal host,
    # the reply from the internal host would otherwise route directly to
    # the original LAN client's IP, which expects a reply from the WAN IP.
    # Masquerade the hairpinned traffic so the reply comes back through
    # the firewall and gets un-DNATed.
    # ---------------------------------------------------------------

    if reflection.get("enabled", True) and nat.get("port_forwards"):

        lan_interface = _iface_name(config, "lan")

        lines.append(
            f'        iifname {_quote(lan_interface)} '
            f'oifname {_quote(lan_interface)} '
            f'masquerade'
        )

    # Dynamic WAN masquerade remains last.
    lines.append(
        '        oifname $WAN_IF masquerade'
    )

    # UPnP-MINIUPNPD: jump into miniupnpd's dynamic chain, then close
    # the postrouting chain and declare the target chain.
    lines.append("    }")
    lines.append("")
    lines.append("    chain postrouting_miniupnpd {")
    lines.append("    }")
    lines.append("}")
    lines.append("")

    # ================================================================
    # NPTv6
    # ================================================================

    if npt:

        lines.append(
            "table ip6 nfw_npt {"
        )

        lines.append(
            "    chain prerouting {"
        )

        lines.append(
            "        type nat hook prerouting priority dstnat; policy accept;"
        )

        for rule in npt:

            if not rule.get(
                "enabled",
                True,
            ):
                continue

            external = ipaddress.ip_network(
                str(
                    rule.get(
                        "external_prefix",
                        "",
                    )
                ),
                strict=True,
            )

            internal = ipaddress.ip_network(
                str(
                    rule.get(
                        "internal_prefix",
                        "",
                    )
                ),
                strict=True,
            )

            if (
                external.prefixlen
                !=
                internal.prefixlen
            ):
                raise CompileError(
                    "NPTv6 prefixes must have equal length"
                )

            lines.append(
                f'        dnat ip6 prefix to ip6 daddr map '
                f'{{ {external} : {internal} }}'
            )

        lines.append(
            "    }"
        )

        lines.append("")

        lines.append(
            "    chain postrouting {"
        )

        lines.append(
            "        type nat hook postrouting priority srcnat; policy accept;"
        )

        for rule in npt:

            if not rule.get(
                "enabled",
                True,
            ):
                continue

            external = ipaddress.ip_network(
                str(
                    rule.get(
                        "external_prefix",
                        "",
                    )
                ),
                strict=True,
            )

            internal = ipaddress.ip_network(
                str(
                    rule.get(
                        "internal_prefix",
                        "",
                    )
                ),
                strict=True,
            )

            if (
                external.prefixlen
                !=
                internal.prefixlen
            ):
                raise CompileError(
                    "NPTv6 prefixes must have equal length"
                )

            interface = _iface_name(
                config,
                rule.get(
                    "interface",
                    "wan",
                ),
            )

            lines.append(
                f'        oifname {_quote(interface)} '
                f'snat ip6 prefix to ip6 saddr map '
                f'{{ {internal} : {external} }}'
            )

        lines.append(
            "    }"
        )

        lines.append(
            "}"
        )

        lines.append("")


    return "\n".join(lines)


def validate_ruleset(ruleset: str) -> tuple[bool, str]:
    """Validate with nft -c -f. Returns (ok, stderr)."""
    fd, path = tempfile.mkstemp(prefix="nfw-validate-", suffix=".nft")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(ruleset)
        p = subprocess.run(["/usr/sbin/nft", "-c", "-f", path],
                           capture_output=True, text=True, timeout=10)
        return p.returncode == 0, p.stderr
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
