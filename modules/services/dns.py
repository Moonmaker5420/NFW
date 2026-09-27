"""Unbound compiler: config → /etc/unbound/unbound.conf.d/nfw.conf."""
from __future__ import annotations
from typing import Any


class CompileError(ValueError):
    pass


def _parse_forwarder(f: dict) -> tuple[str, str]:
    """Return (ip, tls_name_or_empty) from a forwarder dict."""
    addr = f.get("address", "")
    tls = f.get("tls_name", "") or ""
    if "@" in addr and not tls:
        # "1.1.1.1@853" — extract ip
        addr = addr.split("@", 1)[0]
    return addr, tls


def compile_unbound(config: dict) -> str:
    svc = config.get("services", {}).get("dns_config", {}) or {}

    L: list[str] = []
    L.append("# NFW — GENERATED unbound.conf. Do not edit by hand.")
    L.append("server:")

    listens = svc.get("listen") or ["0.0.0.0"]
    for addr in listens:
        L.append(f"    interface: {addr}")
    L.append(f"    port: {int(svc.get('port', 53))}")

    for ac in svc.get("access_control", []) or []:
        L.append(f"    access-control: {ac}")

    if svc.get("hide_identity", True):
        L.append("    hide-identity: yes")
    if svc.get("hide_version", True):
        L.append("    hide-version: yes")
    if svc.get("qname_minimisation", True):
        L.append("    qname-minimisation: yes")
    if svc.get("dnssec", True):
        L.append("    auto-trust-anchor-file: \"/var/lib/unbound/root.key\"")
    if svc.get("prefetch", True):
        L.append("    prefetch: yes")
    if svc.get("so_reuseport", True):
        L.append("    so-reuseport: yes")
    # NOTE: Unbound has no "recursion: yes|no" keyword.
    # Recursion is on by default. To disable, set "deny-any: yes"
    # or configure allow-recursion restrictions.
    if not svc.get("recursive", True):
        L.append("    deny-any: yes")

    num_threads = int(svc.get("num_threads", 2))
    L.append(f"    num-threads: {num_threads}")

    # Host overrides
    overrides = svc.get("host_overrides", []) or []
    if overrides:
        L.append("")
        L.append("    # Host overrides")
        # Group by hostname into a local-data block
        for h in overrides:
            name = h.get("hostname", "").strip().rstrip(".")
            domain = svc.get("local_zone", "lan").strip(".")
            fqdn = f"{name}.{domain}" if name and "." not in name else name
            typ = h.get("type", "A").upper()
            value = h.get("value", "")
            if not fqdn or not value:
                continue
            if typ == "A":
                L.append(f'    local-data: "{fqdn} A {value}"')
            elif typ == "AAAA":
                L.append(f'    local-data: "{fqdn} AAAA {value}"')
            elif typ == "CNAME":
                L.append(f'    local-data: "{fqdn} CNAME {value}."')

    # Local zone (serve our own domain authoritatively)
    local_zone = svc.get("local_zone", "lan")
    if local_zone:
        L.append("")
        L.append("    # Local zone")
        L.append(f'    local-zone: "{local_zone}." static')

    # Blocklist
    bl = svc.get("blocklists", {}) or {}
    if bl.get("enabled"):
        domains = bl.get("domains") or []
        if domains:
            L.append("")
            L.append("    # Blocklist")
            for d in domains:
                d = d.strip().rstrip(".")
                if d:
                    L.append(f'    local-zone: "{d}." always_nxdomain')

    # DoT forwarders
    if svc.get("do_tls") or svc.get("forwarders_tls"):
        L.append("")
        L.append("forward-zone:")
        L.append('    name: "."')
        L.append("    forward-tls-upstream: yes")
        for f in svc.get("forwarders_tls", []) or []:
            ip, tls_name = _parse_forwarder(f)
            if ip and tls_name:
                L.append(f"    forward-addr: {ip}@{853}#{tls_name}"
                         if "@" not in ip else f"    forward-addr: {ip}#{tls_name}")
            elif ip:
                L.append(f"    forward-addr: {ip}")

    # Extra forward zones
    for fz in svc.get("forward_zones", []) or []:
        name = fz.get("name")
        servers = fz.get("servers", []) or []
        if not name or not servers:
            continue
        L.append("")
        L.append("forward-zone:")
        L.append(f'    name: "{name}"')
        for s in servers:
            L.append(f"    forward-addr: {s}")

    L.append("")
    return "\n".join(L)
