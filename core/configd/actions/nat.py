"""NAT configd actions — aligned with modules/firewall/compiler.py.

Field names:
  * 1:1 NAT uses external_ip / internal_ip
  * NPT is a flat list (not {"entries": [...]})
  * Reflection: nat.reflection.enabled + per-rule "reflection" flag
"""
from __future__ import annotations

import logging
import os
import secrets
import subprocess
import sys
from typing import Any

from configd.registry import action

sys.path.insert(0, "/opt/nfw")
sys.path.insert(0, "/opt/nfw/core")

from config import store as cfg_store
from config.schema import validate

LOG = logging.getLogger("configd.nat")

UPNP_CONF = "/etc/miniupnpd/miniupnpd.conf"
UPNP_SERVICE = "miniupnpd.service"


def _effective_config() -> dict:
    staged = cfg_store.get_staging()
    return dict(staged if staged is not None else cfg_store.read())


def _nat(cfg: dict) -> dict:
    return cfg.setdefault("firewall", {}).setdefault("nat", {})


def _run(cmd, timeout: int = 15) -> dict:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, check=False)
        return {"rc": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
    except subprocess.TimeoutExpired:
        return {"rc": 124, "stdout": "", "stderr": "timeout"}
    except FileNotFoundError as e:
        return {"rc": 127, "stdout": "", "stderr": str(e)}


def _stage(cfg: dict, author: str) -> None:
    validate(cfg)
    cfg_store.stage(cfg, author=author or "unknown")


def _atomic_write(path: str, content: str, mode: int = 0o600) -> None:
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


# --- Port forwards ---------------------------------------------------------
def _pf_list(cfg): return list(_nat(cfg).get("port_forwards", []) or [])
def _set_pf(cfg, items): _nat(cfg)["port_forwards"] = items

@action("nat.port_forwards.list")
def nat_pf_list(_data):
    return {"port_forwards": _pf_list(_effective_config())}

@action("nat.port_forwards.add")
def nat_pf_add(data):
    pf = data.get("pf")
    if not isinstance(pf, dict): raise ValueError("missing 'pf'")
    for k in ("ext_port", "int_ip"):
        if not pf.get(k): raise ValueError(f"{k} required")
    pf.setdefault("id", "pf-" + secrets.token_hex(4))
    pf.setdefault("enabled", True)
    pf.setdefault("proto", "tcp")
    pf.setdefault("interface", "wan")
    cfg = _effective_config()
    items = _pf_list(cfg); items.append(pf); _set_pf(cfg, items)
    _stage(cfg, data.get("author"))
    return {"port_forward": pf}

@action("nat.port_forwards.update")
def nat_pf_update(data):
    pid = data.get("id"); pf = data.get("pf")
    if not pid or not isinstance(pf, dict): raise ValueError("missing id or pf")
    cfg = _effective_config()
    items = _pf_list(cfg)
    for i, x in enumerate(items):
        if x.get("id") == pid:
            pf["id"] = pid; items[i] = pf; break
    else:
        raise FileNotFoundError(f"port-forward {pid} not found")
    _set_pf(cfg, items); _stage(cfg, data.get("author"))
    return {"port_forward": pf}

@action("nat.port_forwards.delete")
def nat_pf_delete(data):
    pid = data.get("id")
    cfg = _effective_config()
    items = _pf_list(cfg)
    new = [x for x in items if x.get("id") != pid]
    if len(new) == len(items): raise FileNotFoundError(f"pf {pid} not found")
    _set_pf(cfg, new); _stage(cfg, data.get("author"))
    return {"deleted": pid}

@action("nat.port_forwards.toggle")
def nat_pf_toggle(data):
    pid = data.get("id")
    cfg = _effective_config()
    items = _pf_list(cfg)
    for x in items:
        if x.get("id") == pid:
            x["enabled"] = not x.get("enabled", True)
            _set_pf(cfg, items); _stage(cfg, data.get("author"))
            return {"port_forward": x}
    raise FileNotFoundError(f"pf {pid} not found")


# --- Outbound NAT ----------------------------------------------------------
def _out_list(cfg): return list(_nat(cfg).get("outbound", []) or [])
def _set_out(cfg, items): _nat(cfg)["outbound"] = items

@action("nat.outbound.list")
def nat_out_list(_data): return {"outbound": _out_list(_effective_config())}

@action("nat.outbound.add")
def nat_out_add(data):
    r = data.get("rule")
    if not isinstance(r, dict): raise ValueError("missing 'rule'")
    r.setdefault("id", "on-" + secrets.token_hex(4))
    r.setdefault("enabled", True)
    r.setdefault("interface", "wan")
    r.setdefault("source", "any")
    r.setdefault("snat_to", None)
    cfg = _effective_config()
    items = _out_list(cfg); items.append(r); _set_out(cfg, items)
    _stage(cfg, data.get("author"))
    return {"rule": r}

@action("nat.outbound.update")
def nat_out_update(data):
    rid = data.get("id"); r = data.get("rule")
    if not rid or not isinstance(r, dict): raise ValueError("missing id or rule")
    cfg = _effective_config()
    items = _out_list(cfg)
    for i, x in enumerate(items):
        if x.get("id") == rid:
            r["id"] = rid; items[i] = r; break
    else:
        raise FileNotFoundError(f"outbound {rid} not found")
    _set_out(cfg, items); _stage(cfg, data.get("author"))
    return {"rule": r}

@action("nat.outbound.delete")
def nat_out_delete(data):
    rid = data.get("id")
    cfg = _effective_config()
    items = _out_list(cfg)
    new = [x for x in items if x.get("id") != rid]
    if len(new) == len(items): raise FileNotFoundError(f"outbound {rid} not found")
    _set_out(cfg, new); _stage(cfg, data.get("author"))
    return {"deleted": rid}


# --- 1:1 NAT ---------------------------------------------------------------
def _oto_list(cfg): return list(_nat(cfg).get("one_to_one", []) or [])
def _set_oto(cfg, items): _nat(cfg)["one_to_one"] = items

def _validate_oto(b: dict) -> None:
    import ipaddress
    for k in ("external_ip", "internal_ip"):
        if not b.get(k):
            raise ValueError(f"{k} required")
        try:
            ipaddress.ip_address(b[k])
        except ValueError as e:
            raise ValueError(f"{k}: {e}")

@action("nat.one_to_one.list")
def nat_oto_list(_data):
    return {"one_to_one": _oto_list(_effective_config())}

@action("nat.one_to_one.add")
def nat_oto_add(data):
    b = data.get("binat")
    if not isinstance(b, dict): raise ValueError("missing 'binat'")
    _validate_oto(b)
    b.setdefault("id", "oto-" + secrets.token_hex(4))
    b.setdefault("enabled", True)
    b.setdefault("interface", "wan")
    b.setdefault("reflection", True)
    b.setdefault("description", "")
    cfg = _effective_config()
    items = _oto_list(cfg)
    if any(x.get("external_ip") == b["external_ip"] for x in items):
        raise ValueError(f"1:1 mapping for {b['external_ip']} already exists")
    items.append(b); _set_oto(cfg, items)
    _stage(cfg, data.get("author"))
    return {"binat": b}

@action("nat.one_to_one.update")
def nat_oto_update(data):
    bid = data.get("id"); b = data.get("binat")
    if not bid or not isinstance(b, dict): raise ValueError("missing id or binat")
    _validate_oto(b)
    cfg = _effective_config()
    items = _oto_list(cfg)
    for i, x in enumerate(items):
        if x.get("id") == bid:
            b["id"] = bid; items[i] = b; break
    else:
        raise FileNotFoundError(f"1:1 {bid} not found")
    _set_oto(cfg, items); _stage(cfg, data.get("author"))
    return {"binat": b}

@action("nat.one_to_one.delete")
def nat_oto_delete(data):
    bid = data.get("id")
    cfg = _effective_config()
    items = _oto_list(cfg)
    new = [x for x in items if x.get("id") != bid]
    if len(new) == len(items): raise FileNotFoundError(f"1:1 {bid} not found")
    _set_oto(cfg, new); _stage(cfg, data.get("author"))
    return {"deleted": bid}

@action("nat.one_to_one.toggle")
def nat_oto_toggle(data):
    bid = data.get("id")
    cfg = _effective_config()
    items = _oto_list(cfg)
    for x in items:
        if x.get("id") == bid:
            x["enabled"] = not x.get("enabled", True)
            _set_oto(cfg, items); _stage(cfg, data.get("author"))
            return {"binat": x}
    raise FileNotFoundError(f"1:1 {bid} not found")


# --- NPTv6 -----------------------------------------------------------------
def _npt_list(cfg):
    npt = _nat(cfg).get("npt")
    if isinstance(npt, dict):
        return list(npt.get("entries", []) or [])
    return list(npt or [])

def _set_npt(cfg, items): _nat(cfg)["npt"] = items

def _validate_npt(e: dict) -> None:
    import ipaddress
    for k in ("internal_prefix", "external_prefix"):
        if not e.get(k): raise ValueError(f"{k} required")
        try:
            net = ipaddress.ip_network(e[k], strict=False)
        except ValueError as ex:
            raise ValueError(f"{k}: {ex}")
        if net.version != 6:
            raise ValueError(f"{k}: must be IPv6")
        if not (48 <= net.prefixlen <= 64):
            raise ValueError(f"{k}: prefix length must be /48../64 (RFC 6296)")

@action("nat.npt.list")
def nat_npt_list(_data):
    return {"entries": _npt_list(_effective_config())}

@action("nat.npt.add")
def nat_npt_add(data):
    e = data.get("entry")
    if not isinstance(e, dict): raise ValueError("missing 'entry'")
    _validate_npt(e)
    e.setdefault("id", "npt-" + secrets.token_hex(4))
    e.setdefault("enabled", True)
    e.setdefault("interface", "wan")
    e.setdefault("description", "")
    cfg = _effective_config()
    items = _npt_list(cfg); items.append(e); _set_npt(cfg, items)
    _stage(cfg, data.get("author"))
    return {"entry": e}

@action("nat.npt.update")
def nat_npt_update(data):
    eid = data.get("id"); e = data.get("entry")
    if not eid or not isinstance(e, dict): raise ValueError("missing id or entry")
    _validate_npt(e)
    cfg = _effective_config()
    items = _npt_list(cfg)
    for i, x in enumerate(items):
        if x.get("id") == eid:
            e["id"] = eid; items[i] = e; break
    else:
        raise FileNotFoundError(f"NPT {eid} not found")
    _set_npt(cfg, items); _stage(cfg, data.get("author"))
    return {"entry": e}

@action("nat.npt.delete")
def nat_npt_delete(data):
    eid = data.get("id")
    cfg = _effective_config()
    items = _npt_list(cfg)
    new = [x for x in items if x.get("id") != eid]
    if len(new) == len(items): raise FileNotFoundError(f"NPT {eid} not found")
    _set_npt(cfg, new); _stage(cfg, data.get("author"))
    return {"deleted": eid}

@action("nat.npt.toggle")
def nat_npt_toggle(data):
    eid = data.get("id")
    cfg = _effective_config()
    items = _npt_list(cfg)
    for x in items:
        if x.get("id") == eid:
            x["enabled"] = not x.get("enabled", True)
            _set_npt(cfg, items); _stage(cfg, data.get("author"))
            return {"entry": x}
    raise FileNotFoundError(f"NPT {eid} not found")


# --- Reflection ------------------------------------------------------------
@action("nat.reflection.get")
def nat_refl_get(_data):
    cfg = _effective_config()
    r = _nat(cfg).setdefault("reflection", {"enabled": False})
    return {"reflection": r}

@action("nat.reflection.set")
def nat_refl_set(data):
    r = data.get("reflection")
    if not isinstance(r, dict): raise ValueError("missing 'reflection'")
    if not isinstance(r.get("enabled"), bool):
        raise ValueError("reflection.enabled must be bool")
    cfg = _effective_config()
    _nat(cfg)["reflection"] = r
    _stage(cfg, data.get("author"))
    return {"reflection": r}


# --- UPnP ------------------------------------------------------------------
def _upnp_defaults() -> dict:
    return {
        "enabled": False,
        "external_iface": "wan",
        "internal_iface": "lan",
        "allow": [],
        "deny": [],
        "secure_mode": True,
        "http_port": 5000,
        "presentation_url": "",
            }

def _upnp_get(cfg: dict) -> dict:
    s = _nat(cfg).setdefault("upnp", _upnp_defaults())
    known = set(_upnp_defaults().keys())
    for stale in [k for k in list(s.keys()) if k not in known]:
        del s[stale]
    for k, v in _upnp_defaults().items():
        s.setdefault(k, v)
    # Fill in uuid and external_ip if missing
    return _upnp_fill_missing(cfg)

def _upnp_fill_missing(cfg: dict) -> dict:
    """Populate uuid and external_ip if not set. Called before every
    render so a fresh install works without manual configuration."""
    import secrets
    import uuid as _uuid
    import urllib.request

    s = _nat(cfg).setdefault("upnp", _upnp_defaults())

    # 1. UUID: generate once, keep forever
    if not s.get("uuid"):
        s["uuid"] = str(_uuid.uuid4())

    # 2. External IP: if not set, try to detect it.
    #    Only do this when UPnP is enabled to avoid pointless network calls.
    if s.get("enabled") and not s.get("external_ip"):
        for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "NFW/1.0"})
                with urllib.request.urlopen(req, timeout=5) as r:
                    ip = r.read().decode().strip()
                    if ip and ":" not in ip:
                        s["external_ip"] = ip
                        break
            except Exception:
                continue

    return s


@action("nat.upnp.detect_ip")
def nat_upnp_detect_ip(_data):
    """Query an external service for the current public IPv4 address,
    update the config if different, and return the new value. Used by
    the 'Detect now' button on the UPnP GUI page."""
    import urllib.request

    ip = ""
    for url in ("https://api.ipify.org",
                "https://ifconfig.me/ip",
                "https://icanhazip.com"):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NFW/1.0"})
            with urllib.request.urlopen(req, timeout=8) as r:
                candidate = r.read().decode().strip()
            if candidate and ":" not in candidate:
                ip = candidate
                break
        except Exception:
            continue

    if not ip:
        raise RuntimeError("could not detect public IP (all providers failed)")

    cfg = _effective_config()
    upnp = _upnp_get(cfg)
    old = upnp.get("external_ip") or ""
    upnp["external_ip"] = ip
    _nat(cfg)["upnp"] = upnp
    _stage(cfg, _data.get("author") or "unknown")
    return {"ip": ip, "previous": old, "changed": old != ip}


def _render_upnpd(cfg: dict) -> str:
    from modules.network.interfaces import resolve_roles
    upnp = _upnp_get(cfg)
    roles = resolve_roles(cfg.get("network", {}))
    ext = roles.get(upnp.get("external_iface", "wan"),
                    upnp.get("external_iface", "wan"))
    intf = roles.get(upnp.get("internal_iface", "lan"),
                     upnp.get("internal_iface", "lan"))
    port = int(upnp.get("http_port", 5000))
    # Force secure_mode=no when ext_ip is provided — the Ubuntu
    # build of miniupnpd has no ext_allow_private_ipv4, so this
    # is the only way to make it accept a private WAN IP.
    _extip = upnp.get("external_ip") or ""
    secure = "no" if _extip else ("yes" if upnp.get("secure_mode", True) else "no")
    pres = upnp.get("presentation_url") or ""
    # If presentation_url is empty, build it from the LAN IP
    if not pres:
        try:
            from modules.network.interfaces import resolve_roles
            _lan = resolve_roles(cfg.get("network", {})).get("lan", "")
            _lan_ip = None
            for x in _resolve_iface_ips(cfg, "lan"):
                if ":" not in x:
                    _lan_ip = x
                    break
            if _lan_ip:
                pres = f"http://{_lan_ip}:8080/"
        except Exception:
            pass

    # Directive set verified against /usr/share/miniupnpd/miniupnpd.conf
    # and iteratively against Debian miniupnpd 2.x parse errors.
    # NOT supported by this build: enable_pcp, enable_igdv2.
    L = ["# NFW — GENERATED miniupnpd config. Do not edit by hand.", ""]
    L.append(f"ext_ifname={ext}")
    L.append(f"listening_ip={intf}")
    L.append(f"port={port}")
    L.append("")
    L.append("enable_natpmp=yes")
    L.append("enable_upnp=yes")


    # ext_ip overrides the WAN IP for GetExternalIPAddress responses.
    # Required when the WAN interface has a private (RFC1918) address,
    # because miniupnpd refuses to report private IPs as external.
    # Matches OPNsense's "Override WAN address" field.
    _extip = upnp.get("external_ip") or ""
    if _extip:
        L.append(f"ext_ip={_extip}")
    # the real external IP, since the WAN interface has a private
    # (RFC1918) address that miniupnpd refuses to report.
    L.append(f"secure_mode={secure}")
    L.append("force_igd_desc_v1=yes")
    L.append("system_uptime=yes")
    _uuid = upnp.get("uuid") or "00000000-0000-0000-0000-000000000000"
    L.append(f"uuid={_uuid}")
    if pres:
        L.append(f"presentation_url={pres}")
    L.append("")
    for a in upnp.get("allow", []) or []:
        L.append(f"allow {a}")
    for d in upnp.get("deny", []) or []:
        L.append(f"deny {d}")
    L.append("")
    return "\n".join(L)

def _apply_upnp(cfg: dict) -> dict:
    upnp = _upnp_get(cfg)
    enabled = bool(upnp.get("enabled", False))

    if not enabled:
        _run(["/usr/bin/systemctl", "stop", UPNP_SERVICE])
        _run(["/usr/bin/systemctl", "disable", UPNP_SERVICE])
        return {"enabled": False, "service": "stopped"}

    # Direct write to the target file — the parent dir /etc is read-only
    # in configd's sandbox, but /etc/miniupnpd/nfw.conf is in
    # ReadWritePaths. Mirrors the pattern used by modules/vpn/ipsec.py.
    _content = _render_upnpd(cfg)
    try:
        os.makedirs(os.path.dirname(UPNP_CONF), exist_ok=True)
    except OSError:
        pass
    with open(UPNP_CONF, "w") as _f:
        _f.write(_content)
        _f.flush()
        os.fsync(_f.fileno())
    try:
        os.chmod(UPNP_CONF, 0o644)
    except OSError:
        pass
    # miniupnpd creates its own nftables tables + chains via
    # /etc/miniupnpd/nft_init.sh at service start. If they already
    # exist, the script is a no-op.
    import os as _os
    if _os.path.exists("/etc/miniupnpd/nft_init.sh"):
        _run(["/bin/sh", "/etc/miniupnpd/nft_init.sh"])
    _run(["/usr/bin/systemctl", "unmask", UPNP_SERVICE])
    en = _run(["/usr/bin/env", "SYSTEMCTL_SKIP_SYSV=1",
               "/usr/bin/systemctl", "enable", UPNP_SERVICE])
    if en["rc"] != 0:
        LOG.warning("enable %s failed rc=%s err=%s",
                    UPNP_SERVICE, en["rc"], (en.get("stderr") or "").strip()[:200])
    r = _run(["/usr/bin/systemctl", "restart", UPNP_SERVICE], timeout=20)
    return {"enabled": True, "service_rc": r["rc"], "service_err": r["stderr"][:300]}

@action("nat.upnp.get")
def nat_upnp_get(_data):
    cfg = _effective_config()
    upnp = _upnp_get(cfg)
    status = _run(["/usr/bin/systemctl", "is-active", UPNP_SERVICE])
    return {"upnp": upnp, "service": status["stdout"].strip(),
            "leases": _read_upnp_leases()}

@action("nat.upnp.set")
def nat_upnp_set(data):
    u = data.get("upnp")
    if not isinstance(u, dict): raise ValueError("missing 'upnp'")
    if "enabled" in u and not isinstance(u["enabled"], bool):
        raise ValueError("upnp.enabled must be bool")
    if "http_port" in u and u["http_port"] is not None:
        try: hp = int(u["http_port"])
        except (TypeError, ValueError): raise ValueError("upnp.http_port must be int")
        if not (1 <= hp <= 65535): raise ValueError("upnp.http_port out of range")
    cfg = _effective_config()
    cur = _upnp_get(cfg)
    cur.update(u)
    _nat(cfg)["upnp"] = cur
    _stage(cfg, data.get("author"))
    return {"upnp": cur}

@action("nat.upnp.apply")
def nat_upnp_apply(data):
    return _apply_upnp(_effective_config())

def _read_upnp_leases() -> list[dict]:
    path = "/var/lib/miniupnpd/leases"
    if not os.path.exists(path):
        return []
    out = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) < 5:
                    continue
                out.append({"proto": parts[0], "ext_port": parts[1],
                            "int_ip": parts[2], "int_port": parts[3],
                            "ts": parts[4],
                            "desc": ":".join(parts[5:]) if len(parts) > 5 else ""})
    except OSError:
        return []
    return out
