"""Service configd actions: DHCP, DNS, NTP."""
from __future__ import annotations
import logging
import os
import subprocess
import sys
from typing import Any

from configd.registry import action

sys.path.insert(0, "/opt/nfw")
sys.path.insert(0, "/opt/nfw/core")

from config import store as cfg_store  # noqa: E402
from config.schema import validate  # noqa: E402
from modules.services.dhcp import compile_dhcpd, dhcp_service_unit_interface  # noqa: E402
from modules.services.dns import compile_unbound  # noqa: E402
from modules.services.ntp import compile_chrony  # noqa: E402
from modules.network.interfaces import resolve_roles  # noqa: E402

LOG = logging.getLogger("configd.services")


def _effective_config() -> dict:
    staged = cfg_store.get_staging()
    cfg = staged if staged is not None else cfg_store.read()
    cfg = dict(cfg)
    try:
        cfg["_resolved_interfaces"] = resolve_roles(cfg.get("network", {}))
    except Exception as e:
        LOG.warning("interface resolve failed: %s", e)
    return cfg


def _atomic_write(path: str, content: str, mode: int = 0o644):
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _direct_write(path: str, content: str):
    with open(path, "w") as f:
        f.write(content)


def _run(cmd: list[str], timeout: int = 15) -> dict:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, check=False)
        return {"rc": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
    except subprocess.TimeoutExpired:
        return {"rc": 124, "stdout": "", "stderr": "timeout"}
    except FileNotFoundError as e:
        return {"rc": 127, "stdout": "", "stderr": str(e)}


# ===========================================================================
# DHCP
# ===========================================================================
@action("dhcp.config.get")
def dhcp_get(_data):
    cfg = _effective_config()
    return {"config": cfg["services"].get("dhcp_config", {})}


@action("dhcp.config.set")
def dhcp_set(data):
    """Merge incoming config with existing (preserve subnets if absent)."""
    new = data.get("config")
    if not isinstance(new, dict):
        raise ValueError("missing config")

    cfg = _effective_config()
    existing = cfg.get("services", {}).get("dhcp_config", {}) or {}

    # Merge: start from existing, overlay incoming fields.
    # NB: empty subnets/static_reservations lists are intentional —
    # the front-end gates Save on a successful load, so if it sends an
    # empty list, the user deleted the last item. (An earlier version
    # tried to distinguish "not loaded" from "user deleted" here and
    # silently ignored the delete; the distinction belongs in the UI.)
    merged = dict(existing)
    for k, v in new.items():
        merged[k] = v

    # Refuse to stage enabled=true with no subnets. dhcpd exits with
    # "No subnet declaration for <iface>" otherwise — the GUI would show
    # enabled, the daemon would be failed, and the config would lie. Do
    # this at save time so no broken staging entry is ever created.
    if merged.get("enabled") and not (merged.get("subnets") or []):
        raise ValueError(
            "Cannot enable DHCP without at least one subnet. "
            "Click '+ Subnet' to add one, then Save & Apply."
        )

    cfg.setdefault("services", {})["dhcp_config"] = merged
    cfg["services"]["dhcp"] = bool(merged.get("enabled"))
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"staged": True, "config": merged}


@action("dhcp.preview")
def dhcp_preview(_data):
    cfg = _effective_config()
    text = compile_dhcpd(cfg)
    iface = dhcp_service_unit_interface(cfg)
    return {"config": text, "interface": iface}


@action("dhcp.apply")
def dhcp_apply(data):
    cfg = _effective_config()
    text = compile_dhcpd(cfg)
    iface = dhcp_service_unit_interface(cfg)

    _atomic_write("/etc/dhcp/dhcpd.conf", text)

    default_content = 'INTERFACESv4="' + iface + '"\nINTERFACESv6=""\n'
    try:
        _direct_write("/etc/default/isc-dhcp-server", default_content)
    except (PermissionError, OSError) as e:
        LOG.warning("direct write of /etc/default/isc-dhcp-server failed: %s", e)
        p = subprocess.run(
            ["/usr/bin/tee", "/etc/default/isc-dhcp-server"],
            input=default_content,
            capture_output=True, text=True, timeout=10, check=False,
        )
        if p.returncode != 0:
            raise RuntimeError(
                "cannot write /etc/default/isc-dhcp-server: " + p.stderr)

    enabled = cfg["services"].get("dhcp_config", {}).get("enabled", False)
    if enabled:
        _run(["systemctl", "unmask", "isc-dhcp-server"])
        en = _run(["env", "SYSTEMCTL_SKIP_SYSV=1",
                   "systemctl", "enable", "isc-dhcp-server"])
        if en["rc"] != 0:
            LOG.warning("enable isc-dhcp-server failed rc=%s err=%s",
                        en["rc"], (en.get("stderr") or "").strip()[:200])
        r = _run(["systemctl", "restart", "isc-dhcp-server"])
    else:
        # Stop AND disable. Just stopping leaves the unit enabled, so
        # systemd auto-restarts it (Restart=on-failure), dhcpd crashes
        # again (no subnet → "No subnet declaration"), and the unit
        # sits in state=failed forever. reset-failed also clears the
        # restart-limit state so the unit can start cleanly next time
        # the user enables it.
        _run(["systemctl", "stop", "isc-dhcp-server"])
        _run(["systemctl", "disable", "isc-dhcp-server"])
        _run(["systemctl", "reset-failed", "isc-dhcp-server"])
        r = {"rc": 0}

    return {"applied": True, "interface": iface, "service": r}


@action("dhcp.status")
def dhcp_status(_data):
    """Daemon state + configured-enabled flag, so the GUI can show
    reality vs intent side by side."""
    r = _run(["systemctl", "is-active", "isc-dhcp-server"])
    svc = (r["stdout"] or "").strip() or "unknown"
    cfg = cfg_store.read()
    dc = cfg.get("services", {}).get("dhcp_config", {}) or {}
    return {"service": svc,
            "enabled": bool(dc.get("enabled")),
            "subnet_count": len(dc.get("subnets") or [])}


@action("dhcp.leases")
def dhcp_leases(_data):
    path = "/var/lib/dhcp/dhcpd.leases"
    leases: list[dict] = []
    if not os.path.exists(path):
        return {"leases": []}
    cur: dict = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line.startswith("lease "):
                cur = {"ip": line.split()[1], "state": "active"}
            elif line.startswith("ends "):
                cur["ends"] = line[5:].rstrip(";")
            elif line.startswith("starts "):
                cur["starts"] = line[7:].rstrip(";")
            elif line.startswith("hardware ethernet"):
                cur["mac"] = line.split()[2].rstrip(";")
            elif line.startswith("client-hostname"):
                cur["hostname"] = line.split()[1].strip('";')
            elif line == "}" and cur:
                leases.append(cur)
                cur = {}
    return {"leases": leases}


# ===========================================================================
# DNS (Unbound)
# ===========================================================================
# ---------------------------------------------------------------------------
# DNS blocklists
# ---------------------------------------------------------------------------
@action("dns.blocklist.get")
def dns_blocklist_get(_data):
    from config import store as _cs
    from modules.services import blocklists as _bl
    staged = _cs.get_staging()
    cfg = dict(staged if staged is not None else _cs.read())
    svc = cfg.get("services", {}).get("dns_config", {}) or {}
    bl = svc.get("blocklists", {}) or {}
    return {"config": bl, "state": _bl._load_state(), "catalog": _bl.CATALOG}


@action("dns.blocklist.set")
def dns_blocklist_set(data):
    from config import store as _cs
    from config.schema import validate as _validate
    new = data.get("config") or {}
    staged = _cs.get_staging()
    cfg = dict(staged if staged is not None else _cs.read())
    svc = cfg.setdefault("services", {}).setdefault("dns_config", {})
    bl = svc.setdefault("blocklists", {})
    for k in ("enabled", "mode", "schedule", "manual", "whitelist", "sources"):
        if k in new:
            bl[k] = new[k]
    _validate(cfg)
    _cs.stage(cfg, author=data.get("author") or "unknown")
    return {"staged": True, "config": bl}


@action("dns.blocklist.refresh")
def dns_blocklist_refresh(_data):
    import subprocess as _sp
    r = _sp.run(["/usr/local/sbin/nfw-dnsblock-refresh.py"],
                capture_output=True, text=True, timeout=300)
    return {"rc": r.returncode,
            "stdout": (r.stdout or "")[-2000:],
            "stderr": (r.stderr or "")[-2000:]}


@action("dns.blocklist.sources.catalog")
def dns_blocklist_catalog(_data):
    from modules.services import blocklists as _bl
    return {"catalog": _bl.CATALOG}


@action("dns.config.get")
def dns_get(_data):
    cfg = _effective_config()
    return {"config": cfg["services"].get("dns_config", {})}


@action("dns.config.set")
def dns_set(data):
    """Merge incoming config with existing (preserve critical fields)."""
    new = data.get("config")
    if not isinstance(new, dict):
        raise ValueError("missing config")

    cfg = _effective_config()
    existing = cfg.get("services", {}).get("dns_config", {}) or {}

    # Fields that must never be wiped by an incomplete UI POST
    PRESERVE_IF_EMPTY = ("forwarders_tls", "access_control",
                        "forward_zones", "host_overrides")

    merged = dict(existing)
    for k, v in new.items():
        if k in PRESERVE_IF_EMPTY and isinstance(v, list) and len(v) == 0:
            if existing.get(k):
                continue
        merged[k] = v

    # Ensure listen defaults to 0.0.0.0 if unset
    if not merged.get("listen"):
        merged["listen"] = ["0.0.0.0"]

    cfg.setdefault("services", {})["dns_config"] = merged
    cfg["services"]["dns"] = bool(merged.get("enabled"))
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"staged": True, "config": merged}


@action("dns.preview")
def dns_preview(_data):
    cfg = _effective_config()
    text = compile_unbound(cfg)
    return {"config": text}


@action("dns.apply")
def dns_apply(data):
    cfg = _effective_config()
    # Regenerate the blocklist include BEFORE compiling unbound.conf.
    # Otherwise a Save & Apply after adding a manual domain (or changing
    # sources / whitelist) wouldn't take effect until the user also
    # clicked the separate Refresh button. refresh() handles
    # blocklists.enabled=False by writing an empty include.
    try:
        from modules.services import blocklists as _bl
        _bl.refresh(cfg)
    except Exception as e:
        LOG.warning("dns_apply: blocklist refresh failed: %s", e)

    text = compile_unbound(cfg)
    path = "/etc/unbound/unbound.conf.d/nfw.conf"
    _atomic_write(path, text)

    v = _run(["unbound-checkconf", path])
    if v["rc"] != 0:
        raise RuntimeError("unbound-checkconf: " + v["stderr"])

    enabled = cfg["services"].get("dns_config", {}).get("enabled", False)
    if enabled:
        # Older installs masked unbound.service to prevent apt auto-start
        # with default configs. Unmask before enable so a user's first
        # Save & Apply actually starts the daemon.
        _run(["systemctl", "unmask", "unbound"])
        # SYSTEMCTL_SKIP_SYSV: without it, `enable` also tries to sync
        # with /etc/rc*.d/, which is not writable inside configd's
        # sandbox. NFW is systemd-only, so the sync is a no-op anyway.
        en = _run(["env", "SYSTEMCTL_SKIP_SYSV=1",
                   "systemctl", "enable", "unbound"])
        if en["rc"] != 0:
            LOG.warning("systemctl enable unbound failed rc=%s err=%s",
                        en["rc"], (en.get("stderr") or "").strip()[:200])
        r = _run(["systemctl", "restart", "unbound"])
    else:
        _run(["systemctl", "stop", "unbound"])
        r = {"rc": 0}

    # Apply commits staging — every other apply path (radius, advanced
    # interfaces, gateway, captive portal) does the same. Without this,
    # active.json stays behind and the "uncommitted changes" banner
    # never clears after Save & Apply.
    try:
        staged = cfg_store.get_staging()
        if staged is not None:
            info = cfg_store.commit(
                author=(data or {}).get("author") or "unknown",
                message="dns: apply",
            )
            return {"applied": True, "check": v, "service": r,
                    "revision": info.revision}
    except Exception as e:
        LOG.error("dns_apply: commit failed: %s", e)

    return {"applied": True, "check": v, "service": r}


@action("dns.querylog")
def dns_querylog(data):
    lines = int(data.get("lines", 100))
    lines = max(1, min(lines, 2000))
    path = "/var/log/unbound/unbound.log"
    if not os.path.exists(path):
        return {"lines": [], "file": path}
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        block = min(size, 128 * 1024)
        f.seek(size - block)
        data = f.read()
    out = data.decode("utf-8", errors="replace").splitlines()[-lines:]
    return {"lines": out, "file": path}


# ===========================================================================
# NTP (chrony)
# ===========================================================================
@action("ntp.config.get")
def ntp_get(_data):
    cfg = _effective_config()
    return {"config": cfg["services"].get("ntp_config", {})}


@action("ntp.config.set")
def ntp_set(data):
    """Merge incoming config with existing."""
    new = data.get("config")
    if not isinstance(new, dict):
        raise ValueError("missing config")
    cfg = _effective_config()
    existing = cfg.get("services", {}).get("ntp_config", {}) or {}
    merged = dict(existing)
    for k, v in new.items():
        if k == "servers" and isinstance(v, list) and len(v) == 0:
            if existing.get("servers"):
                continue
        merged[k] = v
    cfg.setdefault("services", {})["ntp_config"] = merged
    cfg["services"]["ntp"] = bool(merged.get("enabled"))
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"staged": True, "config": merged}


@action("ntp.preview")
def ntp_preview(_data):
    cfg = _effective_config()
    return {"config": compile_chrony(cfg)}


@action("ntp.apply")
def ntp_apply(data):
    cfg = _effective_config()
    text = compile_chrony(cfg)
    _atomic_write("/etc/chrony/chrony.conf", text)
    enabled = cfg["services"].get("ntp_config", {}).get("enabled", True)
    if enabled:
        _run(["systemctl", "unmask", "chrony"])
        en = _run(["env", "SYSTEMCTL_SKIP_SYSV=1",
                   "systemctl", "enable", "chrony"])
        if en["rc"] != 0:
            LOG.warning("enable chrony failed rc=%s err=%s",
                        en["rc"], (en.get("stderr") or "").strip()[:200])
        r = _run(["systemctl", "restart", "chrony"])
    else:
        _run(["systemctl", "stop", "chrony"])
        r = {"rc": 0}
    return {"applied": True, "service": r}


@action("ntp.status")
def ntp_status(_data):
    r = _run(["chronyc", "tracking"])
    src = _run(["chronyc", "sources", "-v"])
    return {"tracking": r["stdout"], "sources": src["stdout"]}
