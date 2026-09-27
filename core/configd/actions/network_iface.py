"""Per-interface IP configuration actions."""
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
from modules.network.interfaces import (  # noqa: E402
    list_devices, resolve_roles, auto_assign, validate_assignment,
)
from modules.network.networkd import (  # noqa: E402
    compile_networkd, file_path as networkd_path,
)

LOG = logging.getLogger("configd.network_iface")


def _effective_config() -> dict:
    staged = cfg_store.get_staging()
    cfg = staged if staged is not None else cfg_store.read()
    return dict(cfg)


def _run(cmd, timeout: int = 15) -> dict:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, check=False)
        return {"rc": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
    except subprocess.TimeoutExpired:
        return {"rc": 124, "stdout": "", "stderr": "timeout"}
    except FileNotFoundError as e:
        return {"rc": 127, "stdout": "", "stderr": str(e)}


def _read_current_addresses(dev: str) -> list[dict]:
    """Return addresses currently on dev (via ip -j addr show dev)."""
    r = _run(["/usr/sbin/ip", "-j", "addr", "show", "dev", dev])
    if r["rc"] != 0:
        return []
    import json as _json
    try:
        data = _json.loads(r["stdout"])
    except Exception:
        return []
    out = []
    for iface in data:
        for a in iface.get("addr_info", []):
            out.append({
                "family": a.get("family"),
                "address": a.get("local"),
                "prefixlen": a.get("prefixlen"),
            })
    return out


# ===========================================================================
# Read
# ===========================================================================
@action("network.iface.get_all")
def iface_get_all(_data: dict[str, Any]) -> dict[str, Any]:
    cfg = _effective_config()
    net = cfg.get("network", {})
    ifaces = net.get("interfaces") or {}

    devices = list_devices()
    roles = {}
    try:
        roles = resolve_roles(net)
    except Exception as e:
        LOG.warning("resolve_roles failed: %s", e)

    # role lookup: device → role
    dev_role = {}
    for role, dev in roles.items():
        if dev:
            dev_role.setdefault(dev, role)

    out = []
    for d in devices:
        dev = d["name"]
        icfg = ifaces.get(dev) or {}
        out.append({
            "device": dev,
            "state": d["state"],
            "mac": d["mac"],
            "role": dev_role.get(dev, ""),
            "ipv4": icfg.get("ipv4") or {"mode": "dhcp"},
            "ipv6": icfg.get("ipv6") or {"mode": "auto"},
            "current_addrs": _read_current_addresses(dev),
        })

    return {
        "interfaces": out,
        "roles": roles,
        "auto": auto_assign(),
    }


@action("network.iface.get")
def iface_get(data: dict[str, Any]) -> dict[str, Any]:
    dev = data.get("device")
    if not dev:
        raise ValueError("missing 'device'")
    cfg = _effective_config()
    ifaces = (cfg.get("network") or {}).get("interfaces") or {}
    return {
        "device": dev,
        "config": ifaces.get(dev) or {"ipv4": {"mode": "dhcp"},
                                       "ipv6": {"mode": "auto"}},
    }


# ===========================================================================
# Stage
# ===========================================================================
@action("network.iface.set")
def iface_set(data: dict[str, Any]) -> dict[str, Any]:
    dev = data.get("device")
    ifcfg = data.get("config")
    if not dev or not isinstance(ifcfg, dict):
        raise ValueError("device and config required")

    cfg = _effective_config()

    # Make sure network and interfaces exist as dicts
    net = cfg.setdefault("network", {})
    if not isinstance(net.get("interfaces"), dict):
        net["interfaces"] = {}
    net["interfaces"][dev] = ifcfg

    # Ensure roles are preserved
    for role in ("wan", "lan", "opt"):
        if role not in net:
            net[role] = "auto" if role != "opt" else []

    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"staged": True, "device": dev, "config": ifcfg}


@action("network.iface.unset")
def iface_unset(data: dict[str, Any]) -> dict[str, Any]:
    dev = data.get("device")
    if not dev:
        raise ValueError("missing 'device'")
    cfg = _effective_config()
    ifaces = cfg.setdefault("network", {}).setdefault("interfaces", {})
    if dev in ifaces:
        del ifaces[dev]
        validate(cfg)
        cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"unset": dev}


# ===========================================================================
# Preview
# ===========================================================================
@action("network.iface.preview")
def iface_preview(_data: dict[str, Any]) -> dict[str, Any]:
    cfg = _effective_config()
    files = compile_networkd(cfg)
    return {
        "files": [
            {"path": networkd_path(dev), "content": content}
            for dev, content in files.items()
        ]
    }


# ===========================================================================
# Apply
# ===========================================================================
@action("network.iface.apply")
def iface_apply(data: dict[str, Any]) -> dict[str, Any]:
    """
    Write all interface config files, reload networkd, then recompile
    the firewall with the (possibly new) interface roles.

    Apply order:
      1. Compile + validate networkd files (in memory)
      2. Write files
      3. Reload systemd-networkd
      4. Recompile + apply nftables
      5. Restart DHCP/DNS/NTP if they reference those interfaces
    """
    cfg = _effective_config()
    files = compile_networkd(cfg)

    # 1. Write networkd files
    written = []
    for dev, content in files.items():
        path = networkd_path(dev)
        tmp = path + ".tmp"
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(tmp, "w") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        written.append(path)

    # 2. Reload networkd
    r1 = _run(["systemctl", "reload-or-restart", "systemd-networkd"])

    # 3. Recompile + apply firewall
    try:
        from modules.firewall.compiler import compile_ruleset, validate_ruleset
        cfg2 = dict(cfg)
        cfg2["_resolved_interfaces"] = resolve_roles(cfg.get("network", {}))
        text = compile_ruleset(cfg2)
        ok, err = validate_ruleset(text)
        if ok:
            import shutil, time
            path = "/etc/nftables.conf"
            backup_dir = "/etc/nfw/backups"
            os.makedirs(backup_dir, exist_ok=True)
            if os.path.exists(path):
                shutil.copy2(path, os.path.join(backup_dir,
                                                f"nftables.conf.{int(time.time())}"))
            with open(path, "w") as f:
                f.write(text)
            r2 = _run(["/usr/sbin/nft", "-f", path])
            fw_applied = r2["rc"] == 0
            fw_err = r2["stderr"] if not fw_applied else ""
        else:
            fw_applied = False
            fw_err = err
    except Exception as e:
        fw_applied = False
        fw_err = str(e)

    # 4. Restart services that depend on interfaces
    svc_restarts = {}
    for svc in ("isc-dhcp-server", "unbound", "chrony"):
        is_active = _run(["systemctl", "is-active", svc])
        if is_active["stdout"].strip() == "active":
            _run(["systemctl", "restart", svc])
            svc_restarts[svc] = "restarted"

    return {
        "files_written": written,
        "networkd": r1,
        "firewall_applied": fw_applied,
        "firewall_error": fw_err,
        "services": svc_restarts,
    }
