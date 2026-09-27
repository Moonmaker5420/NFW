"""Network discovery + assignment actions."""
from __future__ import annotations
import sys
from typing import Any
from configd.registry import action
sys.path.insert(0, "/opt/nfw")
sys.path.insert(0, "/opt/nfw/core")

from modules.network.interfaces import (  # noqa: E402
    list_devices, default_route_iface, auto_assign, resolve_roles,
    validate_assignment,
)

from config import store as cfg_store  # noqa: E402
from config.schema import validate  # noqa: E402


@action("network.discover")
def network_discover(_data: dict[str, Any]) -> dict[str, Any]:
    return {
        "devices": list_devices(),
        "default_route_iface": default_route_iface(),
        "auto_assign": auto_assign(),
    }


@action("network.resolve_roles")
def network_resolve_roles(data: dict[str, Any]) -> dict[str, Any]:
    cfg = data.get("network") or {}
    return {"resolved": resolve_roles(cfg), "auto": auto_assign()}


@action("network.assignments")
def network_assignments(_data: dict[str, Any]) -> dict[str, Any]:
    """Return current role assignments (from config) + resolved devices."""
    cfg = cfg_store.read()
    net = cfg.get("network", {})
    resolved = resolve_roles(net)
    return {
        "network": net,
        "resolved": resolved,
        "devices": list_devices(),
        "auto": auto_assign(),
    }


@action("network.validate_assignment")
def network_validate(data: dict[str, Any]) -> dict[str, Any]:
    net = data.get("network") or {}
    errors = validate_assignment(net)
    return {"ok": len(errors) == 0, "errors": errors}


@action("network.apply_assignment")
def network_apply(data: dict[str, Any]) -> dict[str, Any]:
    """Save a network role assignment to the config store.

    CRITICAL: preserve network.interfaces when updating roles, otherwise
    per-interface IP config (staged separately by the Edit modal) is lost.
    """
    net = data.get("network")
    if not isinstance(net, dict):
        raise ValueError("missing 'network'")

    errors = validate_assignment(net)
    if errors:
        raise ValueError("; ".join(errors))

    # Start from staged if present, else active
    staged = cfg_store.get_staging()
    cfg = dict(staged if staged is not None else cfg_store.read())

    # Preserve existing interfaces dict
    existing_ifaces = (cfg.get("network") or {}).get("interfaces")
    if not isinstance(existing_ifaces, dict):
        existing_ifaces = {}

    cfg["network"] = {
        "wan": net.get("wan") or "auto",
        "lan": net.get("lan") or "auto",
        "opt": net.get("opt") or [],
        "interfaces": existing_ifaces,
    }
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    info = cfg_store.commit(author=data.get("author") or "unknown",
                            message="interface assignment")

    # Recompile and apply the ruleset so the new interfaces take effect
    try:
        from modules.firewall.compiler import compile_ruleset, validate_ruleset
        from modules.network.interfaces import resolve_roles as _resolve
        cfg2 = dict(cfg)
        cfg2["_resolved_interfaces"] = _resolve(cfg["network"])
        text = compile_ruleset(cfg2)
        ok, err = validate_ruleset(text)
        if ok:
            import os as _os, shutil, subprocess as _sp, time as _time
            path = "/etc/nftables.conf"
            backup_dir = "/etc/nfw/backups"
            _os.makedirs(backup_dir, exist_ok=True)
            if _os.path.exists(path):
                shutil.copy2(path, _os.path.join(
                    backup_dir, f"nftables.conf.{int(_time.time())}"))
            with open(path, "w") as f:
                f.write(text)
            p = _sp.run(["/usr/sbin/nft", "-f", path],
                        capture_output=True, text=True, timeout=15)
            applied = (p.returncode == 0)
            apply_err = p.stderr if not applied else ""
        else:
            applied = False
            apply_err = err
    except Exception as e:
        applied = False
        apply_err = str(e)

    return {
        "revision": info.revision,
        "resolved": _resolve(cfg["network"]),
        "applied": applied,
        "apply_error": apply_err,
    }
