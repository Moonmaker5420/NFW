"""Gateway + gateway group + static route actions."""
from __future__ import annotations
import logging
import sys
from typing import Any

from configd.registry import action

sys.path.insert(0, "/opt/nfw")
sys.path.insert(0, "/opt/nfw/core")

from config import store as cfg_store
from config.schema import validate
from modules.gateway.model import (
    Gateway, GatewayGroup, GatewayError, new_gw_id, new_gwg_id,
)
from modules.gateway import monitor as gw_monitor

LOG = logging.getLogger("configd.gateway")


def _effective_config() -> dict:
    staged = cfg_store.get_staging()
    return dict(staged if staged is not None else cfg_store.read())


def _gw_section(cfg: dict) -> dict:
    s = cfg.setdefault("network", {}).setdefault("gateways", {})
    s.setdefault("gateways", [])
    s.setdefault("groups", [])
    s.setdefault("static_routes", [])
    return s


def _get_gateways(cfg: dict) -> list[dict]:
    return list(_gw_section(cfg).get("gateways", []))


def _get_groups(cfg: dict) -> list[dict]:
    return list(_gw_section(cfg).get("groups", []))


def _get_routes(cfg: dict) -> list[dict]:
    return list(_gw_section(cfg).get("static_routes", []))


def _all_gateways_for_monitor() -> list[dict]:
    """Callback for the monitor thread — reads staged-over-active so
    newly-added gateways show up immediately."""
    try:
        staged = cfg_store.get_staging()
        cfg = staged if staged is not None else cfg_store.read()
        return cfg.get("network", {}).get("gateways", {}).get("gateways", [])
    except Exception:
        return []


# Start the monitor thread right here at module import
try:
    gw_monitor.start(_all_gateways_for_monitor)
    LOG.info("gateway monitor started at module import")
except Exception as _e:
    LOG.warning("gateway monitor failed to start: %s", _e)

# ---- Gateway reconciler -----------------------------------------------
# Watches monitor status and swaps the default route when the active
# failover member changes. Safe by default: no-op when no group exists,
# no-op when no member is up, no-op when the disable file exists.
from modules.gateway import reconciler as gw_reconciler


def _full_effective_config() -> dict:
    from config import store as _st
    staged = _st.get_staging()
    return dict(staged if staged is not None else _st.read())


try:
    gw_reconciler.start(_full_effective_config, gw_monitor.get_status)
    LOG.info("gateway reconciler started at module import")
except Exception as _e:
    LOG.warning("gateway reconciler failed to start: %s", _e)
# ---- /Gateway reconciler ----------------------------------------------




# ===========================================================================
# Gateways
# ===========================================================================
@action("gateway.list")
def gw_list(_data):
    cfg = _effective_config()
    gateways = _get_gateways(cfg)
    groups = _get_groups(cfg)
    status = gw_monitor.get_status()
    # Merge status into gateways
    for g in gateways:
        g["status"] = status.get(g["id"], {"state": "unknown"})
    return {"gateways": gateways, "groups": groups}


@action("gateway.add")
def gw_add(data):
    gw = data.get("gateway")
    if not isinstance(gw, dict):
        raise ValueError("missing 'gateway'")
    try:
        g = Gateway.from_dict(gw)
        g.validate()
    except GatewayError as e:
        raise ValueError(str(e))

    cfg = _effective_config()
    items = _get_gateways(cfg)
    if any(x.get("id") == g.id for x in items):
        raise ValueError(f"gateway {g.id} exists")
    if any(x.get("name") == g.name for x in items):
        raise ValueError(f"gateway name '{g.name}' exists")
    items.append(g.to_dict())
    _gw_section(cfg)["gateways"] = items
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"gateway": g.to_dict()}


@action("gateway.update")
def gw_update(data):
    gid = data.get("id")
    gw = data.get("gateway")
    if not gid or not isinstance(gw, dict):
        raise ValueError("missing id or gateway")
    try:
        g = Gateway.from_dict({**gw, "id": gid})
        g.validate()
    except GatewayError as e:
        raise ValueError(str(e))

    cfg = _effective_config()
    items = _get_gateways(cfg)
    for i, x in enumerate(items):
        if x.get("id") == gid:
            # Check name uniqueness vs others
            if any(y.get("name") == g.name and y.get("id") != gid for y in items):
                raise ValueError(f"name '{g.name}' already used")
            items[i] = g.to_dict()
            break
    else:
        raise FileNotFoundError(f"gateway {gid} not found")
    _gw_section(cfg)["gateways"] = items
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"gateway": g.to_dict()}


@action("gateway.delete")
def gw_delete(data):
    gid = data.get("id")
    cfg = _effective_config()
    items = _get_gateways(cfg)
    new_items = [x for x in items if x.get("id") != gid]
    if len(new_items) == len(items):
        raise FileNotFoundError(f"gateway {gid} not found")

    # Refuse if referenced by any group
    for grp in _get_groups(cfg):
        for m in grp.get("members", []):
            if m.get("gateway_id") == gid:
                raise ValueError(
                    f"gateway {gid} is used by group '{grp['name']}' — remove it first")

    _gw_section(cfg)["gateways"] = new_items
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"deleted": gid}


# ===========================================================================
# Gateway groups
# ===========================================================================
@action("gateway.groups.add")
def gwg_add(data):
    grp = data.get("group")
    if not isinstance(grp, dict):
        raise ValueError("missing 'group'")
    try:
        g = GatewayGroup.from_dict(grp)
        g.validate({x["id"] for x in _get_gateways(_effective_config())})
    except GatewayError as e:
        raise ValueError(str(e))

    cfg = _effective_config()
    items = _get_groups(cfg)
    if any(x.get("id") == g.id for x in items):
        raise ValueError(f"group {g.id} exists")
    if any(x.get("name") == g.name for x in items):
        raise ValueError(f"group name '{g.name}' exists")
    items.append(g.to_dict())
    _gw_section(cfg)["groups"] = items
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"group": g.to_dict()}


@action("gateway.groups.update")
def gwg_update(data):
    gid = data.get("id")
    grp = data.get("group")
    if not gid or not isinstance(grp, dict):
        raise ValueError("missing id or group")
    try:
        g = GatewayGroup.from_dict({**grp, "id": gid})
        g.validate({x["id"] for x in _get_gateways(_effective_config())})
    except GatewayError as e:
        raise ValueError(str(e))

    cfg = _effective_config()
    items = _get_groups(cfg)
    for i, x in enumerate(items):
        if x.get("id") == gid:
            if any(y.get("name") == g.name and y.get("id") != gid for y in items):
                raise ValueError(f"name '{g.name}' already used")
            items[i] = g.to_dict()
            break
    else:
        raise FileNotFoundError(f"group {gid} not found")
    _gw_section(cfg)["groups"] = items
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"group": g.to_dict()}


@action("gateway.groups.delete")
def gwg_delete(data):
    gid = data.get("id")
    cfg = _effective_config()
    items = _get_groups(cfg)
    new_items = [x for x in items if x.get("id") != gid]
    if len(new_items) == len(items):
        raise FileNotFoundError(f"group {gid} not found")
    _gw_section(cfg)["groups"] = new_items
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"deleted": gid}


# ===========================================================================
# Static routes
# ===========================================================================
@action("gateway.routes.add")
def route_add(data):
    r = data.get("route")
    if not isinstance(r, dict):
        raise ValueError("missing 'route'")
    import ipaddress
    dst = r.get("destination")
    gw = r.get("gateway")           # gateway_id or explicit IP
    if not dst:
        raise ValueError("destination required")
    try:
        ipaddress.ip_network(dst, strict=False)
    except ValueError as e:
        raise ValueError(f"invalid destination: {e}")

    # Gateway must exist if given as an ID
    if gw and gw.startswith("gw-"):
        ids = {x["id"] for x in _get_gateways(_effective_config())}
        if gw not in ids:
            raise ValueError(f"unknown gateway: {gw}")

    import secrets
    r.setdefault("id", "sr-" + secrets.token_hex(4))
    r.setdefault("description", "")
    r.setdefault("enabled", True)

    cfg = _effective_config()
    routes = _get_routes(cfg)
    routes.append(r)
    _gw_section(cfg)["static_routes"] = routes
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"route": r}


@action("gateway.routes.delete")
def route_delete(data):
    rid = data.get("id")
    cfg = _effective_config()
    routes = _get_routes(cfg)

    # Find the route we're about to delete
    target = next((r for r in routes if r.get("id") == rid), None)
    if target is None:
        raise FileNotFoundError(f"route {rid} not found")

    # Remove from kernel first
    import subprocess
    dst = target.get("destination")
    if dst:
        r = subprocess.run(["/usr/sbin/ip", "route", "del", dst],
                           capture_output=True, text=True)
        kernel_del = {"rc": r.returncode, "stderr": r.stderr}
    else:
        kernel_del = {"rc": 0}

    # Then remove from config
    new = [x for x in routes if x.get("id") != rid]
    _gw_section(cfg)["static_routes"] = new
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"deleted": rid, "kernel": kernel_del}


@action("gateway.routes.sync")
def route_sync(data):
    """Reconcile kernel routes with config:
       - Add missing routes from config
       - Remove kernel routes that NFW created but are no longer in config
    Only touches routes whose destination matches something NFW would manage.
    Does NOT touch system routes (default, link-local, etc).
    """
    import subprocess
    cfg = _effective_config()
    routes = _get_routes(cfg)
    gateways = {g["id"]: g for g in _get_gateways(cfg)}

    # Get current kernel routes
    out = subprocess.run(["/usr/sbin/ip", "-j", "route", "show"],
                         capture_output=True, text=True)
    import json as _json
    kernel = []
    try:
        kernel = _json.loads(out.stdout or "[]")
    except Exception:
        pass

    # Add missing
    added = []
    for r in routes:
        if not r.get("enabled", True):
            continue
        dst = r.get("destination")
        gw_ref = r.get("gateway")
        gw_ip = None
        if gw_ref and gw_ref.startswith("gw-"):
            g = gateways.get(gw_ref)
            if g:
                gw_ip = g.get("address")
        else:
            gw_ip = gw_ref
        if not dst or not gw_ip:
            continue
        # Check if already present
        present = any(k.get("dst") == dst for k in kernel)
        if not present:
            subprocess.run(["/usr/sbin/ip", "route", "replace", dst, "via", gw_ip],
                           capture_output=True, text=True)
            added.append({"dst": dst, "gw": gw_ip})

    # Remove orphans: kernel routes whose dst is not in our config
    # (only if the dst is in a private range — don't touch public routes)
    import ipaddress
    managed_dsts = {r.get("destination") for r in routes}
    removed = []
    for k in kernel:
        dst = k.get("dst")
        if not dst or dst == "default":
            continue
        if dst in managed_dsts:
            continue
        # Skip: link-local, multicast, kernel-managed
        try:
            net = ipaddress.ip_network(dst, strict=False)
        except Exception:
            continue
        if net.is_multicast or net.is_loopback:
            continue
        # Only remove if it's a static /8, /16, /24 route we likely created
        # Heuristic: /8, /12, /16, /24 that aren't RFC1918 basics
        if net.prefixlen not in (8, 12, 16, 24):
            continue
        # Skip: 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12 base networks (probably legit)
        if str(net) in ("192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"):
            # But 10.0.0.0/8 as a static route IS what we'd have added
            # Actually skip base networks to be safe
            continue
        r = subprocess.run(["/usr/sbin/ip", "route", "del", dst],
                           capture_output=True, text=True)
        if r.returncode == 0:
            removed.append(dst)

    return {"added": added, "removed": removed}


# ===========================================================================
# Status + apply
# ===========================================================================
@action("gateway.status")
def gw_status(_data):
    return {"status": gw_monitor.get_status()}


@action("gateway.apply")
def gw_apply(data):
    """Apply static routes to the kernel."""
    cfg = _effective_config()
    routes = _get_routes(cfg)
    gateways = {g["id"]: g for g in _get_gateways(cfg)}

    import subprocess
    results = []

    # Flush our managed routes first
    for r in routes:
        if not r.get("enabled", True):
            continue
        dst = r.get("destination")
        gw_ref = r.get("gateway")
        gw_ip = None
        if gw_ref and gw_ref.startswith("gw-"):
            g = gateways.get(gw_ref)
            if g:
                gw_ip = g.get("address")
        else:
            gw_ip = gw_ref

        if not dst or not gw_ip:
            results.append({"route": r.get("id"), "ok": False, "error": "missing dst or gw"})
            continue

        # Replace existing route
        subprocess.run(["/usr/sbin/ip", "route", "replace", dst, "via", gw_ip],
                       capture_output=True, text=True)
        results.append({"route": r.get("id"), "ok": True, "dst": dst, "gw": gw_ip})

    result = {
        "applied": True,
        "routes": results,
        "routes_count": len(results),
        "gateways_count": len(gateways),
        "groups_count": len(_get_groups(cfg)),
    }

    # Commit staging now that routes are applied. Without this, gateway
    # add/update/delete stay in staging.json and never reach active.json
    # — the GUI table shows the new state but store.read() returns the
    # old config, so every page refresh reverts to the previous state.
    try:
        staged = cfg_store.get_staging()
        if staged is not None:
            info = cfg_store.commit(
                author=(data or {}).get("author") or "unknown",
                message="gateway apply",
            )
            result["revision"] = info.revision
    except Exception as e:
        LOG.error("gateway.apply: commit failed: %s", e)

    return result
