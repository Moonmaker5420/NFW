"""Gateway reconciler — keeps the default route pointed at the healthiest
member of the active failover group.

Runs in a background thread started by configd. Every 5s:
  1. Reads config for network.gateways.{gateways,groups}
  2. Reads monitor status
  3. Picks the highest-priority member of the first non-empty group that's 'up'
  4. Replaces the default route via that gateway if it isn't already

Safe by default:
  - No-op if no group is configured
  - No-op if no member is up (never blackholes)
  - No-op if /var/lib/nfw/gateway-reconciler.disabled exists
  - Only manages the main-table default route
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
from typing import Callable, Optional

LOG = logging.getLogger("gateway.reconciler")

DISABLE_FILE = "/var/lib/nfw/gateway-reconciler.disabled"
TICK_SECONDS = 5
IP = "/usr/sbin/ip"

_thread: Optional[threading.Thread] = None
_stop = threading.Event()


def _run(cmd, timeout=5):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:
        return 1, "", str(e)


def _get_default_route() -> Optional[dict]:
    rc, out, _ = _run([IP, "-j", "route", "show", "default"])
    if rc != 0 or not out.strip():
        return None
    try:
        routes = json.loads(out)
    except Exception:
        return None
    if not routes:
        return None
    routes.sort(key=lambda r: int(r.get("metric", 0) or 0))
    r = routes[0]
    return {"via": r.get("gateway", ""), "dev": r.get("dev", "")}


def _replace_default_route(iface: str, gw_ip: str) -> bool:
    # Flush existing default routes on this interface first. networkd's
    # DHCP client installs `default via <gw> metric 100 proto dhcp`;
    # `ip route replace` only replaces routes with matching metric, so
    # without a flush both routes coexist and the kernel picks whichever
    # has lower metric — non-deterministic.
    _run([IP, "route", "flush", "default", "dev", iface])

    # Match DHCP's metric so any later additions don't silently outrank us.
    rc, _, err = _run([IP, "route", "replace", "default",
                       "via", gw_ip, "dev", iface, "metric", "100"])
    if rc != 0:
        LOG.error("replace default route failed: %s", err.strip()[:200])
        return False
    return True


def _find_active_group(groups: list) -> Optional[dict]:
    for g in groups:
        if isinstance(g, dict) and g.get("members"):
            return g
    return None


def _resolve_iface(role: str, cfg: dict) -> str:
    """Map a role name ('wan', 'lan', 'opt1', ...) to a real device name.

    The config stores gateways with `interface: 'wan'` — a role. `ip route`
    needs the device ('ens33'), which comes from network.wan/lan/opt.
    If `role` already looks like a device name (contains no reserved role
    keyword), return it unchanged.
    """
    if not role:
        return ""
    net = (cfg.get("network") or {})
    role_l = role.lower()
    if role_l == "wan":
        return str(net.get("wan") or "")
    if role_l == "lan":
        return str(net.get("lan") or "")
    if role_l.startswith("opt"):
        opts = net.get("opt") or []
        try:
            idx = int(role_l[3:]) - 1
            if 0 <= idx < len(opts):
                return str(opts[idx])
        except (ValueError, IndexError):
            pass
        return ""
    # Not a role keyword — assume it's already a device
    return role


def _gw_is_up(st) -> bool:
    """Handle both status shapes:
       - {"state": "up"|"down", ...}  (current monitor)
       - {"up": true|false, ...}      (older/newer variants)
    """
    if not isinstance(st, dict):
        return False
    state = st.get("state")
    if isinstance(state, str):
        return state.lower() == "up"
    if "up" in st:
        return bool(st["up"])
    return False


def reconcile_once(get_config_fn: Callable[[], dict],
                   get_status_fn: Callable[[], dict]) -> None:
    if os.path.exists(DISABLE_FILE):
        return
    try:
        cfg = get_config_fn()
    except Exception as e:
        LOG.warning("reconciler: config read failed: %s", e)
        return

    net = (cfg.get("network") or {}).get("gateways") or {}
    gateways = net.get("gateways") or []
    groups = net.get("groups") or []

    group = _find_active_group(groups)
    if group is None:
        return

    status = get_status_fn() or {}
    gw_by_id = {str(g.get("id")): g for g in gateways if isinstance(g, dict)}

    target = None
    for m in (group.get("members") or []):
        # Members are dicts: {"gateway_id": "gw-...", "tier": 1}.
        # Support plain strings for backward compatibility.
        if isinstance(m, dict):
            member_id = str(m.get("gateway_id") or "")
        else:
            member_id = str(m)
        if not member_id:
            continue

        st = status.get(member_id, {})
        if not _gw_is_up(st):
            continue
        gw = gw_by_id.get(member_id)
        if not gw:
            continue
        role = gw.get("interface") or ""
        iface = _resolve_iface(role, cfg)
        gw_ip = gw.get("address") or ""
        if not iface or not gw_ip:
            LOG.debug("reconciler: skipping %s — role=%r iface=%r gw=%r",
                      member_id, role, iface, gw_ip)
            continue
        target = (member_id, iface, gw_ip)
        break

    if target is None:
        return

    cur = _get_default_route()
    if cur and cur.get("via") == target[2] and cur.get("dev") == target[1]:
        return

    LOG.warning("reconciler: switching default route to %s via %s dev %s",
                target[0], target[2], target[1])
    _replace_default_route(target[1], target[2])


def _loop(get_config_fn, get_status_fn) -> None:
    LOG.info("gateway reconciler started")
    while not _stop.is_set():
        try:
            reconcile_once(get_config_fn, get_status_fn)
        except Exception as e:
            LOG.exception("reconciler tick failed: %s", e)
        _stop.wait(TICK_SECONDS)
    LOG.info("gateway reconciler stopped")


def start(get_config_fn, get_status_fn) -> None:
    global _thread
    if _thread is not None and _thread.is_alive():
        return
    _stop.clear()
    _thread = threading.Thread(
        target=_loop, args=(get_config_fn, get_status_fn),
        name="gw-reconciler", daemon=True,
    )
    _thread.start()


def stop() -> None:
    _stop.set()
    if _thread is not None:
        _thread.join(timeout=3)
