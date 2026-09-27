"""
Gateway health monitor.

Runs a background thread that pings each monitor IP on each gateway
every N seconds. Results are cached in memory and can be queried via
the configd action `gateway.status`.
"""
from __future__ import annotations
import json
import subprocess
import threading
import time
from typing import Any

PING_INTERVAL = 5       # seconds between checks
PING_TIMEOUT  = 2       # seconds per ping
CONSEC_FAIL   = 3       # consecutive failures before marking down

_lock = threading.Lock()
_status: dict[str, dict] = {}       # gateway_id -> {state, rtt_ms, last_check, last_change, fails}
_thread: threading.Thread | None = None
_stop = threading.Event()


def _ping(ip: str) -> tuple[bool, float]:
    try:
        p = subprocess.run(
            ["/bin/ping", "-c", "1", "-W", str(PING_TIMEOUT), "-n", ip],
            capture_output=True, text=True, timeout=PING_TIMEOUT + 1,
        )
        if p.returncode != 0:
            return False, 0.0
        # Parse "time=X ms"
        for line in p.stdout.splitlines():
            if "time=" in line:
                try:
                    return True, float(line.split("time=")[1].split()[0])
                except Exception:
                    return True, 0.0
        return True, 0.0
    except Exception:
        return False, 0.0


def _check_gateway(gw: dict) -> None:
    """Ping all monitor IPs; success if any responds."""
    gid = gw.get("id")
    ips = gw.get("monitor_ips") or []
    if not ips:
        with _lock:
            _status[gid] = {
                "state": "unknown",
                "rtt_ms": None,
                "last_check": time.time(),
                "last_change": _status.get(gid, {}).get("last_change", time.time()),
                "fails": 0,
                "gateway_name": gw.get("name", ""),
            }
        return

    any_ok = False
    best_rtt = None
    for ip in ips:
        ok, rtt = _ping(ip)
        if ok:
            any_ok = True
            if best_rtt is None or rtt < best_rtt:
                best_rtt = rtt

    with _lock:
        prev = _status.get(gid, {})
        was_up = prev.get("state") == "up"
        prev_fails = prev.get("fails", 0)

        if any_ok:
            fails = 0
            state = "up"
        else:
            fails = prev_fails + 1
            state = "down" if fails >= CONSEC_FAIL else prev.get("state", "up")

        now = time.time()
        last_change = prev.get("last_change", now)
        if was_up and state == "down":
            last_change = now
        elif not was_up and state == "up":
            last_change = now

        _status[gid] = {
            "state": state,
            "rtt_ms": round(best_rtt, 1) if best_rtt is not None else None,
            "last_check": now,
            "last_change": last_change,
            "fails": fails,
            "gateway_name": gw.get("name", ""),
        }


def _loop(get_gateways_fn) -> None:
    while not _stop.is_set():
        try:
            gateways = get_gateways_fn()
            for gw in gateways:
                if not gw.get("enabled", True):
                    continue
                _check_gateway(gw)
        except Exception:
            pass
        _stop.wait(PING_INTERVAL)


def start(get_gateways_fn) -> None:
    """Start the monitor thread. Idempotent."""
    global _thread
    if _thread is not None and _thread.is_alive():
        return
    _stop.clear()
    _thread = threading.Thread(target=_loop, args=(get_gateways_fn,), daemon=True)
    _thread.start()


def stop() -> None:
    _stop.set()


def get_status() -> dict[str, dict]:
    with _lock:
        return dict(_status)
