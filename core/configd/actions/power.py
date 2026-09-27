"""System power actions — reboot and shutdown.

Design notes:
  - Actions are named `power.reboot` / `power.shutdown` instead of
    `system.reboot` / `system.shutdown` on purpose. The latter are in
    configd's ROOT_ONLY_ACTIONS, which would deny the API (www-data)
    from calling them. The API-level `require_acl("admin")` gate is
    the sole authorization boundary for power operations.

  - Actual power action is scheduled via `systemd-run --on-active=N`
    so the configd response can be delivered before the system goes
    down. Without the delay, the socket is torn down mid-response.

  - Delay is clamped to [2, 60] seconds.
"""
from __future__ import annotations

import logging
import subprocess
from typing import Any

from configd.registry import action

LOG = logging.getLogger("configd.power")


def _schedule_power(action: str, delay_seconds: int) -> dict[str, Any]:
    delay = max(2, min(int(delay_seconds or 5), 60))
    unit = f"nfw-{action}"

    # Clean up any leftover failed unit from a previous invocation.
    subprocess.run(["systemctl", "reset-failed", f"{unit}.timer"],
                   capture_output=True, timeout=5)
    subprocess.run(["systemctl", "reset-failed", f"{unit}.service"],
                   capture_output=True, timeout=5)

    cmd = [
        "systemd-run",
        f"--on-active={delay}",
        f"--unit={unit}",
        "--collect",
        f"--description=NFW requested {action}",
        "systemctl", action,
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except Exception as e:
        LOG.error("systemd-run failed: %s", e)
        return {"ok": False, "error": str(e)[:200]}

    if r.returncode != 0:
        err = (r.stderr or r.stdout or "unknown").strip()[:300]
        LOG.error("systemd-run rc=%d err=%s", r.returncode, err)
        return {"ok": False, "error": err}

    LOG.warning("scheduled %s in %ds (unit=%s)", action, delay, unit)
    return {
        "ok": True,
        "action": action,
        "delay_seconds": delay,
        "unit": f"{unit}.timer",
    }


@action("power.reboot")
def power_reboot(data: dict[str, Any]) -> dict[str, Any]:
    return _schedule_power("reboot", int(data.get("delay_seconds", 5)))


@action("power.shutdown")
def power_shutdown(data: dict[str, Any]) -> dict[str, Any]:
    return _schedule_power("poweroff", int(data.get("delay_seconds", 5)))


@action("power.cancel")
def power_cancel(_data: dict[str, Any]) -> dict[str, Any]:
    """Cancel a pending reboot/shutdown. Only works during the delay window."""
    cancelled = []
    for unit in ("nfw-reboot", "nfw-poweroff"):
        r = subprocess.run(["systemctl", "stop", f"{unit}.timer"],
                           capture_output=True, timeout=5)
        if r.returncode == 0:
            cancelled.append(unit)
    return {"ok": True, "cancelled": cancelled}
