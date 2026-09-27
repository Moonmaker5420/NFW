"""Service control actions."""
from __future__ import annotations

import subprocess
from typing import Any

from configd.registry import action

SYSTEMCTL = "/usr/bin/systemctl"

MANAGED_UNITS = {
    "nftables.service",
    "unbound.service",
    "isc-dhcp-server.service",
    "suricata.service",
    "wg-quick@wg0.service",
    "nfw-configd.service",
}


def _run(cmd: list[str], timeout: int = 20) -> dict[str, Any]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return {"rc": 124, "stdout": "", "stderr": "timeout"}
    return {"rc": p.returncode, "stdout": p.stdout, "stderr": p.stderr}


def _check_unit(unit: str) -> None:
    if unit not in MANAGED_UNITS:
        raise ValueError(f"unit '{unit}' not managed by NFW")


@action("service.status")
def service_status(data: dict[str, Any]) -> dict[str, Any]:
    unit = data.get("unit")
    if not isinstance(unit, str):
        raise ValueError("missing 'unit'")
    _check_unit(unit)
    r = _run([SYSTEMCTL, "is-active", unit])
    active = r["stdout"].strip()
    r2 = _run([SYSTEMCTL, "show", unit, "--property=ActiveState,SubState,MainPID"])
    return {"ok": True, "unit": unit, "active": active, "props": r2["stdout"]}


@action("service.restart")
def service_restart(data: dict[str, Any]) -> dict[str, Any]:
    unit = data.get("unit")
    if not isinstance(unit, str):
        raise ValueError("missing 'unit'")
    _check_unit(unit)
    r = _run([SYSTEMCTL, "restart", unit])
    return {"ok": r["rc"] == 0, **r}


@action("service.list")
def service_list(_data: dict[str, Any]) -> dict[str, Any]:
    return {"units": sorted(MANAGED_UNITS)}
