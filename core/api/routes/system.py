"""System routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query

from ..auth import Session
from ..configd_client import ConfigdError, call as configd_call
from ..deps import require_acl

router = APIRouter(prefix="/api/system", tags=["system"])


async def _cd(action: str, data: dict[str, Any] | None = None):
    try:
        return await configd_call(action, data)
    except ConfigdError as e:
        raise HTTPException(status_code=502, detail=f"configd: {e}")


@router.get("/ping")
async def ping():
    return await _cd("core.ping")


@router.get("/version")
async def version(user: Session = Depends(require_acl("readonly"))):
    return await _cd("core.version")


@router.get("/info")
async def info(user: Session = Depends(require_acl("readonly"))):
    return await _cd("system.info")


@router.get("/modules")
async def modules(user: Session = Depends(require_acl("readonly"))):
    return await _cd("system.modules")


@router.get("/interfaces")
async def interfaces(user: Session = Depends(require_acl("readonly"))):
    return await _cd("network.interfaces")


@router.get("/routes")
async def routes(user: Session = Depends(require_acl("readonly"))):
    return await _cd("network.routes")


@router.get("/conntrack")
async def conntrack(user: Session = Depends(require_acl("readonly"))):
    return await _cd("network.conntrack_count")


@router.get("/firewall/status")
async def firewall_status(user: Session = Depends(require_acl("readonly"))):
    return await _cd("firewall.status")


@router.post("/firewall/reload")
async def firewall_reload(user: Session = Depends(require_acl("admin"))):
    return await _cd("firewall.reload")


@router.get("/logs/{name}")
async def logs(name: str, lines: int = 100,
               user: Session = Depends(require_acl("readonly"))):
    return await _cd("system.logs", {"file": name, "lines": lines})


# --- Services (UI needs list + status + restart) ---------------------------
@router.get("/services")
async def services_list(user: Session = Depends(require_acl("readonly"))):
    return await _cd("service.list")


@router.get("/service-status")
async def service_status(unit: str = Query(...),
                         user: Session = Depends(require_acl("readonly"))):
    return await _cd("service.status", {"unit": unit})


@router.post("/service-restart")
async def service_restart(body: dict = Body(...),
                          user: Session = Depends(require_acl("admin"))):
    return await _cd("service.restart", {"unit": body.get("unit")})
