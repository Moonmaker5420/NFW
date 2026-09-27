"""IDS/IPS API routes."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, Body, Depends, HTTPException

from ..auth import Session
from ..configd_client import ConfigdError, call as configd_call
from ..deps import require_acl

router = APIRouter(prefix="/api/ids", tags=["ids"])


async def _cd(action: str, data: dict[str, Any] | None = None):
    try:
        return await configd_call(action, data)
    except ConfigdError as e:
        raise HTTPException(status_code=502, detail=f"configd: {e}")


@router.get("")
async def ids_get(user: Session = Depends(require_acl("readonly"))):
    return await _cd("ids.config.get")

@router.put("")
async def ids_set(body: dict = Body(...), user: Session = Depends(require_acl("operator"))):
    return await _cd("ids.config.set", {"config": body.get("config"), "author": user.username})

@router.get("/preview")
async def ids_preview(user: Session = Depends(require_acl("readonly"))):
    return await _cd("ids.preview")

@router.post("/apply")
async def ids_apply(user: Session = Depends(require_acl("admin"))):
    # Suricata config test takes 20-30s with 50k+ rules; give it room.
    from ..configd_client import ConfigdError, call as _call
    try:
        return await _call("ids.apply", timeout=180.0)
    except ConfigdError as e:
        from fastapi import HTTPException
        msg = str(e)
        if "not found" in msg:
            raise HTTPException(status_code=404, detail=msg)
        raise HTTPException(status_code=502, detail=f"configd: {e}")

@router.post("/update-rules")
async def ids_update(user: Session = Depends(require_acl("admin"))):
    return await _cd("ids.update_rules")

@router.get("/alerts")
async def ids_alerts(limit: int = 100, severity: str = "", src: str = "",
                     user: Session = Depends(require_acl("readonly"))):
    return await _cd("ids.alerts", {"limit": limit, "severity": severity, "src": src})
