"""Traffic shaping API routes."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, Body, Depends, HTTPException

from ..auth import Session
from ..configd_client import ConfigdError, call as configd_call
from ..deps import require_acl

router = APIRouter(prefix="/api/shaper", tags=["shaper"])


async def _cd(action: str, data: dict[str, Any] | None = None):
    try:
        return await configd_call(action, data)
    except ConfigdError as e:
        raise HTTPException(status_code=502, detail=f"configd: {e}")


@router.get("")
async def shaper_get(user: Session = Depends(require_acl("readonly"))):
    return await _cd("shaper.config.get")

@router.put("")
async def shaper_set(body: dict = Body(...), user: Session = Depends(require_acl("operator"))):
    return await _cd("shaper.config.set", {"config": body.get("config"), "author": user.username})

@router.post("/apply")
async def shaper_apply(user: Session = Depends(require_acl("admin"))):
    return await _cd("shaper.apply")

@router.get("/status")
async def shaper_status(user: Session = Depends(require_acl("readonly"))):
    return await _cd("shaper.status")
