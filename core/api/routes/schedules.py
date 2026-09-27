"""Schedules API routes (Phase 9.7a)."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, Body, Depends, HTTPException

from ..auth import Session
from ..configd_client import ConfigdError, call as configd_call
from ..deps import require_acl

router = APIRouter(prefix="/api/firewall/schedules", tags=["schedules"])


async def _cd(action: str, data: dict[str, Any] | None = None):
    try:
        return await configd_call(action, data)
    except ConfigdError as e:
        raise HTTPException(status_code=502, detail=f"configd: {e}")


@router.get("")
async def list_schedules(user: Session = Depends(require_acl("readonly"))):
    return await _cd("schedules.list")


@router.get("/active")
async def active_schedules(user: Session = Depends(require_acl("readonly"))):
    return await _cd("schedules.active")


@router.post("")
async def add_schedule(body: dict = Body(...),
                       user: Session = Depends(require_acl("operator"))):
    return await _cd("schedules.add",
                     {"schedule": body.get("schedule"), "author": user.username})


@router.put("/{sid}")
async def update_schedule(sid: str, body: dict = Body(...),
                          user: Session = Depends(require_acl("operator"))):
    return await _cd("schedules.update",
                     {"id": sid, "schedule": body.get("schedule"),
                      "author": user.username})


@router.delete("/{sid}")
async def delete_schedule(sid: str,
                          user: Session = Depends(require_acl("operator"))):
    return await _cd("schedules.delete",
                     {"id": sid, "author": user.username})


@router.post("/{sid}/toggle")
async def toggle_schedule(sid: str,
                          user: Session = Depends(require_acl("operator"))):
    return await _cd("schedules.toggle",
                     {"id": sid, "author": user.username})
