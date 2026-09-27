"""Advanced interface API routes."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, Body, Depends, HTTPException

from ..auth import Session
from ..configd_client import ConfigdError, call as configd_call
from ..deps import require_acl

router = APIRouter(prefix="/api/interfaces/advanced", tags=["interfaces"])


async def _cd(action: str, data: dict[str, Any] | None = None):
    try:
        return await configd_call(action, data)
    except ConfigdError as e:
        raise HTTPException(status_code=502, detail=f"configd: {e}")


@router.get("")
async def list_ifaces(user: Session = Depends(require_acl("readonly"))):
    return await _cd("interfaces.advanced.list")

@router.post("")
async def add_iface(body: dict = Body(...), user: Session = Depends(require_acl("operator"))):
    return await _cd("interfaces.advanced.add", {"interface": body.get("interface"), "author": user.username})

@router.put("/{name}")
async def update_iface(name: str, body: dict = Body(...), user: Session = Depends(require_acl("operator"))):
    return await _cd("interfaces.advanced.update", {"name": name, "interface": body.get("interface"), "author": user.username})

@router.delete("/{name}")
async def delete_iface(name: str, user: Session = Depends(require_acl("operator"))):
    return await _cd("interfaces.advanced.delete", {"name": name, "author": user.username})

@router.get("/preview")
async def preview(user: Session = Depends(require_acl("readonly"))):
    return await _cd("interfaces.advanced.preview")

@router.post("/apply")
async def apply(user: Session = Depends(require_acl("admin"))):
    return await _cd("interfaces.advanced.apply")
