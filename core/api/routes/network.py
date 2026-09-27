"""Network discovery + assignment API routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException

from ..auth import Session
from ..configd_client import ConfigdError, call as configd_call
from ..deps import require_acl

router = APIRouter(prefix="/api/network", tags=["network"])


async def _cd(action: str, data: dict[str, Any] | None = None):
    try:
        return await configd_call(action, data)
    except ConfigdError as e:
        raise HTTPException(status_code=502, detail=f"configd: {e}")


@router.get("/discover")
async def discover(user: Session = Depends(require_acl("readonly"))):
    return await _cd("network.discover")


@router.post("/resolve")
async def resolve(body: dict = Body(...),
                  user: Session = Depends(require_acl("readonly"))):
    return await _cd("network.resolve_roles", {"network": body.get("network")})


@router.get("/assignments")
async def assignments(user: Session = Depends(require_acl("readonly"))):
    return await _cd("network.assignments")


@router.post("/validate")
async def validate(body: dict = Body(...),
                   user: Session = Depends(require_acl("readonly"))):
    return await _cd("network.validate_assignment",
                     {"network": body.get("network")})


@router.post("/apply")
async def apply(body: dict = Body(...),
                user: Session = Depends(require_acl("admin"))):
    return await _cd("network.apply_assignment",
                     {"network": body.get("network"),
                      "author": user.username})


# ---- Phase 4.6 — per-interface config --------------------------------------
@router.get("/ifaces")
async def ifaces_list(user: Session = Depends(require_acl("readonly"))):
    return await _cd("network.iface.get_all")


@router.get("/ifaces/{dev}")
async def ifaces_get(dev: str, user: Session = Depends(require_acl("readonly"))):
    return await _cd("network.iface.get", {"device": dev})


@router.put("/ifaces/{dev}")
async def ifaces_set(dev: str, body: dict = Body(...),
                     user: Session = Depends(require_acl("operator"))):
    return await _cd("network.iface.set",
                     {"device": dev, "config": body.get("config"),
                      "author": user.username})


@router.delete("/ifaces/{dev}")
async def ifaces_unset(dev: str,
                       user: Session = Depends(require_acl("operator"))):
    return await _cd("network.iface.unset",
                     {"device": dev, "author": user.username})


@router.get("/ifaces-preview")
async def ifaces_preview(user: Session = Depends(require_acl("readonly"))):
    return await _cd("network.iface.preview")


@router.post("/ifaces-apply")
async def ifaces_apply(user: Session = Depends(require_acl("admin"))):
    return await _cd("network.iface.apply")
