"""Gateway API routes."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, Body, Depends, HTTPException

from ..auth import Session
from ..configd_client import ConfigdError, call as configd_call
from ..deps import require_acl

router = APIRouter(prefix="/api/gateways", tags=["gateways"])


async def _cd(action: str, data: dict[str, Any] | None = None):
    try:
        return await configd_call(action, data)
    except ConfigdError as e:
        raise HTTPException(status_code=502, detail=f"configd: {e}")


# --- Gateways --------------------------------------------------------------
@router.get("")
async def list_gateways(user: Session = Depends(require_acl("readonly"))):
    return await _cd("gateway.list")


@router.post("")
async def add_gateway(body: dict = Body(...),
                      user: Session = Depends(require_acl("operator"))):
    return await _cd("gateway.add",
                     {"gateway": body.get("gateway"), "author": user.username})


@router.put("/{gid}")
async def update_gateway(gid: str, body: dict = Body(...),
                         user: Session = Depends(require_acl("operator"))):
    return await _cd("gateway.update",
                     {"id": gid, "gateway": body.get("gateway"),
                      "author": user.username})


@router.delete("/{gid}")
async def delete_gateway(gid: str,
                         user: Session = Depends(require_acl("operator"))):
    return await _cd("gateway.delete", {"id": gid, "author": user.username})


# --- Groups ----------------------------------------------------------------
@router.post("/groups")
async def add_group(body: dict = Body(...),
                    user: Session = Depends(require_acl("operator"))):
    return await _cd("gateway.groups.add",
                     {"group": body.get("group"), "author": user.username})


@router.put("/groups/{gid}")
async def update_group(gid: str, body: dict = Body(...),
                       user: Session = Depends(require_acl("operator"))):
    return await _cd("gateway.groups.update",
                     {"id": gid, "group": body.get("group"),
                      "author": user.username})


@router.delete("/groups/{gid}")
async def delete_group(gid: str,
                       user: Session = Depends(require_acl("operator"))):
    return await _cd("gateway.groups.delete", {"id": gid, "author": user.username})


# --- Routes ----------------------------------------------------------------
@router.post("/routes")
async def add_route(body: dict = Body(...),
                    user: Session = Depends(require_acl("operator"))):
    return await _cd("gateway.routes.add",
                     {"route": body.get("route"), "author": user.username})


@router.delete("/routes/{rid}")
async def delete_route(rid: str,
                       user: Session = Depends(require_acl("operator"))):
    return await _cd("gateway.routes.delete", {"id": rid, "author": user.username})


# --- Status + apply --------------------------------------------------------
@router.get("/status")
async def gateway_status(user: Session = Depends(require_acl("readonly"))):
    return await _cd("gateway.status")


@router.post("/apply")
async def gateway_apply(user: Session = Depends(require_acl("admin"))):
    return await _cd("gateway.apply")


@router.post("/routes/sync")
async def routes_sync(user: Session = Depends(require_acl("admin"))):
    return await _cd("gateway.routes.sync")
