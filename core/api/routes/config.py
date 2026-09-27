"""Config routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException

from ..auth import Session
from ..configd_client import ConfigdError, call as configd_call
from ..deps import require_acl

router = APIRouter(prefix="/api/config", tags=["config"])


async def _cd(action: str, data: dict[str, Any] | None = None):
    try:
        return await configd_call(action, data)
    except ConfigdError as e:
        raise HTTPException(status_code=502, detail=f"configd: {e}")


@router.get("/")
async def read_config(user: Session = Depends(require_acl("readonly"))):
    return await _cd("config.read")


@router.get("/defaults")
async def defaults(user: Session = Depends(require_acl("readonly"))):
    return await _cd("config.defaults")


@router.post("/validate")
async def validate(body: dict = Body(...),
                   user: Session = Depends(require_acl("readonly"))):
    return await _cd("config.validate", {"config": body.get("config")})


@router.post("/stage")
async def stage(body: dict = Body(...),
                user: Session = Depends(require_acl("operator"))):
    return await _cd("config.stage", {
        "config": body.get("config"),
        "author": user.username,
    })


@router.post("/discard")
async def discard(user: Session = Depends(require_acl("operator"))):
    return await _cd("config.discard_staging")


@router.post("/commit")
async def commit(body: dict = Body(default={}),
                 user: Session = Depends(require_acl("admin"))):
    return await _cd("config.commit", {
        "author": user.username,
        "message": body.get("message", ""),
    })


@router.post("/rollback")
async def rollback(body: dict = Body(...),
                   user: Session = Depends(require_acl("admin"))):
    return await _cd("config.rollback", {
        "revision": body.get("revision"),
        "author": user.username,
        "reason": body.get("reason", ""),
    })


@router.get("/revisions")
async def revisions(limit: int = 100,
                    user: Session = Depends(require_acl("readonly"))):
    return await _cd("config.revisions", {"limit": limit})


@router.get("/revisions/{revision}")
async def get_revision(revision: str,
                       user: Session = Depends(require_acl("readonly"))):
    return await _cd("config.get_revision", {"revision": revision})


@router.get("/effective")
async def read_effective(user: Session = Depends(require_acl("readonly"))):
    """Return the config that WILL be applied: staged if present, active otherwise."""
    return await _cd("config.read_effective")
