"""LDAP + RADIUS provider configuration API (Phase 9.9b)."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, Body, Depends, HTTPException

from ..auth import Session
from ..configd_client import ConfigdError, call as configd_call
from ..deps import require_acl

router = APIRouter(prefix="/api/auth/providers", tags=["auth-providers"])


async def _cd(action: str, data: dict | None = None, timeout: float = 30.0):
    try:
        return await configd_call(action, data, timeout=timeout)
    except ConfigdError as e:
        raise HTTPException(status_code=502, detail=f"configd: {e}")


@router.get("")
async def get_config(user: Session = Depends(require_acl("admin"))):
    return await _cd("auth.config.get")


@router.put("")
async def set_config(body: dict = Body(...),
                     user: Session = Depends(require_acl("admin"))):
    return await _cd("auth.config.set",
                     {**body, "author": user.username})


@router.post("/ldap/test")
async def ldap_test(user: Session = Depends(require_acl("admin"))):
    return await _cd("auth.ldap.test", timeout=30)


@router.post("/radius/test")
async def radius_test(user: Session = Depends(require_acl("admin"))):
    return await _cd("auth.radius.test", timeout=30)
