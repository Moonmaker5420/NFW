"""Reporting API (Phase 9.14)."""
from __future__ import annotations
import base64
import re
from typing import Any
from fastapi import APIRouter, Body, Depends, HTTPException, Query, Response

from ..auth import Session
from ..configd_client import ConfigdError, call as configd_call
from ..deps import require_acl

router = APIRouter(prefix="/api/reporting", tags=["reporting"])

_SAFE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


async def _cd(action: str, data: dict[str, Any] | None = None, timeout: float = 30.0):
    try:
        return await configd_call(action, data, timeout=timeout)
    except ConfigdError as e:
        raise HTTPException(status_code=502, detail=f"configd: {e}")


@router.get("/status")
async def status(user: Session = Depends(require_acl("readonly"))):
    return await _cd("reporting.status")


@router.get("/graphs")
async def graphs(user: Session = Depends(require_acl("readonly"))):
    return await _cd("reporting.graph_list")


@router.get("/graph/{name}.png")
async def graph_png(name: str,
                    range: str = Query("day"),
                    width: int = Query(700),
                    height: int = Query(200),
                    user: Session = Depends(require_acl("readonly"))):
    if not _SAFE.match(name):
        raise HTTPException(400, "invalid graph name")
    r = await _cd("reporting.graph",
                  {"name": name, "range": range, "width": width, "height": height},
                  timeout=45)
    png = base64.b64decode(r["png_b64"])
    return Response(content=png, media_type="image/png",
                    headers={"Cache-Control": "no-store, max-age=0"})


@router.get("/top")
async def top(limit: int = Query(20),
              user: Session = Depends(require_acl("readonly"))):
    return await _cd("reporting.top_talkers", {"limit": limit})


@router.get("/netflow")
async def netflow_get(user: Session = Depends(require_acl("readonly"))):
    return await _cd("reporting.netflow_status")


@router.put("/netflow")
async def netflow_set(body: dict = Body(...),
                      user: Session = Depends(require_acl("operator"))):
    return await _cd("reporting.netflow_set",
                     {"netflow": body.get("netflow"), "author": user.username})


@router.post("/netflow/apply")
async def netflow_apply(user: Session = Depends(require_acl("admin"))):
    return await _cd("reporting.netflow_apply", timeout=60)
