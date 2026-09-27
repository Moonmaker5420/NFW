"""First-run setup wizard — page + API."""
from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.requests import Request

from ..auth import Session
from ..deps import require_acl
from ..configd_client import ConfigdError, call as configd_call

LOG = logging.getLogger("api.wizard")
router = APIRouter(tags=["wizard"])

TEMPLATE_DIR = Path("/opt/nfw/web/templates")
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


class CompleteBody(BaseModel):
    hostname: str
    timezone: str = "UTC"
    admin_password: str


@router.get("/wizard", response_class=HTMLResponse)
async def wizard_page(request: Request):
    return templates.TemplateResponse(request, "wizard.html", {})


@router.post("/api/wizard/complete")
async def wizard_complete(body: CompleteBody,
                          user: Session = Depends(require_acl("admin"))):
    try:
        r = await configd_call("wizard.complete", body.model_dump(), timeout=30.0)
    except ConfigdError as e:
        raise HTTPException(status_code=500, detail=str(e))
    if not r.get("ok"):
        raise HTTPException(status_code=400,
                            detail=r.get("error", "setup failed"))
    return r
