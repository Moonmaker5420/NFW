"""NFW API — FastAPI application (Phase 4)."""
from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .middleware.auth import PageAuthMiddleware
from .routes import auth as r_auth
from .routes import auth_oauth as r_auth_oauth
from .routes import auth_providers as r_auth_providers
from .routes import ca as r_ca
from .routes import config as r_config
from .routes import reporting as r_reporting
from .routes import firewall as r_firewall
from .routes import advanced as r_advanced
from .routes import gateway as r_gateway
from .routes import interfaces as r_ifaces_adv
from .routes import ids as r_ids
from .routes import shaper as r_shaper
from .routes import network as r_network
from .routes import services as r_services
from .routes import system as r_system
from .routes import schedules as r_schedules
from .routes import ui as r_ui
from .routes import diagnostics as r_diagnostics
from .routes import users as r_users
from .routes import vpn as r_vpn
from .routes import ws as r_ws

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)

app = FastAPI(title="NFW API", version=__version__)

TEMPLATE_DIR = Path("/opt/nfw/web/templates")
STATIC_DIR = Path("/opt/nfw/web/static")

app.add_middleware(PageAuthMiddleware)

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

app.include_router(r_auth.router)
app.include_router(r_auth_oauth.router)
app.include_router(r_auth_providers.router)
app.include_router(r_ca.router)
app.include_router(r_config.router)
app.include_router(r_reporting.router)
app.include_router(r_firewall.router)
app.include_router(r_advanced.router)
app.include_router(r_gateway.router)
app.include_router(r_ifaces_adv.router)
app.include_router(r_ids.router)
app.include_router(r_shaper.router)
app.include_router(r_network.router)
app.include_router(r_services.router)
app.include_router(r_system.router)
app.include_router(r_users.router)
app.include_router(r_vpn.router)
app.include_router(r_ws.router)
app.include_router(r_schedules.router)
app.include_router(r_ui.router)
app.include_router(r_diagnostics.router)


@app.get("/api/health")
async def health():
    return {"ok": True, "version": __version__}


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    logging.exception("unhandled error in API")
    return JSONResponse(status_code=500, content={"ok": False, "error": str(exc)})
