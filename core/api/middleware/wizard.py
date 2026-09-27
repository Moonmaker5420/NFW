"""Wizard gate — redirect to /wizard when setup is pending."""
from __future__ import annotations

import os

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse

MARKER = "/var/lib/nfw/config/setup_pending"

ALLOWED_PREFIXES = (
    "/wizard",
    "/api/wizard",
    "/api/health",
    "/api/auth",
    "/static",
    "/favicon",
    "/login",
    "/logout",
)


def _pending() -> bool:
    try:
        return os.path.exists(MARKER)
    except OSError:
        return False


def _is_allowed(path: str) -> bool:
    return any(path == p or path.startswith(p + "/") or path.startswith(p)
               for p in ALLOWED_PREFIXES)


class WizardGateMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if not _pending():
            return await call_next(request)
        path = request.url.path
        if _is_allowed(path):
            return await call_next(request)
        if path.startswith("/api/"):
            return JSONResponse(
                {"detail": "setup pending", "redirect": "/wizard"},
                status_code=403,
            )
        return RedirectResponse("/wizard", status_code=302)
