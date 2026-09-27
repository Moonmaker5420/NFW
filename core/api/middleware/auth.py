"""Page-level auth middleware: redirect unauthenticated page requests to /login.

Implemented as pure ASGI middleware to avoid the BaseHTTPMiddleware bug that
triggers TypeError: unhashable type: 'dict' when the app also mounts
StaticFiles and WebSocket routes.
"""
from __future__ import annotations

from starlette.requests import Request
from starlette.responses import RedirectResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from ..auth import session_from_request


PUBLIC_PREFIXES = (
    "/login",
    "/static/",
    "/api/auth/login",
    "/api/auth/logout",
    "/api/health",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/favicon.ico",
)


class PageAuthMiddleware:
    """Pure-ASGI middleware. Only intercepts HTTP requests, not WebSocket."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path.startswith("/api/") or path.startswith("/static/"):
            await self.app(scope, receive, send)
            return
        if any(path.startswith(p) for p in PUBLIC_PREFIXES):
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        if session_from_request(request) is None:
            next_url = path
            qs = scope.get("query_string", b"")
            if qs:
                next_url += "?" + qs.decode("latin-1")
            response = RedirectResponse(url=f"/login?next={next_url}", status_code=302)
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)
