"""OAuth/OIDC login + ACL admin routes (Phase 9.9c)."""
from __future__ import annotations
import secrets
import time
from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from fastapi.responses import RedirectResponse

from ..auth import Session, _SESSIONS, _gc_sessions, set_session_cookie
from ..auth import _get_serializer as _sess_serializer  # reuse secret
from ..configd_client import ConfigdError, call as configd_call
from ..deps import require_acl, require_acl
from itsdangerous import BadSignature, URLSafeTimedSerializer

router = APIRouter(tags=["oauth"])

# Dedicated serializer for OAuth state (different salt)
_oauth_serializer: URLSafeTimedSerializer | None = None
_STATE_TTL = 300


def _serializer() -> URLSafeTimedSerializer:
    global _oauth_serializer
    if _oauth_serializer is None:
        secret = _sess_serializer().secret_key
        _oauth_serializer = URLSafeTimedSerializer(secret, salt="nfw-oauth-state")
    return _oauth_serializer


async def _cd(action: str, data: dict | None = None, timeout: float = 30.0):
    try:
        return await configd_call(action, data, timeout=timeout)
    except ConfigdError as e:
        raise HTTPException(status_code=502, detail=f"configd: {e}")


# --- admin get/set for the OAuth providers page ---
@router.get("/api/auth/oauth/get")
async def oauth_admin_get(user: Session = Depends(require_acl("admin"))):
    return await _cd("auth.oauth.get")


@router.put("/api/auth/oauth/set")
async def oauth_admin_set(body: dict = Body(...),
                          user: Session = Depends(require_acl("admin"))):
    return await _cd("auth.oauth.set", {
        "oauth": body.get("oauth") or {},
        "author": user.username,
    })


# --- public list for the login page ---
@router.get("/api/auth/oauth/providers")
async def list_oauth_providers():
    return await _cd("auth.oauth.list_enabled")


# --- start the flow ---
@router.get("/api/auth/oauth/start/{provider_id}")
async def oauth_start(provider_id: str, request: Request,
                      next: str = Query("/")):
    # Build the callback URL from the request
    scheme = request.url.scheme
    host = request.headers.get("host") or request.url.netloc
    redirect_uri = f"{scheme}://{host}/api/auth/oauth/callback/{provider_id}"

    try:
        r = await _cd("auth.oauth.get_provider", {"id": provider_id})
    except HTTPException as e:
        raise e
    provider = r["provider"]
    from modules.auth.oauth_auth import authorization_url
    state = _serializer().dumps({
        "pid": provider_id, "next": next, "nonce": secrets.token_urlsafe(16),
    })
    url = authorization_url(provider, redirect_uri, state)
    return RedirectResponse(url=url, status_code=302)


# --- callback ---
@router.get("/api/auth/oauth/callback/{provider_id}")
async def oauth_callback(provider_id: str, request: Request,
                         code: str = Query(...), state: str = Query(...)):
    try:
        data = _serializer().loads(state, max_age=_STATE_TTL)
    except BadSignature:
        raise HTTPException(400, "invalid or expired state")
    if data.get("pid") != provider_id:
        raise HTTPException(400, "state/provider mismatch")

    scheme = request.url.scheme
    host = request.headers.get("host") or request.url.netloc
    redirect_uri = f"{scheme}://{host}/api/auth/oauth/callback/{provider_id}"

    r = await _cd("auth.oauth.exchange", {
        "id": provider_id, "code": code, "redirect_uri": redirect_uri,
    }, timeout=45.0)

    # Issue a session
    sid = secrets.token_urlsafe(32)
    now = time.time()
    sess = Session(sid=sid, username=r["username"], role=r["role"],
                   created=now, last_seen=now)
    _SESSIONS[sid] = sess
    _gc_sessions()

    # Redirect to the intended page
    dest = data.get("next") or "/"
    response = RedirectResponse(url=dest, status_code=302)
    set_session_cookie(response, sess)
    return response


# =============================================================================
# ACL admin API
# =============================================================================
@router.get("/api/auth/acls")
async def acl_get(user: Session = Depends(require_acl("admin"))):
    return await _cd("auth.acl.get")


@router.put("/api/auth/acls")
async def acl_set(body: dict = Body(...),
                  user: Session = Depends(require_acl("admin"))):
    return await _cd("auth.acl.set",
                     {"acls": body.get("acls"), "author": user.username})


@router.post("/api/auth/acls/test")
async def acl_test(body: dict = Body(...),
                   user: Session = Depends(require_acl("admin"))):
    return await _cd("auth.acl.check", body)
