"""Auth routes — including 2FA challenge (Phase 9.9a)."""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Response, status
from pydantic import BaseModel

from ..auth import (
    Session, clear_session_cookie, consume_pending, current_user,
    fail_pending, get_pending, login, set_session_cookie,
)
from ..configd_client import ConfigdError, call as configd_call

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginBody(BaseModel):
    username: str
    password: str


class TwoFABody(BaseModel):
    pending_sid: str
    code: str


@router.post("/login")
async def do_login(body: LoginBody, response: Response):
    result = await login(body.username, body.password)

    # 2FA path: don't set a cookie, hand back the pending sid
    if isinstance(result, dict) and result.get("requires_2fa"):
        return {
            "ok": True,
            "requires_2fa": True,
            "pending_sid": result["pending_sid"],
            "username": result["username"],
        }

    sess: Session = result["session"]
    set_session_cookie(response, sess)
    return {"ok": True, "username": sess.username, "role": sess.role}


@router.post("/2fa")
async def do_2fa(body: TwoFABody, response: Response):
    pending = get_pending(body.pending_sid)
    if pending is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="pending session expired or invalid")

    # Ask configd to verify the code (or recovery code) for this user
    try:
        r = await configd_call("users.totp.verify_for_login",
                               {"username": pending.username,
                                "code": body.code})
    except ConfigdError as e:
        raise HTTPException(status_code=502, detail=f"configd: {e}")

    if not r.get("valid"):
        destroyed = fail_pending(body.pending_sid)
        LOG_msg = "invalid 2FA code" + (" (session destroyed)" if destroyed else "")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=LOG_msg)

    # Correct code — finalize login
    consume_pending(body.pending_sid)

    try:
        user_rec = await configd_call("users.get", {"username": pending.username})
    except ConfigdError as e:
        raise HTTPException(status_code=502, detail=f"configd: {e}")
    user = user_rec.get("user") or {}
    import secrets, time
    from ..auth import _SESSIONS, _gc_sessions, Session as S
    sid = secrets.token_urlsafe(32)
    now = time.time()
    sess = S(sid=sid, username=pending.username,
             role=user.get("role", "readonly"),
             created=now, last_seen=now)
    _SESSIONS[sid] = sess
    _gc_sessions()
    set_session_cookie(response, sess)
    return {"ok": True, "username": sess.username, "role": sess.role}


@router.post("/logout")
async def do_logout(response: Response):
    clear_session_cookie(response)
    return {"ok": True}


@router.get("/whoami")
async def whoami(user: Session = Depends(current_user)):
    return {
        "ok": True,
        "username": user.username,
        "role": user.role,
        "created": user.created,
        "last_seen": user.last_seen,
    }
