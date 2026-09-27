"""
Session auth: bcrypt password check + signed cookie sessions.
"""
from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import bcrypt
from fastapi import HTTPException, Request, Response, status
from itsdangerous import BadSignature, URLSafeTimedSerializer

from .configd_client import ConfigdError, call as configd_call

LOG = logging.getLogger("api.auth")

SECRET_FILE = Path("/etc/nfw/secret.key")
COOKIE_NAME = "nfw_session"
SESSION_LIFETIME = 3600


# ---------------------------------------------------------------------------
# Secret / signing
# ---------------------------------------------------------------------------
def _load_secret() -> bytes:
    if SECRET_FILE.exists():
        return SECRET_FILE.read_bytes()
    SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(48)
    SECRET_FILE.write_bytes(key)
    # Group-readable by nfw so the API process (www-data:nfw) can read it.
    import grp as _grp
    try:
        gid = _grp.getgrnam("nfw").gr_gid
        import os as _os
        _os.chown(SECRET_FILE, 0, gid)
        SECRET_FILE.chmod(0o640)
    except KeyError:
        SECRET_FILE.chmod(0o600)
    return key


_serializer: URLSafeTimedSerializer | None = None


def _get_serializer() -> URLSafeTimedSerializer:
    global _serializer
    if _serializer is None:
        _serializer = URLSafeTimedSerializer(_load_secret(), salt="nfw-session")
    return _serializer


# ---------------------------------------------------------------------------
# bcrypt helpers
# ---------------------------------------------------------------------------
def _bcrypt_verify(password: str, hashed: str) -> bool:
    """Verify a password against a bcrypt hash. Returns False on any error."""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError) as e:
        LOG.error("bcrypt.checkpw error: %s: %s", type(e).__name__, e)
        return False


def _bcrypt_hash(password: str) -> str:
    """Hash a password with bcrypt. Rejects > 72 bytes."""
    pw = password.encode("utf-8")
    if len(pw) > 72:
        raise ValueError("password longer than 72 bytes")
    return bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12)).decode("utf-8")


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------
@dataclass
class Session:
    sid: str
    username: str
    role: str
    created: float
    last_seen: float
    data: dict[str, Any] = field(default_factory=dict)


_SESSIONS: dict[str, Session] = {}

# =============================================================================
# Phase 9.9a — pending sessions (password verified, 2FA not yet supplied)
# =============================================================================
PENDING_LIFETIME = 300          # 5 minutes to enter the 2FA code
PENDING_MAX_ATTEMPTS = 5        # then the pending session is destroyed


@dataclass
class PendingSession:
    sid: str
    username: str
    created: float
    expires: float
    attempts: int = 0


_PENDING: dict[str, PendingSession] = {}


def _gc_pending() -> None:
    now = time.time()
    for sid in [s for s, p in _PENDING.items() if now > p.expires]:
        _PENDING.pop(sid, None)


def create_pending(username: str) -> str:
    """Issue a pending sid that must be redeemed within PENDING_LIFETIME."""
    _gc_pending()
    sid = secrets.token_urlsafe(32)
    now = time.time()
    _PENDING[sid] = PendingSession(
        sid=sid, username=username, created=now,
        expires=now + PENDING_LIFETIME,
    )
    return sid


def get_pending(sid: str) -> PendingSession | None:
    _gc_pending()
    p = _PENDING.get(sid)
    if p is None:
        return None
    if time.time() > p.expires:
        _PENDING.pop(sid, None)
        return None
    return p


def consume_pending(sid: str) -> PendingSession | None:
    """Return the pending session and remove it from the store."""
    p = get_pending(sid)
    if p is not None:
        _PENDING.pop(sid, None)
    return p


def fail_pending(sid: str) -> bool:
    """Bump the attempt counter; destroy if over the limit. Returns True
    if the pending session was destroyed."""
    p = _PENDING.get(sid)
    if p is None:
        return True
    p.attempts += 1
    if p.attempts >= PENDING_MAX_ATTEMPTS:
        _PENDING.pop(sid, None)
        return True
    return False



def _gc_sessions() -> None:
    now = time.time()
    expired = [sid for sid, s in _SESSIONS.items()
               if now - s.last_seen > SESSION_LIFETIME]
    for sid in expired:
        del _SESSIONS[sid]


async def _alert_login_failed(username: str, reason: str = "") -> None:
    """Fire-and-forget alert on failed login.

    Called from the login path; must never raise. Calls the configd
    alerts.notify action which handles threshold counting and SMTP.
    """
    try:
        from .configd_client import call as _cd
        await _cd("alerts.notify", {
            "event": "login_failed",
            "context": {"username": username},
            "subject": f"Failed login for '{username}'",
            "body": (f"A login attempt for user '{username}' failed.\n"
                     f"Reason: {reason}\n\n"
                     f"If this was not you, review access to the API port."),
        }, timeout=15.0)
    except Exception:
        pass


async def login(username: str, password: str):
    """Verify credentials. Returns either:
        {"session": Session}              — full auth complete
        {"requires_2fa": True, "pending_sid": ..., "username": ...}
    or raises HTTPException on failure.

    Credential verification is delegated to configd's auth.authenticate
    action which tries local, then LDAP, then RADIUS (in the order set
    in auth.providers). Auto-creates local records for external users.
    """
    try:
        r = await configd_call("auth.authenticate",
                               {"username": username, "password": password},
                               timeout=30.0)
    except ConfigdError as e:
        LOG.error("configd auth.authenticate failed: %s", e)
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail=f"config service unavailable: {e}")

    if not r or not r.get("ok"):
        LOG.warning("login: failed for %r (%s)", username,
                    (r or {}).get("reason", "invalid credentials"))
        # Fire-and-forget alert dispatch. Failure to notify must never
        # break the auth path — wrap everything in try/except.
        try:
            import asyncio as _asyncio
            _asyncio.create_task(_alert_login_failed(username, reason=str(
                (r or {}).get("reason", "invalid credentials"))))
        except Exception as _e:
            LOG.debug("alerts hook failed silently: %s", _e)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="invalid credentials")

    username = r.get("username", username)
    role = r.get("role", "readonly")
    method = r.get("method", "local")
    totp_enabled = bool(r.get("totp_enabled", False))

    if totp_enabled:
        pending_sid = create_pending(username)
        LOG.info("login: password OK (%s), 2FA required for %r", method, username)
        return {"requires_2fa": True, "pending_sid": pending_sid,
                "username": username}

    sid = secrets.token_urlsafe(32)
    now = time.time()
    sess = Session(sid=sid, username=username, role=role,
                   created=now, last_seen=now)
    _SESSIONS[sid] = sess
    _gc_sessions()
    LOG.info("login OK: user=%r role=%r method=%s", username, role, method)
    return {"session": sess}

def logout(sid: str) -> None:
    _SESSIONS.pop(sid, None)


def get_session(sid: str) -> Session | None:
    s = _SESSIONS.get(sid)
    if s is None:
        return None
    if time.time() - s.last_seen > SESSION_LIFETIME:
        del _SESSIONS[sid]
        return None
    s.last_seen = time.time()
    return s


def set_session_cookie(response: Response, session: Session) -> None:
    token = _get_serializer().dumps({"sid": session.sid})
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=SESSION_LIFETIME,
        httponly=True,
        samesite="strict",
        secure=False,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(COOKIE_NAME, path="/")


def session_from_request(request: Request) -> Session | None:
    raw = request.cookies.get(COOKIE_NAME)
    if not raw:
        return None
    try:
        data = _get_serializer().loads(raw, max_age=SESSION_LIFETIME)
    except BadSignature:
        return None
    sid = data.get("sid")
    if not sid:
        return None
    return get_session(sid)


def current_user(request: Request) -> Session:
    sess = session_from_request(request)
    if sess is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="not authenticated")
    return sess
