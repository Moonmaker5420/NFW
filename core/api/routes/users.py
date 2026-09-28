"""User management routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException
import bcrypt

from ..auth import Session
from ..configd_client import ConfigdError, call as configd_call
from ..deps import require_acl

def _bcrypt_hash(password: str) -> str:
    """Hash a password with bcrypt. Rejects > 72 bytes."""
    pw = password.encode("utf-8")
    if len(pw) > 72:
        raise ValueError("password longer than 72 bytes")
    return bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12)).decode("utf-8")


router = APIRouter(prefix="/api/users", tags=["users"])


async def _cd(action: str, data: dict[str, Any] | None = None):
    try:
        return await configd_call(action, data)
    except ConfigdError as e:
        raise HTTPException(status_code=502, detail=f"configd: {e}")


@router.get("/")
async def list_users(user: Session = Depends(require_acl("admin"))):
    return await _cd("users.list")


@router.post("/")
async def create_user(body: dict = Body(...),
                      user: Session = Depends(require_acl("admin"))):
    username = body.get("username")
    password = body.get("password")
    role = body.get("role", "readonly")
    if not username or not password:
        raise HTTPException(status_code=400, detail="username and password required")
    h = _bcrypt_hash(password)
    return await _cd("users.create", {"username": username, "hash": h, "role": role})


@router.delete("/{username}")
async def delete_user(username: str,
                      user: Session = Depends(require_acl("admin"))):
    if username == user.username:
        raise HTTPException(status_code=400, detail="cannot delete self")
    return await _cd("users.delete", {"username": username})


@router.post("/{username}/password")
async def change_password(username: str, body: dict = Body(...),
                          user: Session = Depends(require_acl("readonly"))):
    if username != user.username and user.role != "admin":
        raise HTTPException(status_code=403, detail="admin required")
    password = body.get("password")
    if not password:
        raise HTTPException(status_code=400, detail="password required")
    h = _bcrypt_hash(password)
    return await _cd("users.set_password", {"username": username, "hash": h})


@router.post("/{username}/role")
async def set_role(username: str, body: dict = Body(...),
                   user: Session = Depends(require_acl("admin"))):
    role = body.get("role")
    if role not in ("admin", "operator", "readonly"):
        raise HTTPException(status_code=400, detail="invalid role")
    return await _cd("users.set_role", {"username": username, "role": role})


@router.post("/{username}/disabled")
async def set_disabled(username: str, body: dict = Body(...),
                       user: Session = Depends(require_acl("admin"))):
    if username == user.username:
        raise HTTPException(status_code=400, detail="cannot disable self")
    return await _cd("users.set_disabled",
                     {"username": username, "disabled": bool(body.get("disabled", False))})

# =============================================================================
# Phase 9.9a — per-user 2FA management
# =============================================================================
@router.get("/{username}/2fa")
async def user_2fa_status(username: str,
                          user: Session = Depends(require_acl("readonly"))):
    # A user can view their own status; admin can view anyone's
    if username != user.username and user.role != "admin":
        raise HTTPException(status_code=403, detail="admin required")
    return await _cd("users.totp.status", {"username": username})


@router.post("/{username}/2fa/setup")
async def user_2fa_setup(username: str,
                         user: Session = Depends(require_acl("readonly"))):
    if username != user.username and user.role != "admin":
        raise HTTPException(status_code=403, detail="admin required")
    return await _cd("users.totp.setup", {"username": username})


@router.post("/{username}/2fa/enable")
async def user_2fa_enable(username: str, body: dict = Body(...),
                          user: Session = Depends(require_acl("readonly"))):
    if username != user.username and user.role != "admin":
        raise HTTPException(status_code=403, detail="admin required")
    return await _cd("users.totp.enable",
                     {"username": username, "code": body.get("code")})


@router.post("/{username}/2fa/cancel")
async def user_2fa_cancel(username: str,
                          user: Session = Depends(require_acl("readonly"))):
    """Abort an in-progress 2FA enrollment (clears pending secret)."""
    if username != user.username and user.role != "admin":
        raise HTTPException(status_code=403, detail="admin required")
    return await _cd("users.totp.cancel", {"username": username})


@router.post("/{username}/2fa/disable")
async def user_2fa_disable(username: str,
                           user: Session = Depends(require_acl("readonly"))):
    # Self-service disable requires admin OR self (with the note that
    # the user must have already authenticated — this endpoint is behind
    # the session cookie).
    if username != user.username and user.role != "admin":
        raise HTTPException(status_code=403, detail="admin required")
    return await _cd("users.totp.disable", {"username": username})


@router.post("/{username}/2fa/require")
async def user_2fa_require(username: str, body: dict = Body(...),
                           user: Session = Depends(require_acl("admin"))):
    return await _cd("users.totp.require",
                     {"username": username,
                      "required": bool(body.get("required", True))})


@router.post("/{username}/2fa/recovery")
async def user_2fa_recovery(username: str,
                            user: Session = Depends(require_acl("readonly"))):
    if username != user.username and user.role != "admin":
        raise HTTPException(status_code=403, detail="admin required")
    return await _cd("users.totp.recovery_regen", {"username": username})

