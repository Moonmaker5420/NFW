"""
User store for the API.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from configd.registry import action

USERS = Path("/etc/nfw/users.json")
ROLES = {"admin", "operator", "readonly"}


def _read() -> dict[str, Any]:
    if not USERS.exists():
        return {}
    try:
        with open(USERS, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def _write(data: dict[str, Any]) -> None:
    USERS.parent.mkdir(parents=True, exist_ok=True)
    tmp = USERS.with_suffix(".json.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, USERS)


@action("users.list")
def users_list(_data: dict[str, Any]) -> dict[str, Any]:
    data = _read()
    out = []
    for name, rec in data.items():
        out.append({
            "username": name,
            "role": rec.get("role", "readonly"),
            "created": rec.get("created"),
            "disabled": rec.get("disabled", False),
        })
    return {"users": sorted(out, key=lambda u: u["username"])}


@action("users.get")
def users_get(data: dict[str, Any]) -> dict[str, Any]:
    username = data.get("username")
    if not isinstance(username, str):
        raise ValueError("missing 'username'")
    rec = _read().get(username)
    if rec is None:
        raise ValueError("not found")
    return {"user": {"username": username, **rec}}


@action("users.create")
def users_create(data: dict[str, Any]) -> dict[str, Any]:
    username = data.get("username")
    password_hash = data.get("hash")
    role = data.get("role", "readonly")
    if not isinstance(username, str) or not username:
        raise ValueError("invalid username")
    if not isinstance(password_hash, str) or not password_hash.startswith("$2"):
        raise ValueError("hash must be bcrypt")
    if role not in ROLES:
        return {"ok": False, "error": f"role must be one of {sorted(ROLES)}"}

    users = _read()
    if username in users:
        raise ValueError("user already exists")
    users[username] = {
        "hash": password_hash,
        "role": role,
        "created": int(time.time()),
        "disabled": False,
    }
    _write(users)
    return {"username": username}


@action("users.delete")
def users_delete(data: dict[str, Any]) -> dict[str, Any]:
    username = data.get("username")
    if not isinstance(username, str):
        raise ValueError("missing 'username'")
    users = _read()
    if username not in users:
        raise ValueError("not found")
    del users[username]
    _write(users)
    return {"username": username}


@action("users.set_password")
def users_set_password(data: dict[str, Any]) -> dict[str, Any]:
    username = data.get("username")
    password_hash = data.get("hash")
    if not isinstance(username, str) or not isinstance(password_hash, str):
        raise ValueError("missing username or hash")
    if not password_hash.startswith("$2"):
        raise ValueError("hash must be bcrypt")
    users = _read()
    if username not in users:
        raise ValueError("not found")
    users[username]["hash"] = password_hash
    _write(users)
    return {"username": username}


@action("users.set_role")
def users_set_role(data: dict[str, Any]) -> dict[str, Any]:
    username = data.get("username")
    role = data.get("role")
    if not isinstance(username, str) or role not in ROLES:
        raise ValueError("invalid username or role")
    users = _read()
    if username not in users:
        raise ValueError("not found")
    users[username]["role"] = role
    _write(users)
    return {"username": username, "role": role}


@action("users.set_disabled")
def users_set_disabled(data: dict[str, Any]) -> dict[str, Any]:
    username = data.get("username")
    disabled = bool(data.get("disabled", False))
    if not isinstance(username, str):
        raise ValueError("missing username")
    users = _read()
    if username not in users:
        raise ValueError("not found")
    users[username]["disabled"] = disabled
    _write(users)
    return {"username": username, "disabled": disabled}

# =============================================================================
# Phase 9.9a — TOTP / 2FA actions
# =============================================================================
import base64
import io
import json as _json
import secrets as _secrets
import time as _time
from pathlib import Path as _Path

try:
    import pyotp as _pyotp
    import qrcode as _qrcode
except ImportError as _e:
    # Let the action fail cleanly if the venv is missing these
    _pyotp = None
    _qrcode = None


def _totp_ready():
    if _pyotp is None or _qrcode is None:
        raise RuntimeError("pyotp/qrcode not installed in configd venv")


def _bcrypt_hash(password: str) -> str:
    import bcrypt
    return bcrypt.hashpw(password.encode("utf-8"),
                         bcrypt.gensalt(rounds=12)).decode("utf-8")


def _bcrypt_verify(password: str, hashed: str) -> bool:
    import bcrypt
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def _gen_recovery_codes(n: int = 10) -> list[str]:
    """Return n human-typable one-time codes, format XXXXXXXXXX (base32)."""
    import base64 as _b64
    out = []
    while len(out) < n:
        raw = _secrets.token_bytes(7)
        code = _b64.b32encode(raw).decode("ascii").rstrip("=")
        code = code[:10]
        # format as XXXXX-XXXXX for readability
        out.append(code[:5] + "-" + code[5:])
    return out


@action("users.totp.status")
def users_totp_status(data):
    """Return the TOTP status of a user (no secrets)."""
    username = data.get("username")
    if not isinstance(username, str):
        raise ValueError("missing username")
    rec = _read().get(username)
    if rec is None:
        raise ValueError("user not found")
    return {
        "username": username,
        "enabled": bool(rec.get("totp_enabled", False)),
        "required": bool(rec.get("totp_required", False)),
        "has_pending": bool(rec.get("totp_pending_secret")),
        "recovery_remaining": len(rec.get("totp_recovery_hashes") or []),
    }


@action("users.totp.setup")
def users_totp_setup(data):
    """Begin 2FA enrollment. Generates a fresh secret, returns QR + URI."""
    _totp_ready()
    username = data.get("username")
    if not isinstance(username, str):
        raise ValueError("missing username")
    users = _read()
    rec = users.get(username)
    if rec is None:
        raise ValueError("user not found")
    if rec.get("totp_enabled"):
        raise ValueError("2FA is already enabled for this user")

    # Idempotent: reuse the existing pending secret if one is stored.
    # Otherwise a page refresh would generate a new secret and invalidate
    # the user's authenticator entry mid-enrollment.
    secret = rec.get("totp_pending_secret")
    if not secret:
        secret = _pyotp.random_base32()
        rec["totp_pending_secret"] = secret
        users[username] = rec
        _write(users)

    totp = _pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name="NFW Firewall")

    # Generate the QR PNG and base64-encode it
    img = _qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")

    return {
        "username": username,
        "secret": secret,
        "uri": uri,
        "qr_png_b64": b64,
    }


@action("users.totp.enable")
def users_totp_enable(data):
    """Verify the code against the pending secret, then finalize enrollment."""
    _totp_ready()
    username = data.get("username")
    code = data.get("code", "")
    if not isinstance(username, str) or not isinstance(code, str):
        raise ValueError("missing username or code")
    code = code.strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        raise ValueError("code must be 6 digits")

    users = _read()
    rec = users.get(username)
    if rec is None:
        raise ValueError("user not found")
    pending = rec.get("totp_pending_secret")
    if not pending:
        raise ValueError("no enrollment in progress; start with /setup")

    totp = _pyotp.TOTP(pending)
    if not totp.verify(code, valid_window=1):
        raise ValueError("invalid code")

    # Move pending → enabled
    rec["totp_secret"] = pending
    rec.pop("totp_pending_secret", None)
    rec["totp_enabled"] = True

    # Generate recovery codes
    codes = _gen_recovery_codes(10)
    rec["totp_recovery_hashes"] = [_bcrypt_hash(c) for c in codes]
    users[username] = rec
    _write(users)

    return {
        "username": username,
        "enabled": True,
        "recovery_codes": codes,
    }


@action("users.totp.cancel")
def users_totp_cancel(data):
    """Abort a pending 2FA enrollment. Clears totp_pending_secret.

    Refuses if 2FA is already enabled — use users.totp.disable instead.
    """
    username = data.get("username")
    if not isinstance(username, str):
        raise ValueError("missing username")
    users = _read()
    rec = users.get(username)
    if rec is None:
        raise ValueError("user not found")
    if rec.get("totp_enabled"):
        raise ValueError("2FA is already enabled — use disable instead")
    rec.pop("totp_pending_secret", None)
    users[username] = rec
    _write(users)
    return {"username": username, "cancelled": True}


@action("users.totp.disable")
def users_totp_disable(data):
    """Disable 2FA for a user. Self-service (with password) or admin-forced."""
    username = data.get("username")
    if not isinstance(username, str):
        raise ValueError("missing username")
    users = _read()
    rec = users.get(username)
    if rec is None:
        raise ValueError("user not found")
    rec.pop("totp_secret", None)
    rec.pop("totp_pending_secret", None)
    rec.pop("totp_recovery_hashes", None)
    rec["totp_enabled"] = False
    users[username] = rec
    _write(users)
    return {"username": username, "enabled": False}


@action("users.totp.require")
def users_totp_require(data):
    """Admin toggles whether this user must have 2FA enabled."""
    username = data.get("username")
    required = bool(data.get("required", True))
    if not isinstance(username, str):
        raise ValueError("missing username")
    users = _read()
    rec = users.get(username)
    if rec is None:
        raise ValueError("user not found")
    rec["totp_required"] = required
    users[username] = rec
    _write(users)
    return {"username": username, "required": required}


@action("users.totp.recovery_regen")
def users_totp_recovery_regen(data):
    """Regenerate recovery codes. Returns the plaintext codes once."""
    username = data.get("username")
    if not isinstance(username, str):
        raise ValueError("missing username")
    users = _read()
    rec = users.get(username)
    if rec is None:
        raise ValueError("user not found")
    if not rec.get("totp_enabled"):
        raise ValueError("2FA is not enabled for this user")
    codes = _gen_recovery_codes(10)
    rec["totp_recovery_hashes"] = [_bcrypt_hash(c) for c in codes]
    users[username] = rec
    _write(users)
    return {"username": username, "recovery_codes": codes}


@action("users.totp.verify_for_login")
def users_totp_verify_for_login(data):
    """Verify a TOTP code (or recovery code) during login.
    Called by the API auth flow, not exposed to the browser directly."""
    _totp_ready()
    username = data.get("username")
    code = data.get("code", "")
    if not isinstance(username, str) or not isinstance(code, str):
        raise ValueError("missing username or code")
    code = code.strip().replace(" ", "").upper()

    users = _read()
    rec = users.get(username)
    if rec is None:
        raise ValueError("user not found")
    if not rec.get("totp_enabled"):
        # No 2FA required — nothing to verify
        return {"valid": True, "method": "none"}

    # Try TOTP first (6 digits)
    if code.isdigit() and len(code) == 6:
        secret = rec.get("totp_secret")
        if secret and _pyotp.TOTP(secret).verify(code, valid_window=1):
            return {"valid": True, "method": "totp"}

    # Try recovery code (has a dash and is base32-ish)
    if "-" in code or len(code) >= 8:
        candidates = rec.get("totp_recovery_hashes") or []
        for i, h in enumerate(candidates):
            if _bcrypt_verify(code, h):
                # Burn this code
                remaining = [x for j, x in enumerate(candidates) if j != i]
                rec["totp_recovery_hashes"] = remaining
                users[username] = rec
                _write(users)
                return {"valid": True, "method": "recovery",
                        "recovery_remaining": len(remaining)}

    return {"valid": False, "method": "totp"}

