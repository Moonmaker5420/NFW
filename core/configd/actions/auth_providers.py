"""LDAP + RADIUS configuration and unified authentication (Phase 9.9b)."""
from __future__ import annotations
import logging
import sys
from typing import Any

from configd.registry import action

sys.path.insert(0, "/opt/nfw")
sys.path.insert(0, "/opt/nfw/core")

from config import store as cfg_store
from config.schema import validate

LOG = logging.getLogger("configd.auth")

_MASK = "********"


def _active_config() -> dict:
    """Authentication always reads the ACTIVE config (not staging) —
    half-staged auth changes shouldn't be able to lock you out."""
    return cfg_store.read()


def _auth(cfg: dict) -> dict:
    return cfg.setdefault("auth", {
        "providers": [
            {"type": "local", "enabled": True},
            {"type": "ldap", "enabled": False},
            {"type": "radius", "enabled": False},
        ],
        "ldap": {},
        "radius": {},
    })


def _mask(secret: str) -> str:
    if not secret:
        return ""
    return _MASK


def _unmask(new: str, old: str) -> str:
    """If the client submits the mask, keep the old value."""
    if new == _MASK:
        return old
    return new or ""


# =============================================================================
# Read / write
# =============================================================================
@action("auth.config.get")
def auth_config_get(_data):
    cfg = _active_config()
    a = _auth(cfg)
    ldap = dict(a.get("ldap") or {})
    radius = dict(a.get("radius") or {})
    # mask secrets
    ldap["bind_password"] = _mask(ldap.get("bind_password", ""))
    radius["secret"] = _mask(radius.get("secret", ""))
    return {
        "providers": a.get("providers") or [],
        "ldap": ldap,
        "radius": radius,
    }


@action("auth.config.set")
def auth_config_set(data):
    cfg = _active_config()
    a = _auth(cfg)

    # providers list — clean and store
    if "providers" in data and isinstance(data["providers"], list):
        clean = []
        for p in data["providers"]:
            if not isinstance(p, dict):
                continue
            t = p.get("type")
            if t not in ("local", "ldap", "radius"):
                continue
            clean.append({"type": t, "enabled": bool(p.get("enabled", True))})
        a["providers"] = clean

    # LDAP
    if "ldap" in data and isinstance(data["ldap"], dict):
        old = a.get("ldap") or {}
        new = dict(old)
        for k, v in data["ldap"].items():
            if k == "bind_password":
                new[k] = _unmask(v, old.get(k, ""))
            elif k in ("port", "timeout"):
                try:
                    new[k] = int(v)
                except (TypeError, ValueError):
                    new[k] = old.get(k, 389 if k == "port" else 5)
            elif k in ("use_ssl", "use_starttls", "auto_create", "enabled"):
                new[k] = bool(v)
            else:
                new[k] = v
        a["ldap"] = new

    # RADIUS
    if "radius" in data and isinstance(data["radius"], dict):
        old = a.get("radius") or {}
        new = dict(old)
        for k, v in data["radius"].items():
            if k == "secret":
                new[k] = _unmask(v, old.get(k, ""))
            elif k in ("port", "timeout"):
                try:
                    new[k] = int(v)
                except (TypeError, ValueError):
                    new[k] = old.get(k, 1812 if k == "port" else 5)
            elif k in ("auto_create", "enabled"):
                new[k] = bool(v)
            else:
                new[k] = v
        a["radius"] = new

    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"staged": True}


# =============================================================================
# Test endpoints
# =============================================================================
@action("auth.ldap.test")
def auth_ldap_test(_data):
    from modules.auth.ldap_auth import test_bind
    cfg = _active_config()
    return test_bind(cfg)


@action("auth.radius.test")
def auth_radius_test(_data):
    from modules.auth.radius_auth import test_reachability
    cfg = _active_config()
    return test_reachability(cfg)


# =============================================================================
# The core: authenticate
# =============================================================================
@action("auth.authenticate")
def auth_authenticate(data):
    """Verify a username/password combo against configured providers.
    Returns {ok, username, role, method, totp_enabled, disabled?}.
    """
    import bcrypt

    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return {"ok": False, "reason": "missing credentials"}

    cfg = _active_config()
    a = _auth(cfg)
    providers = a.get("providers") or [{"type": "local", "enabled": True}]

    # ---- Local ----
    local_ok = False
    local_disabled = False
    local_totp = False
    local_role = None
    if any(p.get("type") == "local" and p.get("enabled", True) for p in providers):
        users = _read_users()
        rec = users.get(username)
        if rec:
            if rec.get("disabled"):
                local_disabled = True
            else:
                stored = rec.get("hash") or rec.get("password_hash") or ""
                try:
                    if stored and bcrypt.checkpw(password.encode("utf-8"),
                                                 stored.encode("utf-8")):
                        local_ok = True
                        local_role = rec.get("role", "readonly")
                        local_totp = bool(rec.get("totp_enabled"))
                except Exception as e:
                    LOG.error("bcrypt error for %r: %s", username, e)

    if local_ok:
        return {"ok": True, "username": username, "role": local_role,
                "method": "local", "totp_enabled": local_totp}

    if local_disabled:
        return {"ok": False, "reason": "invalid credentials"}

    # ---- LDAP ----
    ldap_cfg = a.get("ldap") or {}
    if ldap_cfg.get("enabled") and any(p.get("type") == "ldap" and p.get("enabled", True)
                                       for p in providers):
        try:
            from modules.auth.ldap_auth import authenticate as ldap_auth
            r = ldap_auth(cfg, username, password)
            if r.get("ok"):
                role = r.get("role", ldap_cfg.get("default_role", "readonly"))
                _ensure_local_user(cfg, username, role,
                                   auto=bool(ldap_cfg.get("auto_create", True)))
                totp = _local_totp(cfg, username)
                return {"ok": True, "username": username, "role": role,
                        "method": "ldap", "totp_enabled": totp,
                        "user_dn": r.get("user_dn")}
        except Exception as e:
            LOG.exception("ldap auth errored")

    # ---- RADIUS ----
    rad_cfg = a.get("radius") or {}
    if rad_cfg.get("enabled") and any(p.get("type") == "radius" and p.get("enabled", True)
                                      for p in providers):
        try:
            from modules.auth.radius_auth import authenticate as radius_auth
            r = radius_auth(cfg, username, password)
            if r.get("ok"):
                role = r.get("role", rad_cfg.get("default_role", "readonly"))
                _ensure_local_user(cfg, username, role,
                                   auto=bool(rad_cfg.get("auto_create", True)))
                totp = _local_totp(cfg, username)
                return {"ok": True, "username": username, "role": role,
                        "method": "radius", "totp_enabled": totp}
        except Exception as e:
            LOG.exception("radius auth errored")

    return {"ok": False, "reason": "invalid credentials"}


# =============================================================================
# Helpers
# =============================================================================
def _read_users() -> dict:
    import json
    from pathlib import Path
    p = Path("/etc/nfw/users.json")
    if not p.exists():
        return {}
    try:
        return json.load(open(p))
    except Exception:
        return {}


def _write_users(users: dict) -> None:
    import json, os
    from pathlib import Path
    p = Path("/etc/nfw/users.json")
    tmp = p.with_suffix(".json.tmp")
    with open(tmp, "w") as f:
        json.dump(users, f, indent=2, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)


def _ensure_local_user(cfg: dict, username: str, role: str, auto: bool) -> None:
    """Create or update a local user record after successful external auth."""
    users = _read_users()
    rec = users.get(username)
    if rec is None:
        if not auto:
            return
        users[username] = {
            "hash": "",           # no local password
            "role": role,
            "created": int(__import__("time").time()),
            "disabled": False,
            "external": True,
        }
        _write_users(users)
        LOG.info("auto-created local record for external user %r role=%r",
                 username, role)
    elif rec.get("role") != role and not rec.get("role_locked", False):
        rec["role"] = role
        users[username] = rec
        _write_users(users)
        LOG.info("updated role for %r → %r", username, role)


def _local_totp(cfg: dict, username: str) -> bool:
    rec = _read_users().get(username)
    if not rec:
        return False
    return bool(rec.get("totp_enabled"))
