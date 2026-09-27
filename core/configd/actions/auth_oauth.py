"""OAuth provider config + callback exchange (Phase 9.9c)."""
from __future__ import annotations
import logging
import sys
from typing import Any

from configd.registry import action

sys.path.insert(0, "/opt/nfw")
sys.path.insert(0, "/opt/nfw/core")

from config import store as cfg_store
from config.schema import validate

LOG = logging.getLogger("configd.oauth")
_MASK = "********"


def _active_config() -> dict:
    return cfg_store.read()


def _oauth(cfg: dict) -> dict:
    return cfg.setdefault("auth", {}).setdefault("oauth", {"enabled": False, "providers": []})


def _mask(s: str) -> str:
    return _MASK if s else ""


def _unmask(new: str, old: str) -> str:
    if new == _MASK:
        return old
    return new or ""


@action("auth.oauth.get")
def oauth_get(_data):
    cfg = _active_config()
    o = _oauth(cfg)
    provs = []
    for p in o.get("providers", []) or []:
        p2 = dict(p)
        p2["client_secret"] = _mask(p2.get("client_secret", ""))
        provs.append(p2)
    return {"enabled": bool(o.get("enabled", False)), "providers": provs}


@action("auth.oauth.set")
def oauth_set(data):
    o = data.get("oauth") or {}
    if not isinstance(o, dict):
        raise ValueError("missing oauth")
    cfg = _active_config()
    cur = _oauth(cfg)
    # preserve secret if masked
    old_by_id = {p.get("id"): p for p in cur.get("providers", []) or []}
    new_provs = []
    for p in o.get("providers", []) or []:
        if not isinstance(p, dict) or not p.get("id"):
            continue
        p2 = dict(p)
        old = old_by_id.get(p2["id"]) or {}
        p2["client_secret"] = _unmask(p2.get("client_secret", ""),
                                      old.get("client_secret", ""))
        new_provs.append(p2)
    cur["enabled"] = bool(o.get("enabled", False))
    cur["providers"] = new_provs
    cfg["auth"]["oauth"] = cur
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"staged": True}


@action("auth.oauth.list_enabled")
def oauth_list_enabled(_data):
    """Public-ish: used by the login page to draw provider buttons."""
    cfg = _active_config()
    o = _oauth(cfg)
    if not o.get("enabled", False):
        return {"providers": []}
    out = []
    for p in o.get("providers", []) or []:
        if not p.get("enabled", True):
            continue
        out.append({"id": p.get("id"), "name": p.get("name", p.get("id"))})
    return {"providers": out}


@action("auth.oauth.get_provider")
def oauth_get_provider(data):
    """Return the raw provider config for an exchange (server-side only)."""
    pid = data.get("id")
    cfg = _active_config()
    for p in _oauth(cfg).get("providers", []) or []:
        if p.get("id") == pid:
            return {"provider": p}
    raise FileNotFoundError(f"provider {pid} not found")


@action("auth.oauth.exchange")
def oauth_exchange(data):
    """Do the token exchange + claim extraction. Returns claims + role."""
    import asyncio
    from modules.auth.oauth_auth import (
        exchange_code, identify, role_from_claims,
    )

    pid = data.get("id")
    code = data.get("code")
    redirect_uri = data.get("redirect_uri")
    if not pid or not code or not redirect_uri:
        raise ValueError("missing id, code, or redirect_uri")

    cfg = _active_config()
    provider = None
    for p in _oauth(cfg).get("providers", []) or []:
        if p.get("id") == pid:
            provider = p
            break
    if provider is None:
        raise FileNotFoundError(f"provider {pid} not found")
    if not provider.get("enabled", True):
        raise ValueError(f"provider {pid} is disabled")

    result = asyncio.run(exchange_code(provider, code, redirect_uri))
    claims = result.get("claims") or {}

    username = identify(provider, claims)
    role = role_from_claims(provider, claims)

    if provider.get("auto_create", True):
        _ensure_local(username, role)

    return {
        "username": username,
        "role": role,
        "provider": pid,
        "claims_subset": {k: claims.get(k) for k in
                          ("email", "name", "preferred_username", "sub",
                           "groups", "roles", "login") if k in claims},
    }


def _ensure_local(username: str, role: str) -> None:
    import json, os, time
    from pathlib import Path
    p = Path("/etc/nfw/users.json")
    try:
        users = json.load(open(p)) if p.exists() else {}
    except Exception:
        users = {}
    rec = users.get(username)
    if rec is None:
        users[username] = {
            "hash": "", "role": role, "created": int(time.time()),
            "disabled": False, "external": True, "external_type": "oauth",
        }
    elif not rec.get("role_locked"):
        rec["role"] = role
        users[username] = rec
    tmp = p.with_suffix(".json.tmp")
    with open(tmp, "w") as f:
        json.dump(users, f, indent=2, sort_keys=True)
        f.flush(); os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)
