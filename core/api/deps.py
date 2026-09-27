"""FastAPI dependencies — role + ACL gating (Phase 9.9c).

Semantics:
  * ACLs disabled (default): only the role rank is checked.
  * ACLs enabled:  the ACL table is the authority. If no ACL rule
    matches the request, the request is denied — even if the route's
    declared minimum role would have allowed it. This mirrors how
    OPNsense uses its firewall ruleset as the primary gate.

`require_acl(minimum)` is a drop-in for `require_role(minimum)`; routes
should use require_acl everywhere so admins can tune permissions at
runtime without editing code.
"""
from __future__ import annotations

import fnmatch
import time

from fastapi import Depends, HTTPException, Request, status

from .auth import Session, current_user
from .configd_client import ConfigdError, call as _configd_call

ROLE_RANK = {"readonly": 1, "operator": 2, "admin": 3}


# ---------------------------------------------------------------------------
# ACL cache (avoids a configd round-trip per request)
# ---------------------------------------------------------------------------
_ACL_CACHE = {"data": None, "ts": 0.0}
_ACL_TTL = 3.0


async def _load_acl() -> dict:
    now = time.time()
    if _ACL_CACHE["data"] is not None and now - _ACL_CACHE["ts"] < _ACL_TTL:
        return _ACL_CACHE["data"]
    try:
        r = await _configd_call("auth.acl.get", timeout=5.0)
        _ACL_CACHE["data"] = r.get("acls") or {}
    except ConfigdError:
        _ACL_CACHE["data"] = {"enabled": False}
    _ACL_CACHE["ts"] = now
    return _ACL_CACHE["data"]


_RE_CACHE: dict = {}


def _segment_regex(pattern: str):
    import re
    cached = _RE_CACHE.get(pattern)
    if cached is not None:
        return cached
    out = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            if i + 1 < len(pattern) and pattern[i + 1] == "*":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    rx = re.compile("^" + "".join(out) + "$")
    _RE_CACHE[pattern] = rx
    return rx


def _pattern_matches(pattern: str, method: str, path: str) -> bool:
    pattern = (pattern or "").strip()
    if not pattern:
        return False
    if pattern == "*":
        return True
    parts = pattern.split(None, 1)
    if len(parts) == 1:
        head = parts[0]
        if head.isupper() or head == "*":
            return method.upper() == head or head == "*"
        return bool(_segment_regex(head).match(path))
    m, p = parts[0].upper(), parts[1]
    if m != "*" and m != method.upper():
        return False
    return bool(_segment_regex(p).match(path))


async def check_acl(user: Session, method: str, path: str) -> bool:
    a = await _load_acl()
    if not a.get("enabled", False):
        return True
    if path.startswith("/api/health") or path.startswith("/api/auth/whoami"):
        return True
    users = (a.get("users") or {}).get(user.username) or {}
    for p in users.get("deny", []) or []:
        if _pattern_matches(p, method, path):
            return False
    for p in users.get("allow", []) or []:
        if _pattern_matches(p, method, path):
            return True

    role_cfg = (a.get("roles") or {}).get(user.role)
    role_allow, role_deny = [], []
    if isinstance(role_cfg, list):
        role_allow = role_cfg
    elif isinstance(role_cfg, dict):
        role_allow = role_cfg.get("allow") or []
        role_deny = role_cfg.get("deny") or []

    for p in role_deny:
        if _pattern_matches(p, method, path):
            return False
    for p in role_allow:
        if _pattern_matches(p, method, path):
            return True
    return False


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
def require_role(minimum: str):
    """Role-only gate. Kept for compatibility; prefer require_acl."""
    def dep(user: Session = Depends(current_user)) -> Session:
        if ROLE_RANK.get(user.role, 0) < ROLE_RANK.get(minimum, 99):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"requires role '{minimum}'",
            )
        return user
    return dep


def require_acl(minimum: str):
    """Primary authorization dependency.

    If the ACL table is enabled, it is authoritative: only ACL rules
    can grant access. If ACLs are disabled, role rank is used.
    """
    async def dep(request: Request,
                  user: Session = Depends(current_user)) -> Session:
        a = await _load_acl()
        if a.get("enabled", False):
            if await check_acl(user, request.method, request.url.path):
                return user
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="not permitted by ACL",
            )
        # ACLs disabled → fall back to role rank
        if ROLE_RANK.get(user.role, 0) < ROLE_RANK.get(minimum, 99):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"requires role '{minimum}'",
            )
        return user
    return dep
