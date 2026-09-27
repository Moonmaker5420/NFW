"""ACL config + check (Phase 9.9c).

Model:
    roles.<role>.allow  — patterns that grant access
    roles.<role>.deny   — patterns that explicitly revoke (take precedence)
    users.<username>.allow / .deny — per-user overrides

Pattern syntax (segment-aware):
    *   matches one path segment (no slash)
    **  matches any number of path segments (including zero)
    ?   single character (no slash)

Pattern layout:
    METHOD PATH             e.g.  "POST /api/services/*"
    METHOD PATH             with ** for recursive matches, e.g. "POST **/apply"
    '*'                     matches every method + path
    "METHOD"                matches that method on any path
    "PATH"                  matches that path on any method

Evaluation order:
    1. user deny
    2. user allow  (if matched, grants)
    3. role deny   (if matched, denies)
    4. role allow  (if matched, grants)
    5. default deny
"""
from __future__ import annotations

import logging
import re
import sys
from typing import Any

from configd.registry import action

sys.path.insert(0, "/opt/nfw")
sys.path.insert(0, "/opt/nfw/core")

from config import store as cfg_store
from config.schema import validate

LOG = logging.getLogger("configd.acl")


# -----------------------------------------------------------------------------
# Effective config
# -----------------------------------------------------------------------------
def _effective_config() -> dict:
    staged = cfg_store.get_staging()
    return staged if staged is not None else cfg_store.read()


def _active_config() -> dict:
    return cfg_store.read()


def _acl(cfg: dict) -> dict:
    return (cfg.get("auth") or {}).get("acls") or {}


# -----------------------------------------------------------------------------
# Pattern matching
# -----------------------------------------------------------------------------
def _segment_regex(pattern: str) -> re.Pattern:
    """Convert a segment-aware pattern into a regex.

    **  → .*      (any chars, including '/')
    *   → [^/]*   (single segment)
    ?   → [^/]    (single non-slash char)
    Everything else is escaped.
    """
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
    return re.compile("^" + "".join(out) + "$")


_RE_CACHE: dict[str, re.Pattern] = {}


def _match(pattern: str, method: str, path: str) -> bool:
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
        rx = _RE_CACHE.get(head)
        if rx is None:
            rx = _segment_regex(head)
            _RE_CACHE[head] = rx
        return bool(rx.match(path))
    m, p = parts[0].upper(), parts[1]
    if m != "*" and m != method.upper():
        return False
    rx = _RE_CACHE.get(p)
    if rx is None:
        rx = _segment_regex(p)
        _RE_CACHE[p] = rx
    return bool(rx.match(path))


def _check(cfg: dict, username: str, role: str, method: str, path: str) -> bool:
    a = _acl(cfg)
    if not a.get("enabled", False):
        return True
    if path.startswith("/api/health") or path.startswith("/api/auth/whoami"):
        return True

    user_rules = (a.get("users") or {}).get(username) or {}
    if not isinstance(user_rules, dict):
        user_rules = {}

    # 1. user deny
    for p in user_rules.get("deny", []) or []:
        if _match(p, method, path):
            return False
    # 2. user allow short-circuits
    for p in user_rules.get("allow", []) or []:
        if _match(p, method, path):
            return True

    role_cfg = (a.get("roles") or {}).get(role)
    # Accept both list and dict shapes
    role_allow, role_deny = [], []
    if isinstance(role_cfg, list):
        role_allow = role_cfg
    elif isinstance(role_cfg, dict):
        role_allow = role_cfg.get("allow") or []
        role_deny = role_cfg.get("deny") or []

    # 3. role deny
    for p in role_deny:
        if _match(p, method, path):
            return False
    # 4. role allow
    for p in role_allow:
        if _match(p, method, path):
            return True
    return False


# -----------------------------------------------------------------------------
# Actions
# -----------------------------------------------------------------------------
@action("auth.acl.get")
def acl_get(_data):
    cfg = _effective_config()
    a = dict(_acl(cfg))

    def _norm_list(patterns):
        out = []
        for p in patterns or []:
            if not isinstance(p, str):
                continue
            for line in p.splitlines():
                line = line.strip()
                if line:
                    out.append(line)
        return out

    roles_out = {}
    for k, v in (a.get("roles") or {}).items():
        if isinstance(v, list):
            roles_out[k] = {"allow": _norm_list(v), "deny": []}
        elif isinstance(v, dict):
            roles_out[k] = {
                "allow": _norm_list(v.get("allow") or []),
                "deny": _norm_list(v.get("deny") or []),
            }
    a["roles"] = roles_out

    a["users"] = {
        u: {kind: _norm_list(vals) for kind, vals in (rules or {}).items()}
        for u, rules in (a.get("users") or {}).items()
    }
    return {
        "acls": a,
        "source": "staged" if cfg_store.get_staging() is not None else "active",
        "committed_enabled": bool((_acl(_active_config()) or {}).get("enabled", False)),
    }


@action("auth.acl.set")
def acl_set(data):
    acls = data.get("acls")
    if not isinstance(acls, dict):
        raise ValueError("missing acls")

    def _flat(patterns):
        out = []
        for p in patterns or []:
            if not isinstance(p, str):
                continue
            for line in p.splitlines():
                line = line.strip()
                if line:
                    out.append(line)
        return out

    roles_out = {}
    for k, v in (acls.get("roles") or {}).items():
        if isinstance(v, list):
            roles_out[k] = {"allow": _flat(v), "deny": []}
        elif isinstance(v, dict):
            roles_out[k] = {
                "allow": _flat(v.get("allow") or []),
                "deny": _flat(v.get("deny") or []),
            }
    users_out = {
        u: {"allow": _flat((v or {}).get("allow") or []),
            "deny": _flat((v or {}).get("deny") or [])}
        for u, v in (acls.get("users") or {}).items()
        if isinstance(v, dict)
    }
    cfg = _active_config()
    cfg.setdefault("auth", {})["acls"] = {
        "enabled": bool(acls.get("enabled", False)),
        "roles": roles_out,
        "users": users_out,
    }
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"staged": True}


@action("auth.acl.check")
def acl_check(data):
    cfg = _effective_config()
    username = data.get("username") or ""
    role = data.get("role") or ""
    method = data.get("method") or "GET"
    path = data.get("path") or ""
    a = _acl(cfg)
    return {
        "allowed": _check(cfg, username, role, method, path),
        "enabled": bool(a.get("enabled", False)),
        "source": "staged" if cfg_store.get_staging() is not None else "active",
    }
