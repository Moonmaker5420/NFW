"""Generic OIDC + OAuth2 authentication (Phase 9.9c).

Supports:
    - type "oidc"    — anything with a /.well-known/openid-configuration
    - type "google"  — Google OAuth2/OIDC
    - type "github"  — GitHub OAuth2 (no OIDC discovery; fixed URLs)

Discovery results are cached in-memory with a TTL.
"""
from __future__ import annotations
import logging
import time
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt

LOG = logging.getLogger("auth.oauth")

_DISCOVERY_CACHE: dict[str, tuple[float, dict]] = {}
_DISCOVERY_TTL = 600.0

_GOOGLE_ISSUER = "https://accounts.google.com"
_GITHUB_AUTH = "https://github.com/login/oauth/authorize"
_GITHUB_TOKEN = "https://github.com/login/oauth/access_token"
_GITHUB_API = "https://api.github.com"


def _get_discovery(issuer: str) -> dict:
    now = time.time()
    cached = _DISCOVERY_CACHE.get(issuer)
    if cached and now - cached[0] < _DISCOVERY_TTL:
        return cached[1]
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    with httpx.Client(timeout=10.0) as c:
        r = c.get(url)
        r.raise_for_status()
        cfg = r.json()
    _DISCOVERY_CACHE[issuer] = (now, cfg)
    return cfg


def _effective_provider(p: dict) -> dict:
    """Normalize google/github into a set of endpoints we can drive."""
    typ = p.get("type", "oidc")
    issuer = (p.get("issuer") or "").rstrip("/")

    if typ == "github":
        return {
            "authorization_endpoint": _GITHUB_AUTH,
            "token_endpoint": _GITHUB_TOKEN,
            "userinfo_endpoint": _GITHUB_API + "/user",
            "kind": "github",
            "issuer": issuer or _GITHUB_AUTH,
            "jwks_uri": None,
        }
    if typ == "google":
        d = _get_discovery(issuer or _GOOGLE_ISSUER)
        d["kind"] = "oidc"
        return d
    # generic oidc
    d = _get_discovery(issuer)
    d["kind"] = "oidc"
    return d


def authorization_url(provider: dict, redirect_uri: str,
                      state: str) -> str:
    ep = _effective_provider(provider)
    scopes = provider.get("scopes") or ("openid email profile"
                                        if ep["kind"] == "oidc"
                                        else "read:user user:email")
    params = {
        "client_id": provider["client_id"],
        "redirect_uri": redirect_uri,
        "scope": scopes,
        "state": state,
        "response_type": "code",
    }
    if ep["kind"] == "oidc":
        params["response_mode"] = "query"
    url = ep["authorization_endpoint"]
    return url + ("&" if "?" in url else "?") + urlencode(params)


async def exchange_code(provider: dict, code: str,
                        redirect_uri: str) -> dict:
    ep = _effective_provider(provider)
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": provider["client_id"],
        "client_secret": provider.get("client_secret", ""),
    }
    headers = {"Accept": "application/json"}
    async with httpx.AsyncClient(timeout=15.0) as c:
        r = await c.post(ep["token_endpoint"], data=data, headers=headers)
        if r.status_code >= 400:
            raise RuntimeError(f"token exchange failed: {r.status_code} {r.text[:200]}")
        tok = r.json()

    if ep["kind"] == "github":
        # GitHub returns access_token + scope; fetch the user
        access = tok.get("access_token")
        if not access:
            raise RuntimeError("no access_token from GitHub")
        async with httpx.AsyncClient(timeout=15.0) as c:
            u = await c.get(ep["userinfo_endpoint"],
                            headers={"Authorization": f"Bearer {access}",
                                     "Accept": "application/vnd.github+json"})
            u.raise_for_status()
            claims = u.json()
            # fetch emails if not public
            if not claims.get("email"):
                e = await c.get(_GITHUB_API + "/user/emails",
                                headers={"Authorization": f"Bearer {access}",
                                         "Accept": "application/vnd.github+json"})
                if e.status_code == 200:
                    for e0 in e.json():
                        if e0.get("primary"):
                            claims["email"] = e0.get("email")
                            break
        return {"claims": claims, "token": tok}

    # OIDC: verify the id_token
    idt = tok.get("id_token")
    if not idt:
        raise RuntimeError("no id_token in token response")
    jwks_uri = ep.get("jwks_uri")
    jwks = None
    if jwks_uri:
        async with httpx.AsyncClient(timeout=15.0) as c:
            j = await c.get(jwks_uri)
            j.raise_for_status()
            jwks = jwt.PyJWKSet.from_dict(j.json())
    unverified = jwt.decode(idt, options={"verify_signature": False,
                                          "verify_aud": False})
    kwargs = {"audience": provider["client_id"],
              "issuer": unverified.get("iss"),
              "options": {"verify_aud": True}}
    if jwks is not None:
        key = None
        kid = jwt.get_unverified_header(idt).get("kid")
        for k in jwks.keys:
            if kid is None or k.key_id == kid:
                key = k
                break
        if key is None:
            key = jwks.keys[0]
        claims = jwt.decode(idt, key=key, algorithms=["RS256", "ES256", "HS256"], **kwargs)
    else:
        claims = unverified
    return {"claims": claims, "token": tok}


def role_from_claims(provider: dict, claims: dict) -> str:
    """Map claims → role based on provider.claim_role_map and role_claim."""
    default = provider.get("default_role", "readonly")
    role_claim = provider.get("role_claim", "")
    mapping = provider.get("claim_role_map") or {}
    rank = {"readonly": 1, "operator": 2, "admin": 3}

    def highest(r1, r2):
        if r1 is None:
            return r2
        if r2 is None:
            return r1
        return r1 if rank.get(r1, 0) >= rank.get(r2, 0) else r2

    best = None
    if role_claim:
        vals = claims.get(role_claim)
        if isinstance(vals, str):
            vals = [vals]
        if not isinstance(vals, list):
            vals = [vals] if vals else []
        for v in vals:
            r = mapping.get(str(v))
            if r:
                best = highest(best, r)
    # also look at common claims
    for k in ("groups", "roles", "role", "email"):
        vals = claims.get(k)
        if isinstance(vals, str):
            vals = [vals]
        if not isinstance(vals, list):
            continue
        for v in vals:
            r = mapping.get(str(v))
            if r:
                best = highest(best, r)
    return best or (default if default in rank else "readonly")


def identify(provider: dict, claims: dict) -> str:
    """Return the local username for these claims. Prefer email, then sub."""
    for k in ("email", "preferred_username", "login", "sub"):
        v = claims.get(k)
        if v:
            return str(v)
    raise RuntimeError("cannot identify user from claims")
