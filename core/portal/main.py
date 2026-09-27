"""NFW Captive Portal — serves the login page and CPD endpoints on :8081.

Architecture note: this app has NO concept of authenticated sessions. The
grant is entirely IP-based — an authenticated client's source IP is added
to the `cp_authenticated_v4` nftables set by configd, and the firewall
stops redirecting their traffic. This app just answers the requests that
land here *before* that happens.
"""
from __future__ import annotations

import html
import json
import logging
import os
import sqlite3
import sys
import time
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

sys.path.insert(0, "/opt/nfw")
sys.path.insert(0, "/opt/nfw/core")

from api.configd_client import ConfigdError, call as configd_call  # noqa: E402
from portal import cpd as cpd_routes  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s portal: %(message)s",
)
LOG = logging.getLogger("portal")

CP_DIR = Path("/var/lib/nfw/captiveportal")
CONF_JSON = CP_DIR / "portal.json"
DB_PATH = CP_DIR / "sessions.db"
TEMPLATE_DIR = Path("/opt/nfw/web/templates")
STATIC_DIR = Path("/opt/nfw/web/static")

# ---------------------------------------------------------------------------
# Custom template support (Phase 9.18b4)
# ---------------------------------------------------------------------------
sys.path.insert(0, "/opt/nfw")
sys.path.insert(0, "/opt/nfw/core")
try:
    from modules.services import captiveportal as _cpmod
except Exception:
    _cpmod = None


def _load_custom_template(tid: str):
    if not tid or _cpmod is None:
        return None
    try:
        t = _cpmod.get_template(tid)
    except Exception:
        return None
    if not t:
        return None
    root = _cpmod._tpl_dir(tid)
    login = root / "login.html"
    if not login.exists():
        return None
    try:
        return login.read_text()
    except OSError:
        return None


def _template_vars(cfg: dict, *, error: str = "", next_url: str = "") -> dict:
    mode = _auth_mode(cfg)
    return {
        "gateway_name":      str(cfg.get("gateway_name") or "NFW Captive Portal"),
        "welcome_text":      str((cfg.get("branding") or {}).get("welcome_text") or ""),
        "primary_color":     str((cfg.get("branding") or {}).get("primary_color") or "#58a6ff"),
        "logo_url":          str((cfg.get("branding") or {}).get("logo_url") or ""),
        "error":             str(error or ""),
        "next_url":          str(next_url or ""),
        "portal_url":        _portal_url(cfg),
        "auth_mode":         mode,
        "tos_required":      "yes" if cfg.get("tos_required") else "no",
        "tos_text":          str(cfg.get("tos_text") or ""),
        "splash_label":      str(cfg.get("splash_label") or "Connect"),
        "splash_extra_text": str(cfg.get("splash_extra_text") or ""),
        "show_password_form": "yes" if mode in ("multi", "credentials") else "no",
        "show_voucher_form":  "yes" if mode in ("multi", "voucher") else "no",
    }


def _maybe_custom(cfg: dict, *, error: str = "", next_url: str = "",
                  status_code: int = 200):
    """Return custom HTMLResponse if template_id set + valid, else None."""
    tid = str(cfg.get("template_id") or "").strip()
    if not tid:
        return None
    html = _load_custom_template(tid)
    if html is None:
        return None
    try:
        rendered = _cpmod.substitute_template_vars(
            html, _template_vars(cfg, error=error, next_url=next_url))
    except Exception as e:
        LOG.warning("custom template render failed: %s", e)
        return None
    return HTMLResponse(content=rendered, status_code=status_code)


app = FastAPI(title="NFW Captive Portal", docs_url=None, redoc_url=None)
app.include_router(cpd_routes.router)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _auth_mode(cfg: dict) -> str:
    """Return one of: splash, credentials, voucher, multi."""
    m = (cfg.get("auth_mode") or "multi").lower()
    if m not in ("splash", "credentials", "voucher", "multi"):
        return "multi"
    return m


def _login_ctx(cfg: dict, *, next_url: str = "", error: str = "") -> dict:
    """Build template context for portal/login.html.

    Used by every handler that renders the login page. Keeping this in
    one place prevents handlers from forgetting auth_mode / active_tab
    and silently rendering the wrong tabs (or none at all).
    """
    mode = _auth_mode(cfg)
    return {
        "cfg": cfg,
        "next": next_url,
        "error": error,
        "active_tab": "voucher" if mode == "voucher" else "password",
        "auth_mode": mode,
    }


def _load_config() -> dict:
    try:
        return json.loads(CONF_JSON.read_text())
    except Exception as e:
        LOG.warning("cannot read portal.json: %s", e)
        return {
            "gateway_name": "NFW Captive Portal",
            "listen_ip": "192.168.10.1",
            "portal_port": 8081,
            "session_timeout": 3600,
            "auth_backends": ["local"],
            "tos_required": False,
            "tos_text": "",
            "branding": {
                "primary_color": "#58a6ff",
                "welcome_text": "Welcome. Please sign in.",
            },
        }


def _client_ip(request: Request) -> str:
    """Return the real client IP (nft redirect preserves source)."""
    return (request.client.host if request.client else "") or ""


def _is_authenticated(ip: str) -> dict | None:
    """Return session dict if this IP has an active session in the DB."""
    if not ip:
        return None
    try:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM sessions "
            "WHERE ip = ? AND revoked_at IS NULL AND expires_at > ?",
            (ip, int(time.time())),
        ).fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception as e:
        LOG.warning("DB read failed: %s", e)
        return None


def _portal_url(cfg: dict) -> str:
    """Absolute URL of our own portal root."""
    ip = cfg.get("listen_ip") or "192.168.10.1"
    port = int(cfg.get("portal_port", 8081))
    return f"http://{ip}:{port}"


# ---------------------------------------------------------------------------
# Root + login
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    cfg = _load_config()
    ip = _client_ip(request)
    mode = _auth_mode(cfg)

    # Active session already? → status page
    sess = _is_authenticated(ip)
    if sess:
        return RedirectResponse(f"{_portal_url(cfg)}/status", status_code=302)

    # Welcome-back opportunity? Reactivate transparently.
    if mode != "splash":
        try:
            wb = await configd_call("captiveportal.welcome_back_reactivate", {
                "ip": ip, "mac": "",
                "user_agent": request.headers.get("user-agent", ""),
            })
        except Exception as e:
            LOG.warning("welcome-back check failed: %s", e)
            wb = {}
        if isinstance(wb, dict) and wb.get("ok"):
            LOG.info("welcome-back OK ip=%s user=%s",
                     ip, wb.get("username"))
            return RedirectResponse(f"{_portal_url(cfg)}/status", status_code=302)

    custom = _maybe_custom(cfg, error="", next_url="")
    if custom is not None:
        return custom
    return templates.TemplateResponse(
        request,
        "portal/login.html",
        _login_ctx(cfg, next_url="", error=""),
    )


@app.post("/splash", response_class=HTMLResponse)
async def splash_submit(request: Request,
                        next_url: str = Form("", alias="next"),
                        accept_tos: str = Form("")):
    """Splash-only flow: no credentials, just TOS acceptance."""
    cfg = _load_config()
    ip = _client_ip(request)
    ua = request.headers.get("user-agent", "")

    if cfg.get("tos_required") and not accept_tos:
        custom = _maybe_custom(cfg,
                                error="You must accept the terms of service.",
                                next_url=next_url)
        if custom is not None:
            return custom
        return templates.TemplateResponse(
            request, "portal/login.html",
            {"cfg": cfg, "next": next_url, "auth_mode": "splash",
             "active_tab": "password",
             "error": "You must accept the terms of service."},
            status_code=200,
        )
    try:
        r = await configd_call("captiveportal.splash_authorize",
                                {"ip": ip, "mac": "", "user_agent": ua})
    except ConfigdError as e:
        LOG.error("configd error on splash authorize: %s", e)
        return templates.TemplateResponse(
            request, "portal/login.html",
            {"cfg": cfg, "next": next_url, "auth_mode": "splash",
             "active_tab": "password",
             "error": "Authentication service unavailable."},
            status_code=503,
        )
    if not r.get("ok"):
        return templates.TemplateResponse(
            request, "portal/login.html",
            {"cfg": cfg, "next": next_url, "auth_mode": "splash",
             "active_tab": "password",
             "error": r.get("error", "Could not authorize.")},
            status_code=200,
        )
    target = next_url.strip() or "/status"
    if not (target.startswith("/") or target.startswith(_portal_url(cfg))):
        target = "/status"
    LOG.info("splash authorize OK ip=%s", ip)
    return RedirectResponse(target, status_code=302)


@app.post("/login", response_class=HTMLResponse)
async def login(request: Request,
                username: str = Form(""),
                password: str = Form(""),
                voucher_code: str = Form(""),
                auth_method: str = Form("password"),
                next_url: str = Form("", alias="next"),
                accept_tos: str = Form("")):
    cfg = _load_config()
    ip = _client_ip(request)
    ua = request.headers.get("user-agent", "")
    active_tab = "voucher" if auth_method == "voucher" else "password"
    _mode = _auth_mode(cfg)

    def _err(msg: str, code: int = 200):
        custom = _maybe_custom(cfg, error=msg, next_url=next_url,
                                status_code=code)
        if custom is not None:
            return custom
        return templates.TemplateResponse(
            request, "portal/login.html",
            {"cfg": cfg, "next": next_url, "error": msg,
             "active_tab": active_tab, "auth_mode": _mode},
            status_code=code,
        )

    if cfg.get("tos_required") and not accept_tos:
        return _err("You must accept the terms of service.")

    if auth_method == "voucher":
        voucher_code = (voucher_code or "").strip().upper()
        if not voucher_code:
            return _err("Voucher code required.")
        try:
            result = await configd_call("captiveportal.vouchers.redeem", {
                "code": voucher_code,
                "ip": ip,
                "mac": "",
                "user_agent": ua,
            })
        except ConfigdError as e:
            LOG.error("configd error on voucher redeem: %s", e)
            return _err("Authentication service unavailable.", 503)
        if not result.get("ok"):
            return _err("Invalid, used, or expired voucher.")
        target = next_url.strip() or "/status"
        if not (target.startswith("/") or target.startswith(_portal_url(cfg))):
            target = "/status"
        LOG.info("voucher redeem OK ip=%s code=%s", ip, voucher_code)
        return RedirectResponse(target, status_code=302)

    # Password path
    if not username or not password:
        return _err("Username and password required.")
    try:
        result = await configd_call("captiveportal.authenticate", {
            "username": username,
            "password": password,
            "ip": ip,
            "mac": "",
            "user_agent": ua,
        })
    except ConfigdError as e:
        LOG.error("configd error on auth: %s", e)
        return _err("Authentication service unavailable.", 503)

    if not result.get("ok"):
        return _err("Invalid username or password.")

    target = next_url.strip() or "/status"
    if not (target.startswith("/") or target.startswith(_portal_url(cfg))):
        target = "/status"
    LOG.info("login OK ip=%s user=%s backend=%s",
             ip, username, result.get("auth_backend"))
    return RedirectResponse(target, status_code=302)


@app.get("/status", response_class=HTMLResponse)
async def status_page(request: Request):
    cfg = _load_config()
    ip = _client_ip(request)
    sess = _is_authenticated(ip)
    if not sess:
        return RedirectResponse(f"{_portal_url(cfg)}/", status_code=302)
    remaining = max(0, int(sess["expires_at"]) - int(time.time()))
    hard_remaining = None
    if sess.get("hard_expires_at"):
        hard_remaining = max(0, int(sess["hard_expires_at"]) - int(time.time()))
    return templates.TemplateResponse(
        request,
        "portal/status.html",
        {"cfg": cfg, "session": sess,
         "remaining": remaining, "hard_remaining": hard_remaining},
    )


@app.post("/logout")
async def logout_post(request: Request):
    ip = _client_ip(request)
    try:
        await configd_call("captiveportal.logout", {"ip": ip})
    except ConfigdError as e:
        LOG.warning("logout failed: %s", e)
    cfg = _load_config()
    return RedirectResponse(f"{_portal_url(cfg)}/", status_code=302)


@app.get("/logout")
async def logout_get(request: Request):
    return await logout_post(request)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@app.get("/healthz")
async def healthz():
    return {"ok": True, "service": "nfw-portal", "ts": int(time.time())}


# ---------------------------------------------------------------------------
# Catch-all: any unhandled path (unauth client hitting any URL) -> login page
# ---------------------------------------------------------------------------
@app.get("/portal/template/{tid}/{path:path}")
async def custom_template_asset(tid: str, path: str):
    """Serve static assets bundled with a custom portal template."""
    if _cpmod is None:
        return Response(status_code=404)
    f = _cpmod.read_template_file(tid, path)
    if not f:
        return Response(status_code=404)
    ext = Path(path).suffix.lower()
    media_types = {
        ".html": "text/html; charset=utf-8",
        ".htm":  "text/html; charset=utf-8",
        ".css":  "text/css; charset=utf-8",
        ".js":   "application/javascript",
        ".json": "application/json",
        ".svg":  "image/svg+xml",
        ".png":  "image/png",
        ".jpg":  "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif":  "image/gif",
        ".ico":  "image/x-icon",
        ".woff": "font/woff",
        ".woff2": "font/woff2",
        ".ttf":  "font/ttf",
        ".otf":  "font/otf",
        ".txt":  "text/plain; charset=utf-8",
        ".md":   "text/markdown; charset=utf-8",
    }
    mt = media_types.get(ext, "application/octet-stream")
    if f.get("is_text"):
        return Response(content=f["content"].encode("utf-8"), media_type=mt)
    root = _cpmod._tpl_dir(tid)
    sp = _cpmod._safe_rel_path(path)
    if not sp:
        return Response(status_code=404)
    try:
        data = (root / sp).read_bytes()
    except OSError:
        return Response(status_code=404)
    return Response(content=data, media_type=mt)


# ---------------------------------------------------------------------------
# RFC 8908 — Captive Portal API
# https://datatracker.ietf.org/doc/html/rfc8908
# ---------------------------------------------------------------------------
@app.get("/api/captiveportal/access/api")
async def rfc8908_status(request: Request):
    """Standard captive-portal probe. Returns:
       {
         "captive": true|false,
         "user-portal-url": "https://...",
         "venue-info-url": "",
         "can-extend-session": false,
         "seconds-remaining": <int or null>
       }
    """
    cfg = _load_config()
    ip = _client_ip(request)
    sess = _is_authenticated(ip)
    portal_url = _portal_url(cfg)

    if sess:
        secs = max(0, int(sess["expires_at"]) - int(time.time()))
        return JSONResponse({
            "captive": False,
            "user-portal-url": portal_url,
            "venue-info-url": "",
            "can-extend-session": False,
            "seconds-remaining": secs,
        })
    return JSONResponse({
        "captive": True,
        "user-portal-url": portal_url,
        "venue-info-url": "",
        "can-extend-session": False,
        "seconds-remaining": None,
    })


@app.get("/{full_path:path}", response_class=HTMLResponse)
async def catch_all(request: Request, full_path: str):
    cfg = _load_config()
    ip = _client_ip(request)
    if _is_authenticated(ip):
        # Auth'd client is hitting a non-portal URL somehow — send them
        # back to their original intent by redirecting to the URL root.
        return RedirectResponse(f"http://{full_path}", status_code=302)
    # Not auth'd — serve the login page, carrying the original host+path as next
    host = request.headers.get("host", "")
    next_url = f"http://{host}/{full_path}" if host else f"/{full_path}"
    return templates.TemplateResponse(
        request,
        "portal/login.html",
        _login_ctx(cfg, next_url=next_url, error=""),
    )
