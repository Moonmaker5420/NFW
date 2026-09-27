"""Captive Portal Detection (CPD) response generators.

On a captive network we must tell the client OS "you are behind a portal"
so it shows the sign-in sheet. Mechanism: return 302 redirect to the
portal login page instead of the expected success content.

If a client IS authenticated, nftables no longer redirects their HTTP
traffic to us — the real CPD URLs are reached directly. So these handlers
mostly see unauthenticated clients (via transparent redirect).

Known connectivity-check URLs from major OSes:
  - Apple iOS/macOS:    http://captive.apple.com/hotspot-detect.html
  - Android:            http://connectivitycheck.gstatic.com/generate_204
  - Windows NCSI:       http://www.msftconnecttest.com/connecttest.txt
  - Windows legacy:     http://www.msftncsi.com/ncsi.txt
  - Firefox:            http://detectportal.firefox.com/success.txt
  - GNOME:              http://nmcheck.gnome.org/check_network_status.txt

IMPORTANT: never add any of these hostnames to the captive portal walled
garden. If they bypass the redirect, the client OS reaches the real
server, gets the "success" response, and concludes the network is NOT
captive — no sign-in popup.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import time

from fastapi import APIRouter, Request
from fastapi.responses import (
    HTMLResponse, PlainTextResponse, Response, RedirectResponse,
)

LOG = logging.getLogger("portal.cpd")
router = APIRouter()

DB_PATH = "/var/lib/nfw/captiveportal/sessions.db"
PORTAL_JSON = "/var/lib/nfw/captiveportal/portal.json"

APPLE_SUCCESS = (
    "<HTML><HEAD><TITLE>Success</TITLE></HEAD>"
    "<BODY>Success</BODY></HTML>"
)

# portal.json is rewritten on every captiveportal.apply. Cache the URL by
# mtime so we only re-read when it changes.
_url_cache: tuple[float, str] = (0.0, "/")


def _portal_url() -> str:
    global _url_cache
    try:
        mtime = os.stat(PORTAL_JSON).st_mtime
    except OSError:
        return "/"
    if _url_cache[0] == mtime:
        return _url_cache[1]
    try:
        with open(PORTAL_JSON) as f:
            cfg = json.load(f)
        ip = cfg.get("listen_ip") or "192.168.10.1"
        port = cfg.get("portal_port") or 8081
        url = f"http://{ip}:{port}/"
    except Exception as e:
        LOG.warning("cpd: portal.json read failed: %s", e)
        url = "/"
    _url_cache = (mtime, url)
    return url


def _is_authenticated(ip: str) -> bool:
    """True if ip has an active, non-revoked session in the DB."""
    if not ip:
        return False
    try:
        con = sqlite3.connect(DB_PATH, timeout=2)
        try:
            row = con.execute(
                "SELECT 1 FROM sessions "
                "WHERE ip=? AND revoked_at IS NULL AND expires_at > ? "
                "LIMIT 1",
                (ip, int(time.time())),
            ).fetchone()
        finally:
            con.close()
        return row is not None
    except Exception as e:
        LOG.warning("cpd auth check failed for %s: %s", ip, e)
        return False


def _client_ip(request: Request) -> str:
    if request.client and request.client.host:
        return request.client.host
    # Fallback: X-Forwarded-For if the portal is ever fronted by a proxy
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return ""


def _handle(request: Request, success_response):
    ip = _client_ip(request)
    if _is_authenticated(ip):
        return success_response
    return RedirectResponse(url=_portal_url(), status_code=302)


@router.api_route("/hotspot-detect.html", methods=["GET", "HEAD"])
async def apple_cna(request: Request):
    """Apple CNA — must return exactly this body when authenticated."""
    return _handle(request, HTMLResponse(APPLE_SUCCESS))


@router.api_route("/library/test/success.html", methods=["GET", "HEAD"])
async def apple_legacy(request: Request):
    """Older Apple check URL."""
    return _handle(request, HTMLResponse(APPLE_SUCCESS))


@router.api_route("/generate_204", methods=["GET", "HEAD"])
async def android_204(request: Request):
    """Android connectivity check — expects 204 No Content."""
    return _handle(request, Response(status_code=204))


@router.api_route("/gen_204", methods=["GET", "HEAD"])
async def android_gen204(request: Request):
    """Older Android variant."""
    return _handle(request, Response(status_code=204))


@router.api_route("/connecttest.txt", methods=["GET", "HEAD"])
async def windows_connecttest(request: Request):
    """Windows NCSI."""
    return _handle(request, PlainTextResponse("Microsoft Connect Test"))


@router.api_route("/ncsi.txt", methods=["GET", "HEAD"])
async def windows_ncsi(request: Request):
    """Windows NCSI legacy."""
    return _handle(request, PlainTextResponse("Microsoft NCSI"))


@router.api_route("/success.txt", methods=["GET", "HEAD"])
async def firefox_success(request: Request):
    """Firefox connectivity check."""
    return _handle(request, PlainTextResponse("success\n"))


@router.api_route("/check_network_status.txt", methods=["GET", "HEAD"])
async def gnome_check(request: Request):
    """GNOME NetworkManager."""
    return _handle(request, PlainTextResponse("NetworkManager is online"))
