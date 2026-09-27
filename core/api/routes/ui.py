"""UI page routes — serve Jinja2 templates (Phase 4 adds firewall pages)."""
from __future__ import annotations

import socket
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .. import __version__
from ..auth import Session, current_user, session_from_request

router = APIRouter(tags=["ui"])

TEMPLATE_DIR = Path("/opt/nfw/web/templates")
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


def _ctx(request: Request, user: Session, **extra) -> dict:
    ctx = {
        "user": {"username": user.username, "role": user.role},
        "hostname": socket.gethostname(),
        "version": __version__,
    }
    ctx.update(extra)
    return ctx


def _render(request: Request, template: str, **ctx) -> HTMLResponse:
    # Browsers cache HTML aggressively. Without no-store, a page rendered
    # before a config change (e.g. hostname) keeps showing the old value
    # for hours. See handoff §E.
    resp = templates.TemplateResponse(request, template, ctx)
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    return resp


@router.get("/login", response_class=HTMLResponse)
async def page_login(request: Request):
    if session_from_request(request) is not None:
        return RedirectResponse(url="/", status_code=302)
    return _render(request, "login.html")


@router.get("/", response_class=HTMLResponse)
async def page_dashboard(request: Request, user: Session = Depends(current_user)):
    return _render(request, "dashboard.html", **_ctx(request, user))


@router.get("/config", response_class=HTMLResponse)
async def page_config(request: Request, user: Session = Depends(current_user)):
    return _render(request, "config/active.html", **_ctx(request, user))


@router.get("/config/revisions", response_class=HTMLResponse)
async def page_revisions(request: Request, user: Session = Depends(current_user)):
    return _render(request, "config/revisions.html", **_ctx(request, user))


# --- Phase 4 pages ---------------------------------------------------------
@router.get("/firewall/settings/normalization", response_class=HTMLResponse)
async def page_fw_normalization(request: Request, user: Session = Depends(current_user)):
    return _render(request, "firewall/normalization.html", **_ctx(request, user))


@router.get("/firewall/schedules", response_class=HTMLResponse)
async def page_fw_schedules(request: Request, user: Session = Depends(current_user)):
    return _render(request, "firewall/schedules.html", **_ctx(request, user))


@router.get("/firewall/rules", response_class=HTMLResponse)
async def page_fw_rules(request: Request, user: Session = Depends(current_user)):
    return _render(request, "firewall/rules.html", **_ctx(request, user))


@router.get("/firewall/aliases", response_class=HTMLResponse)
async def page_fw_aliases(request: Request, user: Session = Depends(current_user)):
    return _render(request, "firewall/aliases.html", **_ctx(request, user))


@router.get("/firewall/preview", response_class=HTMLResponse)
async def page_fw_preview(request: Request, user: Session = Depends(current_user)):
    return _render(request, "firewall/preview.html", **_ctx(request, user))


@router.get("/firewall/livelog", response_class=HTMLResponse)
async def page_fw_livelog(request: Request, user: Session = Depends(current_user)):
    return _render(request, "firewall/livelog.html", **_ctx(request, user))


@router.get("/firewall/nat/port-forward", response_class=HTMLResponse)
async def page_pf(request: Request, user: Session = Depends(current_user)):
    return _render(request, "nat/port-forward.html", **_ctx(request, user))

@router.get("/firewall/nat/one-to-one", response_class=HTMLResponse)
async def page_oto(request: Request, user: Session = Depends(current_user)):
    return _render(request, "nat/one-to-one.html", **_ctx(request, user))


@router.get("/firewall/nat/npt", response_class=HTMLResponse)
async def page_npt(request: Request, user: Session = Depends(current_user)):
    return _render(request, "nat/npt.html", **_ctx(request, user))


@router.get("/firewall/nat/reflection", response_class=HTMLResponse)
async def page_refl(request: Request, user: Session = Depends(current_user)):
    return _render(request, "nat/reflection.html", **_ctx(request, user))


@router.get("/firewall/nat/upnp", response_class=HTMLResponse)
async def page_upnp(request: Request, user: Session = Depends(current_user)):
    return _render(request, "nat/upnp.html", **_ctx(request, user))


@router.get("/firewall/nat", response_class=HTMLResponse)
async def page_nat(request: Request, user: Session = Depends(current_user)):
    # NAT has no landing page; send users to the most-used sub-page.
    return RedirectResponse(url="/firewall/nat/port-forward", status_code=302)



# --- Existing pages --------------------------------------------------------
@router.get("/system/interfaces", response_class=HTMLResponse)
async def page_ifaces(request: Request, user: Session = Depends(current_user)):
    return _render(request, "system/interfaces.html", **_ctx(request, user))


@router.get("/system/routes", response_class=HTMLResponse)
async def page_routes(request: Request, user: Session = Depends(current_user)):
    return _render(request, "system/routes.html", **_ctx(request, user))


@router.get("/system/services", response_class=HTMLResponse)
async def page_services(request: Request, user: Session = Depends(current_user)):
    return _render(request, "system/services.html", **_ctx(request, user))


@router.get("/system/acls", response_class=HTMLResponse)
async def page_acls(request: Request, user: Session = Depends(current_user)):
    return _render(request, "system/acls.html", **_ctx(request, user))


@router.get("/system/auth-providers", response_class=HTMLResponse)
async def page_auth_providers(request: Request, user: Session = Depends(current_user)):
    return _render(request, "system/auth-providers.html", **_ctx(request, user))


@router.get("/system/ca", response_class=HTMLResponse)
async def page_ca(request: Request, user: Session = Depends(current_user)):
    return _render(request, "system/ca.html", **_ctx(request, user))


@router.get("/system/security", response_class=HTMLResponse)
async def page_security(request: Request, user: Session = Depends(current_user)):
    return _render(request, "system/security.html", **_ctx(request, user))


@router.get("/system/users", response_class=HTMLResponse)
async def page_users(request: Request, user: Session = Depends(current_user)):
    return _render(request, "system/users.html", **_ctx(request, user))


@router.get("/system/power", response_class=HTMLResponse)
async def page_system_power(request: Request,
                            user: Session = Depends(current_user)):
    return _render(request, "system/power.html", **_ctx(request, user))


@router.get("/system/alerts", response_class=HTMLResponse)
async def page_system_alerts(request: Request,
                             user: Session = Depends(current_user)):
    return _render(request, "system/alerts.html", **_ctx(request, user))


@router.get("/system/logs", response_class=HTMLResponse)
async def page_logs(request: Request, user: Session = Depends(current_user)):
    return _render(request, "system/logs.html", **_ctx(request, user))


# --- Phase 5 pages ---------------------------------------------------------
@router.get("/services/dhcp", response_class=HTMLResponse)
async def page_dhcp(request: Request, user: Session = Depends(current_user)):
    return _render(request, "services/dhcp.html", **_ctx(request, user))


@router.get("/services/dns", response_class=HTMLResponse)
async def page_dns(request: Request, user: Session = Depends(current_user)):
    return _render(request, "services/dns.html", **_ctx(request, user))


@router.get("/services/captiveportal", response_class=HTMLResponse)
async def page_services_captiveportal(request: Request, user: Session = Depends(current_user)):
    return _render(request, "services/captiveportal.html", **_ctx(request, user))


@router.get("/services/radius", response_class=HTMLResponse)
async def page_services_radius(request: Request, user: Session = Depends(current_user)):
    return _render(request, "services/radius.html", **_ctx(request, user))


@router.get("/services/ntp", response_class=HTMLResponse)
async def page_ntp(request: Request, user: Session = Depends(current_user)):
    return _render(request, "services/ntp.html", **_ctx(request, user))


# --- Gateways ---------------------------------------------------------------
@router.get("/gateways", response_class=HTMLResponse)
async def page_gateways(request: Request, user: Session = Depends(current_user)):
    return _render(request, "gateway/index.html", **_ctx(request, user))


@router.get("/vpn", response_class=HTMLResponse)
async def page_vpn(request: Request, user: Session = Depends(current_user)):
    return _render(request, "vpn/index.html", **_ctx(request, user))


@router.get("/ids", response_class=HTMLResponse)
async def page_ids(request: Request, user: Session = Depends(current_user)):
    return _render(request, "ids/index.html", **_ctx(request, user))


@router.get("/shaper", response_class=HTMLResponse)
async def page_shaper(request: Request, user: Session = Depends(current_user)):
    return _render(request, "shaper/index.html", **_ctx(request, user))


@router.get("/advanced/acme", response_class=HTMLResponse)
async def page_acme(request: Request, user: Session = Depends(current_user)):
    return _render(request, "advanced/acme.html", **_ctx(request, user))


@router.get("/advanced/haproxy", response_class=HTMLResponse)
async def page_haproxy(request: Request, user: Session = Depends(current_user)):
    return _render(request, "advanced/haproxy.html", **_ctx(request, user))


@router.get("/advanced/backup", response_class=HTMLResponse)
async def page_backup(request: Request, user: Session = Depends(current_user)):
    return _render(request, "advanced/backup.html", **_ctx(request, user))


@router.get("/advanced/misc", response_class=HTMLResponse)
async def page_misc(request: Request, user: Session = Depends(current_user)):
    return _render(request, "advanced/misc.html", **_ctx(request, user))


@router.get("/interfaces/advanced", response_class=HTMLResponse)
async def page_ifaces_advanced(request: Request, user: Session = Depends(current_user)):
    return _render(request, "interfaces/advanced.html", **_ctx(request, user))


# --- Phase 9.8 pages -------------------------------------------------------
@router.get("/reporting", response_class=HTMLResponse)
async def page_reporting(request: Request, user: Session = Depends(current_user)):
    return _render(request, "reporting/index.html", **_ctx(request, user))


@router.get("/diagnostics", response_class=HTMLResponse)
async def page_diagnostics(request: Request,
                           user: Session = Depends(current_user)):
    return _render(request, "diagnostics/index.html", **_ctx(request, user))
