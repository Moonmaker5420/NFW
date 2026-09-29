"""Service API routes: DHCP, DNS, NTP."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, Body, Depends, HTTPException

from ..auth import Session
from ..configd_client import ConfigdError, call as configd_call
from ..deps import require_acl

router = APIRouter(prefix="/api/services", tags=["services"])


async def _cd(action: str, data: dict[str, Any] | None = None,
               timeout: float = 60.0):
    try:
        return await configd_call(action, data, timeout=timeout)
    except ConfigdError as e:
        raise HTTPException(status_code=502, detail=f"configd: {e}")


# DHCP
@router.get("/dhcp")
async def dhcp_get(user: Session = Depends(require_acl("readonly"))):
    return await _cd("dhcp.config.get")

@router.put("/dhcp")
async def dhcp_set(body: dict = Body(...),
                   user: Session = Depends(require_acl("operator"))):
    return await _cd("dhcp.config.set",
                     {"config": body.get("config"), "author": user.username})

@router.get("/dhcp/preview")
async def dhcp_preview(user: Session = Depends(require_acl("readonly"))):
    return await _cd("dhcp.preview")

@router.post("/dhcp/apply")
async def dhcp_apply(user: Session = Depends(require_acl("admin"))):
    return await _cd("dhcp.apply")

@router.get("/dhcp/leases")
async def dhcp_leases(user: Session = Depends(require_acl("readonly"))):
    return await _cd("dhcp.leases")

# DNS
@router.get("/dns")
async def dns_get(user: Session = Depends(require_acl("readonly"))):
    return await _cd("dns.config.get")

@router.put("/dns")
async def dns_set(body: dict = Body(...),
                  user: Session = Depends(require_acl("operator"))):
    return await _cd("dns.config.set",
                     {"config": body.get("config"), "author": user.username})

@router.get("/dns/preview")
async def dns_preview(user: Session = Depends(require_acl("readonly"))):
    return await _cd("dns.preview")

@router.post("/dns/apply")
async def dns_apply(user: Session = Depends(require_acl("admin"))):
    return await _cd("dns.apply")

@router.get("/dns/querylog")
async def dns_querylog(lines: int = 100,
                       user: Session = Depends(require_acl("readonly"))):
    return await _cd("dns.querylog", {"lines": lines})

# NTP
@router.get("/dns/blocklist")
async def dns_blocklist_get(user: Session = Depends(require_acl("readonly"))):
    return await _cd("dns.blocklist.get")


@router.put("/dns/blocklist")
async def dns_blocklist_set(body: dict = Body(...),
                            user: Session = Depends(require_acl("admin"))):
    return await _cd("dns.blocklist.set", {
        "config": body.get("config") or {},
        "author": user.username,
    })


@router.post("/dns/blocklist/refresh")
async def dns_blocklist_refresh(user: Session = Depends(require_acl("admin"))):
    return await _cd("dns.blocklist.refresh", timeout=300)


@router.get("/ntp")
async def ntp_get(user: Session = Depends(require_acl("readonly"))):
    return await _cd("ntp.config.get")

@router.put("/ntp")
async def ntp_set(body: dict = Body(...),
                  user: Session = Depends(require_acl("operator"))):
    return await _cd("ntp.config.set",
                     {"config": body.get("config"), "author": user.username})

@router.get("/ntp/preview")
async def ntp_preview(user: Session = Depends(require_acl("readonly"))):
    return await _cd("ntp.preview")

@router.post("/ntp/apply")
async def ntp_apply(user: Session = Depends(require_acl("admin"))):
    return await _cd("ntp.apply")

@router.get("/ntp/status")
async def ntp_status(user: Session = Depends(require_acl("readonly"))):
    return await _cd("ntp.status")

# RADIUS
@router.get("/radius")
async def radius_get(user: Session = Depends(require_acl("readonly"))):
    return await _cd("radius.config.get")

@router.put("/radius")
async def radius_set(body: dict = Body(...),
                     user: Session = Depends(require_acl("operator"))):
    return await _cd("radius.config.set",
                     {"config": body.get("config"), "author": user.username})

@router.get("/radius/preview")
async def radius_preview(user: Session = Depends(require_acl("readonly"))):
    return await _cd("radius.preview")

@router.post("/radius/apply")
async def radius_apply(user: Session = Depends(require_acl("admin"))):
    return await _cd("radius.apply")

@router.get("/radius/status")
async def radius_status(user: Session = Depends(require_acl("readonly"))):
    return await _cd("radius.status")

@router.post("/radius/hash-nt")
async def radius_hash_nt(body: dict = Body(...),
                          user: Session = Depends(require_acl("operator"))):
    return await _cd("radius.hash_nt", {"password": body.get("password")})

@router.post("/radius/test")
async def radius_test(body: dict = Body(...),
                      user: Session = Depends(require_acl("operator"))):
    return await _cd("radius.test_user",
                     {"username": body.get("username"),
                      "password": body.get("password")})

# Captive Portal
@router.get("/captiveportal")
async def cp_get(user: Session = Depends(require_acl("readonly"))):
    return await _cd("captiveportal.config.get")

@router.put("/captiveportal")
async def cp_set(body: dict = Body(...),
                 user: Session = Depends(require_acl("operator"))):
    return await _cd("captiveportal.config.set",
                     {"config": body.get("config"), "author": user.username})

@router.post("/captiveportal/apply")
async def cp_apply(user: Session = Depends(require_acl("admin"))):
    return await _cd("captiveportal.apply")

@router.get("/captiveportal/status")
async def cp_status(user: Session = Depends(require_acl("readonly"))):
    return await _cd("captiveportal.status")

@router.get("/captiveportal/sessions")
async def cp_sessions(kind: str = "all", q: str = "",
                       include_revoked: bool = False,
                       limit: int = 500,
                       user: Session = Depends(require_acl("readonly"))):
    return await _cd("captiveportal.sessions.list", {
        "kind": kind, "q": q,
        "include_revoked": include_revoked, "limit": limit,
    })

@router.post("/captiveportal/sessions/{ip}/kick")
async def cp_kick(ip: str, body: dict = Body(default={}),
                  user: Session = Depends(require_acl("operator"))):
    return await _cd("captiveportal.sessions.kick",
                     {"ip": ip, "ttl": body.get("ttl") or 3600})

@router.post("/captiveportal/sessions/unkick")
async def cp_unkick(body: dict = Body(...),
                    user: Session = Depends(require_acl("operator"))):
    return await _cd("captiveportal.sessions.unkick", {
        "ip": body.get("ip"),
        "mac": body.get("mac"),
    })

@router.get("/captiveportal/bypass/kicks")
async def cp_kicks(user: Session = Depends(require_acl("readonly"))):
    return await _cd("captiveportal.bypass.kicks_list")

@router.post("/captiveportal/prune")
async def cp_prune(user: Session = Depends(require_acl("operator"))):
    return await _cd("captiveportal.prune")

# Captive Portal — Vouchers (9.18b1)
@router.post("/captiveportal/vouchers/generate")
async def cp_vouchers_generate(body: dict = Body(...),
                                user: Session = Depends(require_acl("operator"))):
    return await _cd("captiveportal.vouchers.generate", body)

@router.get("/captiveportal/vouchers")
async def cp_vouchers_list(group_name: str | None = None,
                            include_used: bool = True,
                            include_disabled: bool = True,
                            limit: int = 2000,
                            user: Session = Depends(require_acl("readonly"))):
    return await _cd("captiveportal.vouchers.list", {
        "group_name": group_name,
        "include_used": include_used,
        "include_disabled": include_disabled,
        "limit": limit,
    })

@router.get("/captiveportal/vouchers/groups")
async def cp_vouchers_groups(user: Session = Depends(require_acl("readonly"))):
    return await _cd("captiveportal.vouchers.groups")

@router.get("/captiveportal/vouchers/export")
async def cp_vouchers_export(group_name: str | None = None,
                              include_used: bool = True,
                              user: Session = Depends(require_acl("readonly"))):
    from fastapi.responses import Response as _R
    r = await _cd("captiveportal.vouchers.export_csv", {
        "group_name": group_name, "include_used": include_used,
    })
    csv_text = r.get("csv", "")
    fname = f"vouchers-{group_name or 'all'}-{int(__import__('time').time())}.csv"
    return _R(content=csv_text, media_type="text/csv",
              headers={"Content-Disposition": f'attachment; filename="{fname}"'})

@router.delete("/captiveportal/vouchers/{vid}")
async def cp_vouchers_delete(vid: int,
                              user: Session = Depends(require_acl("operator"))):
    return await _cd("captiveportal.vouchers.delete", {"id": vid})

@router.post("/captiveportal/vouchers/delete-group")
async def cp_vouchers_delete_group(body: dict = Body(...),
                                    user: Session = Depends(require_acl("admin"))):
    return await _cd("captiveportal.vouchers.delete_group",
                     {"group_name": body.get("group_name")})

@router.post("/captiveportal/vouchers/{vid}/enable")
async def cp_vouchers_enable(vid: int, body: dict = Body(...),
                              user: Session = Depends(require_acl("operator"))):
    return await _cd("captiveportal.vouchers.set_enabled",
                     {"id": vid, "enabled": body.get("enabled", True)})

# Captive Portal — Bypass (9.18b3)
@router.get("/captiveportal/bypass")
async def cp_bypass_get(user: Session = Depends(require_acl("readonly"))):
    return await _cd("captiveportal.bypass_status")

@router.post("/captiveportal/bypass/refresh")
async def cp_bypass_refresh(user: Session = Depends(require_acl("operator"))):
    return await _cd("captiveportal.bypass_refresh")

# Captive Portal — Templates (9.18b4)
import base64 as _b64

@router.get("/captiveportal/templates")
async def cp_tpl_list(user: Session = Depends(require_acl("readonly"))):
    return await _cd("captiveportal.templates.list")


@router.post("/captiveportal/templates/upload")
async def cp_tpl_upload(body: dict = Body(...),
                        user: Session = Depends(require_acl("operator"))):
    return await _cd("captiveportal.templates.upload",
                     {"zip_b64": body.get("zip_b64"),
                      "name": body.get("name")})


@router.delete("/captiveportal/templates/{tid}")
async def cp_tpl_delete(tid: str,
                        user: Session = Depends(require_acl("operator"))):
    return await _cd("captiveportal.templates.delete", {"id": tid})


@router.get("/captiveportal/templates/{tid}/files")
async def cp_tpl_files(tid: str,
                       user: Session = Depends(require_acl("readonly"))):
    return await _cd("captiveportal.templates.files", {"id": tid})


@router.get("/captiveportal/templates/{tid}/file")
async def cp_tpl_file_get(tid: str, path: str,
                          user: Session = Depends(require_acl("readonly"))):
    return await _cd("captiveportal.templates.file_get",
                     {"id": tid, "path": path})


@router.put("/captiveportal/templates/{tid}/file")
async def cp_tpl_file_put(tid: str, body: dict = Body(...),
                          user: Session = Depends(require_acl("operator"))):
    return await _cd("captiveportal.templates.file_put",
                     {"id": tid, "path": body.get("path"),
                      "content": body.get("content")})


@router.delete("/captiveportal/templates/{tid}/file")
async def cp_tpl_file_delete(tid: str, path: str,
                             user: Session = Depends(require_acl("operator"))):
    return await _cd("captiveportal.templates.file_delete",
                     {"id": tid, "path": path})


@router.get("/captiveportal/templates/download/starter")
async def cp_tpl_download_starter(user: Session = Depends(require_acl("readonly"))):
    from fastapi.responses import Response as _R
    r = await _cd("captiveportal.templates.download_starter")
    raw = _b64.b64decode(r.get("zip_b64") or "")
    return _R(content=raw, media_type="application/zip",
              headers={"Content-Disposition": 'attachment; filename="nfw-portal-starter.zip"'})

