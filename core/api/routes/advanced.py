"""Advanced feature API routes."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.responses import Response

from ..auth import Session
from ..configd_client import ConfigdError, call as configd_call
from ..deps import require_acl

router = APIRouter(prefix="/api/advanced", tags=["advanced"])


async def _cd(action: str, data: dict[str, Any] | None = None, timeout: float = 120.0):
    try:
        return await configd_call(action, data, timeout=timeout)
    except ConfigdError as e:
        raise HTTPException(status_code=502, detail=f"configd: {e}")


# ---- ACME ----
@router.get("/acme")
async def acme_list(user: Session = Depends(require_acl("readonly"))):
    return await _cd("acme.list")

@router.post("/acme/issue")
async def acme_issue(body: dict = Body(...), user: Session = Depends(require_acl("admin"))):
    return await _cd("acme.issue", {
        "domain": body.get("domain"), "email": body.get("email"),
        "webroot": body.get("webroot", "/var/www/html"),
        "dns_plugin": body.get("dns_plugin", ""),
        "dns_credentials": body.get("dns_credentials", ""),
        "staging": body.get("staging", False),
    }, timeout=300)

@router.post("/acme/renew")
async def acme_renew(body: dict = Body(default={}), user: Session = Depends(require_acl("admin"))):
    return await _cd("acme.renew", {"dry_run": body.get("dry_run", False)}, timeout=600)


# ---- HAProxy ----
@router.get("/haproxy")
async def haproxy_get(user: Session = Depends(require_acl("readonly"))):
    return await _cd("haproxy.config.get")

@router.put("/haproxy")
async def haproxy_set(body: dict = Body(...), user: Session = Depends(require_acl("operator"))):
    return await _cd("haproxy.config.set", {"config": body.get("config"), "author": user.username})

@router.get("/haproxy/preview")
async def haproxy_preview(user: Session = Depends(require_acl("readonly"))):
    return await _cd("haproxy.preview")

@router.post("/haproxy/apply")
async def haproxy_apply(user: Session = Depends(require_acl("admin"))):
    return await _cd("haproxy.apply")


# ---- Squid ----
@router.get("/squid")
async def squid_get(user: Session = Depends(require_acl("readonly"))):
    return await _cd("squid.config.get")

@router.put("/squid")
async def squid_set(body: dict = Body(...), user: Session = Depends(require_acl("operator"))):
    return await _cd("squid.config.set", {"config": body.get("config"), "author": user.username})

@router.get("/squid/preview")
async def squid_preview(user: Session = Depends(require_acl("readonly"))):
    return await _cd("squid.preview")

@router.post("/squid/apply")
async def squid_apply(user: Session = Depends(require_acl("admin"))):
    return await _cd("squid.apply")


# ---- Backup ----
@router.get("/backup")
async def backup_list(user: Session = Depends(require_acl("readonly"))):
    return await _cd("backup.list")

@router.get("/backup/export")
async def backup_export(user: Session = Depends(require_acl("admin"))):
    r = await _cd("backup.export", timeout=300)
    import base64
    data = base64.b64decode(r["data_b64"])
    return Response(content=data, media_type="application/gzip",
                    headers={"Content-Disposition": "attachment; filename=nfw-config-backup.tar.gz"})

@router.post("/backup/import")
async def backup_import(body: dict = Body(...), user: Session = Depends(require_acl("admin"))):
    return await _cd("backup.import", {"data_b64": body.get("data_b64"), "author": user.username}, timeout=300)


# ---- DDNS ----
@router.get("/ddns")
async def ddns_get(user: Session = Depends(require_acl("readonly"))):
    return await _cd("ddns.config.get")

@router.put("/ddns")
async def ddns_set(body: dict = Body(...), user: Session = Depends(require_acl("operator"))):
    return await _cd("ddns.config.set", {"config": body.get("config"), "author": user.username})

@router.post("/ddns/update")
async def ddns_update(user: Session = Depends(require_acl("operator"))):
    return await _cd("ddns.update", timeout=60)


# ---- WoL ----
@router.post("/wol")
async def wol(body: dict = Body(...), user: Session = Depends(require_acl("operator"))):
    return await _cd("wol.wake", {"mac": body.get("mac"), "broadcast": body.get("broadcast", "")})


# ---- SNMP ----
@router.get("/snmp")
async def snmp_get(user: Session = Depends(require_acl("readonly"))):
    return await _cd("snmp.config.get")

@router.put("/snmp")
async def snmp_set(body: dict = Body(...), user: Session = Depends(require_acl("operator"))):
    return await _cd("snmp.config.set", {"config": body.get("config"), "author": user.username})

@router.post("/snmp/apply")
async def snmp_apply(user: Session = Depends(require_acl("admin"))):
    return await _cd("snmp.apply")
