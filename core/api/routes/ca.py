"""Certificate Authority API routes (Phase 9.10)."""
from __future__ import annotations
import base64
from typing import Any
from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.responses import Response

from ..auth import Session
from ..configd_client import ConfigdError, call as configd_call
from ..deps import require_acl

router = APIRouter(prefix="/api/ca", tags=["ca"])


async def _cd(action: str, data: dict[str, Any] | None = None, timeout: float = 60.0):
    try:
        return await configd_call(action, data, timeout=timeout)
    except ConfigdError as e:
        raise HTTPException(status_code=502, detail=f"configd: {e}")


@router.get("/status")
async def ca_status(user: Session = Depends(require_acl("readonly"))):
    return await _cd("ca.status")


@router.get("/config")
async def ca_config_get(user: Session = Depends(require_acl("readonly"))):
    return await _cd("ca.config.get")


@router.put("/config")
async def ca_config_set(body: dict = Body(...),
                        user: Session = Depends(require_acl("admin"))):
    return await _cd("ca.config.set",
                     {"config": body.get("config"), "author": user.username})


@router.post("/init")
async def ca_init(body: dict = Body(default={}),
                  user: Session = Depends(require_acl("admin"))):
    return await _cd("ca.init", {"force": bool(body.get("force", False))}, timeout=180)


@router.post("/issue")
async def ca_issue(body: dict = Body(...),
                   user: Session = Depends(require_acl("admin"))):
    return await _cd("ca.issue", body, timeout=60)


@router.post("/sign-csr")
async def ca_sign_csr(body: dict = Body(...),
                      user: Session = Depends(require_acl("admin"))):
    return await _cd("ca.sign_csr", body, timeout=60)


@router.get("/certs")
async def ca_list(user: Session = Depends(require_acl("readonly"))):
    return await _cd("ca.list")


@router.get("/certs/{serial}")
async def ca_get(serial: str, user: Session = Depends(require_acl("readonly"))):
    return await _cd("ca.get", {"serial": serial})


@router.post("/revoke")
async def ca_revoke(body: dict = Body(...),
                    user: Session = Depends(require_acl("admin"))):
    return await _cd("ca.revoke",
                     {"serial": body.get("serial"),
                      "reason": body.get("reason", "unspecified")})


@router.post("/crl/regenerate")
async def ca_crl_regen(user: Session = Depends(require_acl("admin"))):
    return await _cd("ca.crl_regen")


@router.post("/export/p12")
async def ca_export_p12(body: dict = Body(...),
                        user: Session = Depends(require_acl("admin"))):
    return await _cd("ca.export_p12",
                     {"serial": body.get("serial"),
                      "password": body.get("password")}, timeout=60)


@router.delete("/certs/{serial}")
async def ca_delete(serial: str,
                    user: Session = Depends(require_acl("admin"))):
    return await _cd("ca.delete", {"serial": serial})


@router.get("/root.crt")
async def ca_root_download(user: Session = Depends(require_acl("readonly"))):
    r = await _cd("ca.root_pem")
    data = base64.b64decode(r["data_b64"])
    return Response(content=data, media_type="application/x-pem-file",
                    headers={"Content-Disposition":
                             "attachment; filename=nfw-root-ca.crt"})


@router.get("/chain.crt")
async def ca_chain_download(user: Session = Depends(require_acl("readonly"))):
    r = await _cd("ca.chain_pem")
    data = base64.b64decode(r["data_b64"])
    return Response(content=data, media_type="application/x-pem-file",
                    headers={"Content-Disposition":
                             "attachment; filename=nfw-ca-chain.crt"})

# =============================================================================
# Phase 9.10b — integration endpoints
# =============================================================================
@router.post("/issue-for-host")
async def ca_issue_for_host(user: Session = Depends(require_acl("admin"))):
    return await _cd("ca.issue_for_host", timeout=60)


@router.get("/expiring")
async def ca_expiring(within_days: int = 30,
                      user: Session = Depends(require_acl("readonly"))):
    return await _cd("ca.expiring", {"within_days": within_days})


@router.post("/renew")
async def ca_renew(body: dict = Body(...),
                   user: Session = Depends(require_acl("admin"))):
    return await _cd("ca.renew", {"serial": body.get("serial")}, timeout=60)


@router.get("/{serial}/paths")
async def ca_cert_paths(serial: str,
                        user: Session = Depends(require_acl("readonly"))):
    return await _cd("ca.cert_paths", {"serial": serial})


@router.get("/tls/status")
async def ca_tls_status(user: Session = Depends(require_acl("readonly"))):
    return await _cd("ca.tls_status")


@router.post("/tls/enable")
async def ca_tls_enable(user: Session = Depends(require_acl("admin"))):
    return await _cd("ca.tls_enable", timeout=60)


@router.post("/tls/disable")
async def ca_tls_disable(user: Session = Depends(require_acl("admin"))):
    return await _cd("ca.tls_disable", timeout=60)

