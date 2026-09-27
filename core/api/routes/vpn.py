"""VPN API routes."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, Body, Depends, HTTPException

from ..auth import Session
from ..configd_client import ConfigdError, call as configd_call
from ..deps import require_acl

router = APIRouter(prefix="/api/vpn", tags=["vpn"])


async def _cd(action: str, data: dict[str, Any] | None = None):
    try:
        return await configd_call(action, data)
    except ConfigdError as e:
        # Translate common errors to proper HTTP status codes
        msg = str(e)
        if "not found" in msg or "FileNotFoundError" in msg:
            raise HTTPException(status_code=404, detail=msg)
        if "unauthorized" in msg.lower():
            raise HTTPException(status_code=403, detail=msg)
        raise HTTPException(status_code=502, detail=f"configd: {e}")


# --- WireGuard -------------------------------------------------------------
@router.get("/wireguard")
async def wg_list(user: Session = Depends(require_acl("readonly"))):
    return await _cd("vpn.wg.list")

@router.post("/wireguard/instances")
async def wg_add(body: dict = Body(...), user: Session = Depends(require_acl("operator"))):
    return await _cd("vpn.wg.add_instance", {"instance": body.get("instance"), "author": user.username})

@router.put("/wireguard/instances/{iid}")
async def wg_update(iid: str, body: dict = Body(...), user: Session = Depends(require_acl("operator"))):
    return await _cd("vpn.wg.update_instance", {"id": iid, "instance": body.get("instance"), "author": user.username})

@router.delete("/wireguard/instances/{iid}")
async def wg_delete(iid: str, user: Session = Depends(require_acl("operator"))):
    return await _cd("vpn.wg.delete_instance", {"id": iid, "author": user.username})

@router.post("/wireguard/peers")
async def wg_add_peer(body: dict = Body(...), user: Session = Depends(require_acl("operator"))):
    return await _cd("vpn.wg.add_peer", {"instance_id": body.get("instance_id"), "peer": body.get("peer"), "author": user.username})

@router.delete("/wireguard/peers")
async def wg_del_peer(body: dict = Body(...), user: Session = Depends(require_acl("operator"))):
    return await _cd("vpn.wg.delete_peer", {"instance_id": body.get("instance_id"), "peer_id": body.get("peer_id"), "author": user.username})

@router.get("/wireguard/preview")
async def wg_preview(user: Session = Depends(require_acl("readonly"))):
    return await _cd("vpn.wg.preview")

@router.post("/wireguard/apply")
async def wg_apply(user: Session = Depends(require_acl("admin"))):
    return await _cd("vpn.wg.apply")

@router.post("/wireguard/qr")
async def wg_qr(body: dict = Body(...), user: Session = Depends(require_acl("readonly"))):
    return await _cd("vpn.wg.qr", {"instance_id": body.get("instance_id"), "peer_id": body.get("peer_id")})


# --- OpenVPN ---------------------------------------------------------------
@router.get("/openvpn")
async def ovpn_list(user: Session = Depends(require_acl("readonly"))):
    return await _cd("vpn.ovpn.list")

@router.post("/openvpn/servers")
async def ovpn_add(body: dict = Body(...), user: Session = Depends(require_acl("operator"))):
    return await _cd("vpn.ovpn.add_server", {"server": body.get("server"), "author": user.username})

@router.delete("/openvpn/servers/{sid}")
async def ovpn_del(sid: str, user: Session = Depends(require_acl("operator"))):
    return await _cd("vpn.ovpn.delete_server", {"id": sid, "author": user.username})

@router.post("/openvpn/clients")
async def ovpn_add_client(body: dict = Body(...), user: Session = Depends(require_acl("operator"))):
    return await _cd("vpn.ovpn.add_client", {"server_id": body.get("server_id"), "name": body.get("name"), "author": user.username})

@router.post("/openvpn/apply")
async def ovpn_apply(user: Session = Depends(require_acl("admin"))):
    return await _cd("vpn.ovpn.apply")

@router.get("/openvpn/export/{name}")
async def ovpn_export(name: str, user: Session = Depends(require_acl("readonly"))):
    return await _cd("vpn.ovpn.export", {"name": name})


# --- IPsec -----------------------------------------------------------------
@router.get("/ipsec")
async def ipsec_list(user: Session = Depends(require_acl("readonly"))):
    return await _cd("vpn.ipsec.list")

@router.post("/ipsec/tunnels")
async def ipsec_add(body: dict = Body(...), user: Session = Depends(require_acl("operator"))):
    return await _cd("vpn.ipsec.add_tunnel", {"tunnel": body.get("tunnel"), "author": user.username})

@router.delete("/ipsec/tunnels/{tid}")
async def ipsec_del(tid: str, user: Session = Depends(require_acl("operator"))):
    return await _cd("vpn.ipsec.delete_tunnel", {"id": tid, "author": user.username})

@router.post("/ipsec/apply")
async def ipsec_apply(user: Session = Depends(require_acl("admin"))):
    return await _cd("vpn.ipsec.apply")
