"""Diagnostics API routes (Phase 9.8)."""
from __future__ import annotations
import os
import re
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from fastapi.responses import FileResponse

from ..auth import Session
from ..configd_client import ConfigdError, call as configd_call
from ..deps import require_acl

router = APIRouter(prefix="/api/diagnostics", tags=["diagnostics"])

PCAP_DIR = "/var/lib/nfw/pcap"
PCAP_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}\.pcap$")


async def _cd(action: str, data: dict[str, Any] | None = None, timeout: float = 60.0):
    try:
        return await configd_call(action, data, timeout=timeout)
    except ConfigdError as e:
        raise HTTPException(status_code=502, detail=f"configd: {e}")


# --- Interfaces (for the packet-capture interface dropdown) ---
@router.get("/interfaces")
async def list_interfaces(user: Session = Depends(require_acl("readonly"))):
    return await _cd("network.interfaces", timeout=10)


# --- Ping / traceroute / dns ---
@router.get("/ping")
async def ping(target: str = Query(...), count: int = Query(4),
               family: str = Query("auto"), source: str = Query(""),
               user: Session = Depends(require_acl("readonly"))):
    return await _cd("diagnostics.ping",
                     {"target": target, "count": count,
                      "family": family, "source": source},
                     timeout=90)


@router.get("/traceroute")
async def traceroute(target: str = Query(...), max_hops: int = Query(20),
                     family: str = Query("auto"),
                     user: Session = Depends(require_acl("readonly"))):
    return await _cd("diagnostics.traceroute",
                     {"target": target, "max_hops": max_hops, "family": family},
                     timeout=180)


@router.get("/dns")
async def dns_lookup(query: str = Query(...), type: str = Query("A"),
                     server: str = Query(""),
                     user: Session = Depends(require_acl("readonly"))):
    return await _cd("diagnostics.dns_lookup",
                     {"query": query, "type": type, "server": server},
                     timeout=30)


@router.post("/port-test")
async def port_test(body: dict = Body(...),
                    user: Session = Depends(require_acl("readonly"))):
    return await _cd("diagnostics.port_test", body, timeout=30)


# --- ARP / NDP ---
@router.get("/arp")
async def arp(user: Session = Depends(require_acl("readonly"))):
    return await _cd("diagnostics.arp_table")


@router.get("/ndp")
async def ndp(user: Session = Depends(require_acl("readonly"))):
    return await _cd("diagnostics.ndp_table")


# --- Restricted commands ---
@router.get("/commands")
async def commands(user: Session = Depends(require_acl("readonly"))):
    return await _cd("diagnostics.commands")


@router.post("/command")
async def run_command(body: dict = Body(...),
                      user: Session = Depends(require_acl("readonly"))):
    return await _cd("diagnostics.command", {"name": body.get("name")},
                     timeout=30)


# --- Packet capture ---
@router.get("/pcap/status")
async def pcap_status(user: Session = Depends(require_acl("readonly"))):
    return await _cd("diagnostics.pcap_status")


@router.post("/pcap/start")
async def pcap_start(body: dict = Body(...),
                     user: Session = Depends(require_acl("operator"))):
    return await _cd("diagnostics.pcap_start", body, timeout=30)


@router.post("/pcap/stop")
async def pcap_stop(user: Session = Depends(require_acl("operator"))):
    return await _cd("diagnostics.pcap_stop", timeout=30)


@router.get("/pcap/list")
async def pcap_list(user: Session = Depends(require_acl("readonly"))):
    return await _cd("diagnostics.pcap_list")


@router.delete("/pcap/{name}")
async def pcap_delete(name: str,
                      user: Session = Depends(require_acl("operator"))):
    return await _cd("diagnostics.pcap_delete", {"name": name})


@router.get("/pcap/download/{name}")
async def pcap_download(name: str,
                        user: Session = Depends(require_acl("readonly"))):
    if not PCAP_NAME_RE.match(name):
        raise HTTPException(400, "invalid capture name")
    path = os.path.join(PCAP_DIR, name)
    # Defend against any path traversal
    if os.path.realpath(path) != os.path.join(PCAP_DIR, name):
        raise HTTPException(400, "invalid path")
    if not os.path.exists(path):
        raise HTTPException(404, "capture not found")
    return FileResponse(path, media_type="application/vnd.tcpdump.pcap",
                        filename=name)
