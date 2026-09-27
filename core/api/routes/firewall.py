"""Firewall rule + alias + NAT API routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException

from ..auth import Session
from ..configd_client import ConfigdError, call as configd_call
from ..deps import require_acl

router = APIRouter(prefix="/api/firewall", tags=["firewall"])


async def _cd(action: str, data: dict[str, Any] | None = None):
    try:
        return await configd_call(action, data)
    except ConfigdError as e:
        raise HTTPException(status_code=502, detail=f"configd: {e}")


# --- Rules -----------------------------------------------------------------
@router.get("/rules")
async def list_rules(user: Session = Depends(require_acl("readonly"))):
    return await _cd("firewall.rules.list")


@router.get("/rules/{rid}")
async def get_rule(rid: str, user: Session = Depends(require_acl("readonly"))):
    return await _cd("firewall.rules.get", {"id": rid})


@router.post("/rules")
async def add_rule(body: dict = Body(...),
                   user: Session = Depends(require_acl("operator"))):
    return await _cd("firewall.rules.add",
                     {"rule": body.get("rule"), "author": user.username})


@router.put("/rules/{rid}")
async def update_rule(rid: str, body: dict = Body(...),
                      user: Session = Depends(require_acl("operator"))):
    return await _cd("firewall.rules.update",
                     {"id": rid, "rule": body.get("rule"),
                      "author": user.username})


@router.delete("/rules/{rid}")
async def delete_rule(rid: str,
                      user: Session = Depends(require_acl("operator"))):
    return await _cd("firewall.rules.delete",
                     {"id": rid, "author": user.username})


@router.post("/rules/reorder")
async def reorder_rules(body: dict = Body(...),
                        user: Session = Depends(require_acl("operator"))):
    return await _cd("firewall.rules.reorder",
                     {"ids": body.get("ids"), "author": user.username})


@router.post("/rules/{rid}/toggle")
async def toggle_rule(rid: str,
                      user: Session = Depends(require_acl("operator"))):
    return await _cd("firewall.rules.toggle",
                     {"id": rid, "author": user.username})


# --- Aliases ---------------------------------------------------------------
@router.get("/aliases")
async def list_aliases(user: Session = Depends(require_acl("readonly"))):
    return await _cd("firewall.aliases.list")


@router.post("/aliases")
async def add_alias(body: dict = Body(...),
                    user: Session = Depends(require_acl("operator"))):
    return await _cd("firewall.aliases.add",
                     {"alias": body.get("alias"), "author": user.username})


@router.put("/aliases/{name}")
async def update_alias(name: str, body: dict = Body(...),
                       user: Session = Depends(require_acl("operator"))):
    return await _cd("firewall.aliases.update",
                     {"name": name, "alias": body.get("alias"),
                      "author": user.username})


@router.post("/aliases/refresh-all")
async def refresh_all_aliases(user: Session = Depends(require_acl("firewall.edit"))):
    return await _cd("firewall.aliases.refresh", {"author": user.username})


@router.get("/aliases/status")
async def aliases_status(user: Session = Depends(require_acl("readonly"))):
    return await _cd("firewall.aliases.status")


@router.post("/aliases/{name}/refresh")
async def refresh_alias(name: str,
                        user: Session = Depends(require_acl("firewall.edit"))):
    return await _cd("firewall.aliases.refresh", {"name": name, "author": user.username})


@router.delete("/aliases/{name}")
async def delete_alias(name: str,
                       user: Session = Depends(require_acl("operator"))):
    return await _cd("firewall.aliases.delete",
                     {"name": name, "author": user.username})


# --- Compile / apply -------------------------------------------------------
@router.get("/preview")
async def preview(user: Session = Depends(require_acl("readonly"))):
    return await _cd("firewall.preview")


@router.post("/apply")
async def apply_ruleset(user: Session = Depends(require_acl("admin"))):
    return await _cd("firewall.apply_staged")


# --- NAT -------------------------------------------------------------------
@router.get("/nat/port-forwards")
async def pf_list(user: Session = Depends(require_acl("readonly"))):
    return await _cd("nat.port_forwards.list")


@router.post("/nat/port-forwards")
async def pf_add(body: dict = Body(...),
                 user: Session = Depends(require_acl("operator"))):
    return await _cd("nat.port_forwards.add",
                     {"pf": body.get("pf"), "author": user.username})


@router.put("/nat/port-forwards/{pid}")
async def pf_update(pid: str, body: dict = Body(...),
                    user: Session = Depends(require_acl("operator"))):
    return await _cd("nat.port_forwards.update",
                     {"id": pid, "pf": body.get("pf"),
                      "author": user.username})


@router.delete("/nat/port-forwards/{pid}")
async def pf_delete(pid: str,
                    user: Session = Depends(require_acl("operator"))):
    return await _cd("nat.port_forwards.delete",
                     {"id": pid, "author": user.username})


@router.post("/nat/port-forwards/{pid}/toggle")
async def pf_toggle(pid: str,
                    user: Session = Depends(require_acl("operator"))):
    return await _cd("nat.port_forwards.toggle",
                     {"id": pid, "author": user.username})


# --- Phase 9.6 NAT ---------------------------------------------------------

@router.get("/nat/one-to-one")
async def nat_one_to_one_list(
    user: Session = Depends(require_acl("readonly")),
):
    return await _cd("nat.one_to_one.list")


@router.post("/nat/one-to-one")
async def nat_one_to_one_add(
    body: dict = Body(...),
    user: Session = Depends(require_acl("operator")),
):
    return await _cd(
        "nat.one_to_one.add",
        {
            "binat": body.get("binat"),
            "author": user.username,
        },
    )


@router.put("/nat/one-to-one/{rid}")
async def nat_one_to_one_update(
    rid: str,
    body: dict = Body(...),
    user: Session = Depends(require_acl("operator")),
):
    return await _cd(
        "nat.one_to_one.update",
        {
            "id": rid,
            "binat": body.get("binat"),
            "author": user.username,
        },
    )


@router.delete("/nat/one-to-one/{rid}")
async def nat_one_to_one_delete(
    rid: str,
    user: Session = Depends(require_acl("operator")),
):
    return await _cd(
        "nat.one_to_one.delete",
        {
            "id": rid,
            "author": user.username,
        },
    )


@router.post("/nat/one-to-one/{rid}/toggle")
async def nat_one_to_one_toggle(
    rid: str,
    user: Session = Depends(require_acl("operator")),
):
    return await _cd(
        "nat.one_to_one.toggle",
        {
            "id": rid,
            "author": user.username,
        },
    )


@router.get("/nat/npt")
async def nat_npt_list(
    user: Session = Depends(require_acl("readonly")),
):
    return await _cd("nat.npt.list")


@router.post("/nat/npt")
async def nat_npt_add(
    body: dict = Body(...),
    user: Session = Depends(require_acl("operator")),
):
    return await _cd(
        "nat.npt.add",
        {
            "entry": body.get("entry"),
            "author": user.username,
        },
    )


@router.put("/nat/npt/{rid}")
async def nat_npt_update(
    rid: str,
    body: dict = Body(...),
    user: Session = Depends(require_acl("operator")),
):
    return await _cd(
        "nat.npt.update",
        {
            "id": rid,
            "entry": body.get("entry"),
            "author": user.username,
        },
    )


@router.delete("/nat/npt/{rid}")
async def nat_npt_delete(
    rid: str,
    user: Session = Depends(require_acl("operator")),
):
    return await _cd(
        "nat.npt.delete",
        {
            "id": rid,
            "author": user.username,
        },
    )


@router.post("/nat/npt/{rid}/toggle")
async def nat_npt_toggle(
    rid: str,
    user: Session = Depends(require_acl("operator")),
):
    return await _cd(
        "nat.npt.toggle",
        {
            "id": rid,
            "author": user.username,
        },
    )


@router.get("/nat/reflection")
async def nat_reflection_get(
    user: Session = Depends(require_acl("readonly")),
):
    return await _cd("nat.reflection.get")


@router.put("/nat/reflection")
async def nat_reflection_set(
    body: dict = Body(...),
    user: Session = Depends(require_acl("operator")),
):
    return await _cd(
        "nat.reflection.set",
        {
            "reflection": body.get("reflection", body),
            "author": user.username,
        },
    )


@router.get("/nat/upnp")
async def nat_upnp_get(
    user: Session = Depends(require_acl("readonly")),
):
    return await _cd("nat.upnp.get")


@router.put("/nat/upnp")
async def nat_upnp_set(
    body: dict = Body(...),
    user: Session = Depends(require_acl("operator")),
):
    return await _cd(
        "nat.upnp.set",
        {
            "upnp": body.get("upnp", body),
            "author": user.username,
        },
    )


@router.post("/nat/upnp/detect-ip")
async def nat_upnp_detect_ip(user: Session = Depends(require_acl("operator"))):
    """Detect the current public IPv4 and save it into the UPnP config."""
    return await _cd("nat.upnp.detect_ip", {"author": user.username})


@router.post("/nat/upnp/sync")
async def nat_upnp_sync(
    user: Session = Depends(require_acl("admin")),
):
    return await _cd("nat.upnp.apply")


@router.get("/nat/status")
async def nat_status(
    user: Session = Depends(require_acl("readonly")),
):
    return await _cd("nat.status")

# ============================================================================
# Phase 9.7b — normalization
# ============================================================================
@router.get("/normalization")
async def norm_get(user: Session = Depends(require_acl("readonly"))):
    return await _cd("firewall.normalization.get")


@router.put("/normalization")
async def norm_set(body: dict = Body(...),
                   user: Session = Depends(require_acl("operator"))):
    return await _cd("firewall.normalization.set",
                     {"normalization": body.get("normalization"),
                      "author": user.username})

