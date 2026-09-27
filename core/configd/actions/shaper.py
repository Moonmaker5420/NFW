"""Traffic shaping actions."""
from __future__ import annotations
import logging
import sys
from typing import Any

from configd.registry import action

sys.path.insert(0, "/opt/nfw")
sys.path.insert(0, "/opt/nfw/core")

from config import store as cfg_store
from config.schema import validate
from modules.shaper import tc
from modules.network.interfaces import resolve_roles

LOG = logging.getLogger("configd.shaper")


def _effective_config() -> dict:
    staged = cfg_store.get_staging()
    cfg = dict(staged if staged is not None else cfg_store.read())
    try:
        cfg["_resolved_interfaces"] = resolve_roles(cfg.get("network", {}))
    except Exception:
        pass
    return cfg


def _section(cfg: dict) -> dict:
    s = cfg.setdefault("services", {}).setdefault("shaper_config", {})
    s.setdefault("enabled", False)
    s.setdefault("interfaces", [])
    return s


@action("shaper.config.get")
def shaper_get(_data):
    cfg = _effective_config()
    return {"config": _section(cfg), "status": tc.status(cfg)}


@action("shaper.config.set")
def shaper_set(data):
    new = data.get("config")
    if not isinstance(new, dict):
        raise ValueError("missing config")
    cfg = _effective_config()
    s = _section(cfg)
    s.update(new)
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"staged": True, "config": s}


@action("shaper.apply")
def shaper_apply(data):
    cfg = _effective_config()
    return tc.apply(cfg)


@action("shaper.status")
def shaper_status(_data):
    cfg = _effective_config()
    return tc.status(cfg)
