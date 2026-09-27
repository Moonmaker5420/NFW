"""Firewall normalization / scrubbing (Phase 9.7b)."""
from __future__ import annotations
import logging
import sys
from typing import Any

from configd.registry import action

sys.path.insert(0, "/opt/nfw")
sys.path.insert(0, "/opt/nfw/core")

from config import store as cfg_store
from config.schema import validate

LOG = logging.getLogger("configd.normalization")

_DEFAULTS = {
    "mss_clamp": False,
    "mss_clamp_size": 1452,
    "frag_policy": "pass",
    "drop_invalid": True,
    "icmp_drop_redirects": True,
    "icmp_drop_source_quench": True,
    "syn_flood_protect": False,
    "log_martians": False,
}


def _effective_config() -> dict:
    staged = cfg_store.get_staging()
    return dict(staged if staged is not None else cfg_store.read())


def _norm(cfg: dict) -> dict:
    s = cfg.setdefault("firewall", {}).setdefault("normalization", {})
    for k, v in _DEFAULTS.items():
        s.setdefault(k, v)
    return s


def _stage(cfg: dict, author: str) -> None:
    validate(cfg)
    cfg_store.stage(cfg, author=author or "unknown")


@action("firewall.normalization.get")
def norm_get(_data):
    cfg = _effective_config()
    return {"normalization": _norm(cfg)}


@action("firewall.normalization.set")
def norm_set(data):
    n = data.get("normalization")
    if not isinstance(n, dict):
        raise ValueError("missing 'normalization'")
    # whitelist known keys only
    clean = {}
    for k, v in n.items():
        if k in _DEFAULTS:
            clean[k] = v
    if "mss_clamp_size" in clean:
        try:
            clean["mss_clamp_size"] = int(clean["mss_clamp_size"])
        except (TypeError, ValueError):
            raise ValueError("mss_clamp_size must be int")
    if "frag_policy" in clean and clean["frag_policy"] not in ("pass", "drop"):
        raise ValueError("frag_policy must be 'pass' or 'drop'")
    cfg = _effective_config()
    s = _norm(cfg)
    s.update(clean)
    _stage(cfg, data.get("author"))
    return {"normalization": s}
