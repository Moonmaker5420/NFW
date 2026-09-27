"""IDS/IPS actions."""
from __future__ import annotations
import logging
import sys
from typing import Any

from configd.registry import action

sys.path.insert(0, "/opt/nfw")
sys.path.insert(0, "/opt/nfw/core")

from config import store as cfg_store
from config.schema import validate
from modules.ids import suricata
from modules.network.interfaces import resolve_roles

LOG = logging.getLogger("configd.ids")


def _effective_config() -> dict:
    staged = cfg_store.get_staging()
    cfg = dict(staged if staged is not None else cfg_store.read())
    try:
        cfg["_resolved_interfaces"] = resolve_roles(cfg.get("network", {}))
    except Exception:
        pass
    return cfg


def _section(cfg: dict) -> dict:
    s = cfg.setdefault("services", {}).setdefault("ids_config", {})
    s.setdefault("enabled", False)
    s.setdefault("mode", "ids")              # ids | ips
    s.setdefault("interfaces", ["wan"])      # roles
    s.setdefault("home_nets", [])
    s.setdefault("external_net", "!$HOME_NET")
    s.setdefault("rule_paths", ["/var/lib/suricata/rules/suricata.rules"])
    return s


@action("ids.config.get")
def ids_get(_data):
    cfg = _effective_config()
    return {"config": _section(cfg), "status": suricata.status(),
            "rule_count": suricata.rule_count()}


@action("ids.config.set")
def ids_set(data):
    new = data.get("config")
    if not isinstance(new, dict):
        raise ValueError("missing config")
    cfg = _effective_config()
    s = _section(cfg)
    # Merge, but respect explicit false values for booleans
    for k, v in new.items():
        s[k] = v
    # Always stage a valid config
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"staged": True, "config": s}


@action("ids.preview")
def ids_preview(_data):
    cfg = _effective_config()
    return {"config": suricata._render_yaml(cfg)}


@action("ids.apply")
def ids_apply(data):
    cfg = _effective_config()
    return suricata.apply(cfg)


@action("ids.update_rules")
def ids_update_rules(data):
    return suricata.update_rules()


@action("ids.alerts")
def ids_alerts(data):
    return suricata.alerts(
        limit=int(data.get("limit", 100)),
        severity=data.get("severity") or "",
        src=data.get("src") or "",
    )
