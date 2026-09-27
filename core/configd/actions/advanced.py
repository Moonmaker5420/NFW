"""Advanced feature actions: ACME, HAProxy, Squid, Backup, DDNS, WoL, SNMP."""
from __future__ import annotations
import base64
import logging
import sys
from typing import Any

from configd.registry import action

sys.path.insert(0, "/opt/nfw")
sys.path.insert(0, "/opt/nfw/core")

from config import store as cfg_store
from config.schema import validate
from modules.acme import acme
from modules.haproxy import haproxy
from modules.squid import squid
from modules.backup import backup
from modules.ddns import ddns
from modules.wol import wol
from modules.snmp import snmp

LOG = logging.getLogger("configd.advanced")


def _eff() -> dict:
    staged = cfg_store.get_staging()
    return dict(staged if staged is not None else cfg_store.read())


def _sec(cfg: dict, key: str, default: dict) -> dict:
    s = cfg.setdefault("services", {}).setdefault(key, {})
    for k, v in default.items():
        s.setdefault(k, v)
    return s


# ============ ACME ============
@action("acme.list")
def acme_list(_data):
    return acme.list_certs()


@action("acme.issue")
def acme_issue(data):
    return acme.issue(
        domain=data.get("domain", ""),
        email=data.get("email", ""),
        webroot=data.get("webroot", "/var/www/html"),
        dns_plugin=data.get("dns_plugin", ""),
        dns_credentials=data.get("dns_credentials", ""),
        staging=bool(data.get("staging", False)),
    )


@action("acme.renew")
def acme_renew(data):
    return acme.renew_all(dry_run=bool(data.get("dry_run", False)))


# ============ HAProxy ============
@action("haproxy.config.get")
def haproxy_get(_data):
    cfg = _eff()
    sec = _sec(cfg, "haproxy_config", {
        "enabled": False, "frontends": [], "backends": [],
        "stats_enabled": True, "stats_port": 8404,
    })
    return {"config": sec, "status": haproxy.status()}


@action("haproxy.config.set")
def haproxy_set(data):
    new = data.get("config")
    if not isinstance(new, dict):
        raise ValueError("missing config")
    cfg = _eff()
    sec = _sec(cfg, "haproxy_config", {})
    for k, v in new.items():
        sec[k] = v
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"staged": True, "config": sec}


@action("haproxy.preview")
def haproxy_preview(_data):
    return {"config": haproxy._render(_eff())}


@action("haproxy.apply")
def haproxy_apply(data):
    return haproxy.apply(_eff())


# ============ Squid ============
@action("squid.config.get")
def squid_get(_data):
    cfg = _eff()
    sec = _sec(cfg, "squid_config", {
        "enabled": False, "port": 3128, "transparent": False,
        "cache_size_mb": 1000, "allowed_nets": [], "blocked_domains": [],
    })
    return {"config": sec, "status": squid.status()}


@action("squid.config.set")
def squid_set(data):
    new = data.get("config")
    if not isinstance(new, dict):
        raise ValueError("missing config")
    cfg = _eff()
    sec = _sec(cfg, "squid_config", {})
    for k, v in new.items():
        sec[k] = v
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"staged": True, "config": sec}


@action("squid.preview")
def squid_preview(_data):
    return {"config": squid._render(_eff())}


@action("squid.apply")
def squid_apply(data):
    return squid.apply(_eff())


# ============ Backup ============
@action("backup.export")
def backup_export(_data):
    data_bytes = backup.export_full()
    return {"data_b64": base64.b64encode(data_bytes).decode(),
            "size": len(data_bytes)}


@action("backup.import")
def backup_import(data):
    b64 = data.get("data_b64", "")
    author = data.get("author") or "unknown"
    try:
        raw = base64.b64decode(b64)
    except Exception:
        raise ValueError("invalid base64")
    return backup.import_full(raw, author)


@action("backup.list")
def backup_list(_data):
    return backup.list_backups()


# ============ DDNS ============
@action("ddns.config.get")
def ddns_get(_data):
    cfg = _eff()
    sec = _sec(cfg, "ddns_config", {"entries": []})
    return {"config": sec}


@action("ddns.config.set")
def ddns_set(data):
    new = data.get("config")
    if not isinstance(new, dict):
        raise ValueError("missing config")
    cfg = _eff()
    sec = _sec(cfg, "ddns_config", {})
    for k, v in new.items():
        sec[k] = v
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"staged": True, "config": sec}


@action("ddns.update")
def ddns_update(_data):
    return ddns.update(_eff())


# ============ WoL ============
@action("wol.wake")
def wol_wake(data):
    return wol.wake(data.get("mac", ""), data.get("broadcast", ""))


# ============ SNMP ============
@action("snmp.config.get")
def snmp_get(_data):
    cfg = _eff()
    sec = _sec(cfg, "snmp_config", {
        "enabled": False, "location": "Unknown", "contact": "admin@localhost",
        "communities": [{"name": "public", "access": "ro"}],
        "allowed_nets": ["127.0.0.1"],
    })
    return {"config": sec, "status": snmp.status()}


@action("snmp.config.set")
def snmp_set(data):
    new = data.get("config")
    if not isinstance(new, dict):
        raise ValueError("missing config")
    cfg = _eff()
    sec = _sec(cfg, "snmp_config", {})
    for k, v in new.items():
        sec[k] = v
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"staged": True, "config": sec}


@action("snmp.apply")
def snmp_apply(data):
    return snmp.apply(_eff())
