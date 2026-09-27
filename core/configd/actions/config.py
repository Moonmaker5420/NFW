"""Config actions — return raw payloads (dispatcher wraps in ok/result)."""
from __future__ import annotations

import json
import logging
import sys
from typing import Any

from configd.registry import action

sys.path.insert(0, "/opt/nfw/core")
from config import hooks as cfg_hooks  # noqa: E402
from config import store as cfg_store  # noqa: E402
from config.schema import (  # noqa: E402
    SchemaError, default_config, merge_defaults, validate,
)

LOG = logging.getLogger("configd.config")


@action("config.read")
def config_read(_data: dict[str, Any]) -> dict[str, Any]:
    cfg = cfg_store.read()
    active = cfg_store.active_revision()
    return {
        "config": cfg,
        "active_revision": active.to_dict() if active else None,
        "staging": cfg_store.get_staging(),
        "staging_meta": cfg_store.get_staging_meta(),
    }


@action("config.defaults")
def config_defaults(_data: dict[str, Any]) -> dict[str, Any]:
    return {"config": default_config()}


@action("config.validate")
def config_validate(data: dict[str, Any]) -> dict[str, Any]:
    cfg = data.get("config")
    if not isinstance(cfg, dict):
        raise ValueError("missing 'config' object")
    try:
        validate(cfg)
    except SchemaError as e:
        raise ValueError(str(e))
    return {"valid": True}


@action("config.stage")
def config_stage(data: dict[str, Any]) -> dict[str, Any]:
    cfg = data.get("config")
    author = data.get("author") or "unknown"
    if not isinstance(cfg, dict):
        raise ValueError("missing 'config'")
    fp = cfg_store.stage(cfg, author=author)
    return {"fingerprint": fp}


@action("config.discard_staging")
def config_discard_staging(_data: dict[str, Any]) -> dict[str, Any]:
    return {"removed": cfg_store.discard_staging()}


@action("config.commit")
def config_commit(data: dict[str, Any]) -> dict[str, Any]:
    author = data.get("author") or "unknown"
    message = data.get("message") or ""
    old = cfg_store.read()
    info = cfg_store.commit(author=author, message=message)
    new = cfg_store.read()
    hooks = cfg_hooks.run_all(old, new)
    LOG.info("config committed rev=%s author=%s hooks=%s",
             info.revision, author, hooks)
    return {"revision": info.to_dict(), "hooks": hooks}


@action("config.rollback")
def config_rollback(data: dict[str, Any]) -> dict[str, Any]:
    revision = data.get("revision")
    author = data.get("author") or "unknown"
    reason = data.get("reason") or ""
    if not isinstance(revision, str) or not revision:
        raise ValueError("missing 'revision'")
    old = cfg_store.read()
    info = cfg_store.rollback(revision, author=author, reason=reason)
    new = cfg_store.read()
    hooks = cfg_hooks.run_all(old, new)
    LOG.info("config rollback to=%s new=%s hooks=%s",
             revision, info.revision, hooks)
    return {"revision": info.to_dict(), "hooks": hooks}


@action("config.revisions")
def config_revisions(data: dict[str, Any]) -> dict[str, Any]:
    limit = int(data.get("limit", 100))
    limit = max(1, min(limit, 1000))
    revs = [r.to_dict() for r in cfg_store.revisions(limit=limit)]
    active = cfg_store.active_revision()
    return {
        "revisions": revs,
        "active": active.to_dict() if active else None,
    }


@action("config.get_revision")
def config_get_revision(data: dict[str, Any]) -> dict[str, Any]:
    revision = data.get("revision")
    if not isinstance(revision, str) or not revision:
        raise ValueError("missing 'revision'")
    path = cfg_store.REVISIONS / f"{revision}.json"
    if not path.exists():
        raise FileNotFoundError(f"revision '{revision}' not found")
    with open(path) as f:
        return {"config": json.load(f)}


@action("config.merge_defaults")
def config_merge_defaults(data: dict[str, Any]) -> dict[str, Any]:
    cfg = data.get("config")
    if not isinstance(cfg, dict):
        raise ValueError("missing 'config'")
    return {"config": merge_defaults(cfg)}


@action("config.read_effective")
def config_read_effective(_data: dict[str, Any]) -> dict[str, Any]:
    """Return the effective config (staging if present, else active)."""
    staged = cfg_store.get_staging()
    cfg = staged if staged is not None else cfg_store.read()
    active = cfg_store.active_revision()
    staging_meta = cfg_store.get_staging_meta()
    return {
        "config": cfg,
        "source": "staging" if staged is not None else "active",
        "active_revision": active.to_dict() if active else None,
        "staging_meta": staging_meta,
    }
