"""Notification config + test + send actions."""
from __future__ import annotations

import logging
import sys
from typing import Any

from configd.registry import action

sys.path.insert(0, "/opt/nfw")
sys.path.insert(0, "/opt/nfw/core")

from config import store as cfg_store  # noqa: E402
from config.schema import validate  # noqa: E402
from modules.alerts import dispatcher  # noqa: E402

LOG = logging.getLogger("configd.alerts")


def _active_config() -> dict:
    return cfg_store.read()


@action("alerts.config.get")
def alerts_config_get(_data: dict[str, Any]) -> dict[str, Any]:
    cfg = _active_config()
    return {"config": (cfg.get("services") or {}).get("notifications") or {}}


@action("alerts.config.set")
def alerts_config_set(data: dict[str, Any]) -> dict[str, Any]:
    new = data.get("config")
    if not isinstance(new, dict):
        raise ValueError("missing config")
    staged = cfg_store.get_staging()
    cfg = dict(staged if staged is not None else _active_config())
    svc = cfg.setdefault("services", {})
    svc["notifications"] = new
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    info = cfg_store.commit(author=data.get("author") or "unknown",
                            message="alerts config")
    return {"ok": True, "revision": info.revision}


@action("alerts.test")
def alerts_test(data: dict[str, Any]) -> dict[str, Any]:
    cfg = _active_config()
    to_override = data.get("to_addrs")
    if to_override and isinstance(to_override, str):
        to_override = [to_override]
    return dispatcher.test_smtp(cfg, to_override)


@action("alerts.notify")
def alerts_notify(data: dict[str, Any]) -> dict[str, Any]:
    """Called by the API on events (login failure, etc.)."""
    cfg = _active_config()
    event = (data.get("event") or "").strip()
    if not event:
        raise ValueError("event required")
    return dispatcher.notify(
        cfg,
        event,
        context=data.get("context"),
        subject=data.get("subject") or event.replace("_", " "),
        body=data.get("body") or "",
    )


@action("alerts.history")
def alerts_history(data: dict[str, Any]) -> dict[str, Any]:
    limit = int(data.get("limit") or 50)
    return dispatcher.history(limit=limit)
