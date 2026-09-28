"""Advanced interface actions."""
from __future__ import annotations
import logging
import sys
from typing import Any

from configd.registry import action

sys.path.insert(0, "/opt/nfw")
sys.path.insert(0, "/opt/nfw/core")

from config import store as cfg_store
from config.schema import validate
from modules.interfaces import advanced as adv

LOG = logging.getLogger("configd.interfaces")


def _eff() -> dict:
    staged = cfg_store.get_staging()
    return dict(staged if staged is not None else cfg_store.read())


def _section(cfg: dict) -> list[dict]:
    return cfg.setdefault("network", {}).setdefault("advanced_interfaces", [])


@action("interfaces.advanced.list")
def list_advanced(_data):
    cfg = _eff()
    return {"interfaces": _section(cfg), "status": adv.status()}


@action("interfaces.advanced.add")
def add_advanced(data):
    dev = data.get("interface")
    if not isinstance(dev, dict):
        raise ValueError("missing interface")
    if not dev.get("name"):
        raise ValueError("name required")
    kind = dev.get("kind", "")
    if not kind:
        raise ValueError("kind required")

    cfg = _eff()
    items = _section(cfg)
    if any(x.get("name") == dev["name"] for x in items):
        raise ValueError(f"interface '{dev['name']}' already exists")
    dev.setdefault("enabled", True)
    items.append(dev)
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"interface": dev}


@action("interfaces.advanced.update")
def update_advanced(data):
    name = data.get("name")
    dev = data.get("interface")
    if not name or not isinstance(dev, dict):
        raise ValueError("missing name or interface")
    cfg = _eff()
    items = _section(cfg)
    for i, x in enumerate(items):
        if x.get("name") == name:
            dev["name"] = name
            items[i] = dev
            break
    else:
        raise FileNotFoundError(f"interface '{name}' not found")
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"interface": dev}


@action("interfaces.advanced.delete")
def delete_advanced(data):
    name = data.get("name")
    cfg = _eff()
    items = _section(cfg)
    new = [x for x in items if x.get("name") != name]
    if len(new) == len(items):
        raise FileNotFoundError(f"interface '{name}' not found")
    # Remove from config
    cfg["network"]["advanced_interfaces"] = new
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")

    # Also apply the change (removes the networkd files)
    adv.apply(cfg)
    return {"deleted": name}


@action("interfaces.advanced.preview")
def preview_advanced(_data):
    """Generate preview of networkd config files without writing."""
    try:
        cfg = _eff()
        return adv.preview(cfg)
    except Exception as e:
        LOG.exception("preview failed")
        return {"files": [{"device": "config", "error": f"{type(e).__name__}: {e}"}]}


@action("interfaces.advanced.apply")
def apply_advanced(data):
    cfg = _eff()
    result = adv.apply(cfg)

    # adv.apply returns {"persisted": [...], "live": [...], "errors": [...]}.
    # The GUI reads `written`. Provide both keys for compatibility.
    if isinstance(result, dict) and "written" not in result:
        result["written"] = result.get("persisted", [])

    # Commit staging now that files have been written. Without this,
    # active.json keeps the old config, the GUI table shows the previous
    # state on next reload, and the config store drifts from the actual
    # networkd files on disk. commit_after_apply.
    try:
        staged = cfg_store.get_staging()
        if staged is not None:
            info = cfg_store.commit(
                author=(data or {}).get("author") or "unknown",
                message="advanced interfaces apply",
            )
            if isinstance(result, dict):
                result["revision"] = info.revision
    except Exception as e:
        # Don't fail the whole apply if commit fails — the files are
        # already written and networkd already loaded them. Log loudly
        # so it shows up in journal.
        LOG.error("apply_advanced: commit failed: %s", e)

    return result
