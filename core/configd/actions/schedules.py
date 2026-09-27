"""Schedule CRUD for firewall rules (Phase 9.7a)."""
from __future__ import annotations
import logging
import secrets
import sys
from typing import Any

from configd.registry import action

sys.path.insert(0, "/opt/nfw")
sys.path.insert(0, "/opt/nfw/core")

from config import store as cfg_store
from config.schema import validate

LOG = logging.getLogger("configd.schedules")


def _effective_config() -> dict:
    staged = cfg_store.get_staging()
    return dict(staged if staged is not None else cfg_store.read())


def _validate_ranges(ranges):
    """OPNsense parity: each range must be same-day (start < end).
    Cross-midnight windows require two ranges (22:00-23:59 + 00:00-06:00)."""
    for i, r in enumerate(ranges or []):
        if not isinstance(r, dict):
            raise ValueError(f"range[{i}] must be an object")
        s = r.get("start", "00:00")
        e = r.get("end", "23:59")
        try:
            sh, sm = (int(x) for x in s.split(":"))
            eh, em = (int(x) for x in e.split(":"))
        except (ValueError, TypeError):
            raise ValueError(f"range[{i}]: invalid HH:MM format")
        if (sh, sm) >= (eh, em):
            raise ValueError(
                f"range[{i}]: {s}-{e} crosses midnight (start >= end). "
                f"Split into two ranges, e.g. {s}-23:59 and 00:00-{e}"
            )


def _sched(cfg: dict) -> list:
    return cfg.setdefault("firewall", {}).setdefault("schedules", [])


def _stage(cfg: dict, author: str) -> None:
    validate(cfg)
    cfg_store.stage(cfg, author=author or "unknown")


@action("schedules.list")
def sched_list(_data):
    cfg = _effective_config()
    return {"schedules": _sched(cfg)}


@action("schedules.add")
def sched_add(data):
    s = data.get("schedule")
    if not isinstance(s, dict):
        raise ValueError("missing 'schedule'")
    if not s.get("name"):
        raise ValueError("name required")
    if not isinstance(s.get("ranges"), list) or not s["ranges"]:
        raise ValueError("at least one range required")
    _validate_ranges(s["ranges"])
    _validate_ranges(s["ranges"])
    s.setdefault("id", "sch-" + secrets.token_hex(4))
    s.setdefault("enabled", True)
    s.setdefault("description", "")

    cfg = _effective_config()
    items = _sched(cfg)
    if any(x.get("name") == s["name"] for x in items):
        raise ValueError(f"schedule '{s['name']}' already exists")
    items.append(s)
    _stage(cfg, data.get("author"))
    return {"schedule": s}


@action("schedules.update")
def sched_update(data):
    sid = data.get("id")
    s = data.get("schedule")
    if not sid or not isinstance(s, dict):
        raise ValueError("missing id or schedule")
    cfg = _effective_config()
    items = _sched(cfg)
    for i, x in enumerate(items):
        if x.get("id") == sid:
            s["id"] = sid
            s.setdefault("enabled", x.get("enabled", True))
            s.setdefault("description", x.get("description", ""))
            if any(y.get("name") == s.get("name") and y.get("id") != sid for y in items):
                raise ValueError(f"name '{s['name']}' already used")
            items[i] = s
            break
    else:
        raise FileNotFoundError(f"schedule {sid} not found")
    _stage(cfg, data.get("author"))
    return {"schedule": s}


@action("schedules.delete")
def sched_delete(data):
    sid = data.get("id")
    if not sid:
        raise ValueError("missing id")
    cfg = _effective_config()
    items = _sched(cfg)
    new = [x for x in items if x.get("id") != sid]
    if len(new) == len(items):
        raise FileNotFoundError(f"schedule {sid} not found")
    cfg["firewall"]["schedules"] = new
    _stage(cfg, data.get("author"))
    return {"deleted": sid}


@action("schedules.toggle")
def sched_toggle(data):
    sid = data.get("id")
    cfg = _effective_config()
    items = _sched(cfg)
    for x in items:
        if x.get("id") == sid:
            x["enabled"] = not x.get("enabled", True)
            _stage(cfg, data.get("author"))
            return {"schedule": x}
    raise FileNotFoundError(f"schedule {sid} not found")


@action("schedules.active")
def sched_active(_data):
    """Return which schedules are active right now."""
    import datetime
    cfg = _effective_config()
    items = _sched(cfg)
    now = datetime.datetime.now()
    day_key = ["mon","tue","wed","thu","fri","sat","sun"][now.weekday()]
    hhmm = now.strftime("%H:%M")
    active = []
    for s in items:
        if not s.get("enabled", True):
            continue
        for r in s.get("ranges", []) or []:
            days = r.get("days", [])
            if days and day_key not in days:
                continue
            if r.get("start", "00:00") <= hhmm <= r.get("end", "23:59"):
                active.append(s.get("name"))
                break
    return {"active": active, "now": f"{day_key} {hhmm}"}
