"""Base actions."""
from __future__ import annotations

import os
import platform
import shutil
import time
from typing import Any

from configd import __version__
from configd.registry import action, names

START_TIME = time.time()


@action("core.ping")
def core_ping(_data: dict[str, Any]) -> dict[str, Any]:
    return {"pong": True, "ts": time.time()}


@action("core.version")
def core_version(_data: dict[str, Any]) -> dict[str, Any]:
    return {
        "version": __version__,
        "python": platform.python_version(),
        "kernel": platform.release(),
        "uptime_s": int(time.time() - START_TIME),
    }


@action("core.actions")
def core_actions(_data: dict[str, Any]) -> dict[str, Any]:
    return {"actions": names()}


@action("core.health")
def core_health(_data: dict[str, Any]) -> dict[str, Any]:
    du = shutil.disk_usage("/")
    return {
        "pid": os.getpid(),
        "uptime_s": int(time.time() - START_TIME),
        "disk_total": du.total,
        "disk_used": du.used,
        "disk_free": du.free,
    }
