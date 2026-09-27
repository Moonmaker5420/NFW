"""System actions."""
from __future__ import annotations

import socket
import os
import platform
import shutil
import time
from typing import Any

from configd.registry import action

UPTIME_FILE = "/proc/uptime"
MEMINFO_FILE = "/proc/meminfo"
LOADAVG_FILE = "/proc/loadavg"


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""


@action("system.info")
def system_info(_data: dict[str, Any]) -> dict[str, Any]:
    du = shutil.disk_usage("/")
    u = _read(UPTIME_FILE)
    return {
        "hostname": socket.gethostname(),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "python": platform.python_version(),
        "uptime_s": float(u.split()[0]) if u else 0.0,
        "loadavg": _read(LOADAVG_FILE).strip().split()[:3],
        "disk": {"total": du.total, "used": du.used, "free": du.free},
    }


@action("system.meminfo")
def system_meminfo(_data: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, int] = {}
    for line in _read(MEMINFO_FILE).splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            v = v.strip().split()[0]
            try:
                out[k] = int(v)
            except ValueError:
                continue
    return out


@action("system.uptime")
def system_uptime(_data: dict[str, Any]) -> dict[str, Any]:
    u = _read(UPTIME_FILE)
    return {"seconds": float(u.split()[0]) if u else 0.0}


@action("system.time")
def system_time(_data: dict[str, Any]) -> dict[str, Any]:
    return {
        "unix": time.time(),
        "iso": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "tz": time.tzname,
    }


@action("system.logs")
def system_logs(data: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "configd": "/var/log/nfw/configd.log",
        "syslog": "/var/log/syslog",
        "nftables": "/var/log/nftables.log",
        "auth": "/var/log/auth.log",
    }
    key = data.get("file", "configd")
    if key not in allowed:
        raise ValueError(f"file '{key}' not permitted")
    n = int(data.get("lines", 100))
    n = max(1, min(n, 2000))
    path = allowed[key]
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            block = min(size, 128 * 1024)
            f.seek(size - block)
            data_bytes = f.read()
        lines = data_bytes.decode("utf-8", errors="replace").splitlines()[-n:]
    except FileNotFoundError:
        lines = []
    return {"file": path, "lines": lines}
