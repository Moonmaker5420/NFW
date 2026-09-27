"""WebSocket routes — live stats."""
from __future__ import annotations

import asyncio
import json
import logging
import time

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..auth import session_from_request
from ..configd_client import ConfigdError, call as configd_call

LOG = logging.getLogger("api.ws")
router = APIRouter()


def _read_cpu_sample() -> tuple[int, int]:
    """Return (idle_jiffies, total_jiffies) from /proc/stat."""
    try:
        with open("/proc/stat", "r") as f:
            line = f.readline()
    except OSError:
        return 0, 0
    parts = line.split()
    if len(parts) < 5:
        return 0, 0
    nums = [int(x) for x in parts[1:9]]
    idle = nums[3] + (nums[4] if len(nums) > 4 else 0)
    total = sum(nums)
    return idle, total


def _read_mem() -> tuple[int, int]:
    """Return (used_kB, total_kB) from /proc/meminfo."""
    used = total = 0
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    total = int(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    used = total - int(line.split()[1])
                if total and used:
                    break
    except OSError:
        pass
    return used, total


def _read_conntrack() -> tuple[int, int]:
    count = mx = 0
    try:
        with open("/proc/sys/net/netfilter/nf_conntrack_count", "r") as f:
            count = int(f.read().strip())
    except OSError:
        pass
    try:
        with open("/proc/sys/net/netfilter/nf_conntrack_max", "r") as f:
            mx = int(f.read().strip())
    except OSError:
        pass
    return count, mx


async def _collect() -> dict:
    used, total = _read_mem()
    count, mx = _read_conntrack()
    return {
        "ts": time.time(),
        "mem_used": used,
        "mem_total": total,
        "conntrack_count": count,
        "conntrack_max": mx,
    }



async def _recv_watcher(ws: WebSocket) -> None:
    """Drain incoming frames until the client disconnects.

    WebSocketDisconnect is only raised by receive(), never send(). Without
    a concurrent receive loop, a client that closes the socket leaves the
    send loop alive and the next send_text() raises RuntimeError
    ('Unexpected ASGI message websocket.send after websocket.close').
    """
    try:
        while True:
            await ws.receive()
    except Exception:
        return


@router.websocket("/api/ws/stats")
async def ws_stats(ws: WebSocket):
    # Authenticate via cookie
    if session_from_request(ws) is None:
        await ws.close(code=4401)
        return

    await ws.accept()
    LOG.info("ws stats: client connected")

    prev_idle, prev_total = _read_cpu_sample()

    watcher = asyncio.create_task(_recv_watcher(ws))
    try:
        while not watcher.done():
            await asyncio.sleep(2)
            if watcher.done():
                break
            idle, total = _read_cpu_sample()
            d_idle = idle - prev_idle
            d_total = total - prev_total
            prev_idle, prev_total = idle, total
            cpu_pct = 100.0 * (1.0 - d_idle / d_total) if d_total > 0 else 0.0

            payload = await _collect()
            payload["cpu_pct"] = round(cpu_pct, 1)
            try:
                await ws.send_text(json.dumps(payload))
            except (WebSocketDisconnect, RuntimeError):
                break
    except Exception as e:
        LOG.exception("ws error: %s", e)
    finally:
        if not watcher.done():
            watcher.cancel()
        try:
            await ws.close()
        except Exception:
            pass
    LOG.info("ws stats: client disconnected")
