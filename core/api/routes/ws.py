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

# ---------------------------------------------------------------------------
# Live firewall log stream
# ---------------------------------------------------------------------------
@router.websocket("/api/firewall/livelog/ws")
async def ws_livelog(ws: WebSocket):
    """Stream firewall log entries over WebSocket.

    Protocol:
      - On connect, sends: {"type": "snapshot", "entries": [...]}
      - Then every 1s:     {"type": "append",   "entries": [...]}
      - Every 30s:         {"type": "ping"}
      - Client sends:      {"filter": {"kind": "...", "scope": "...", "q": "..."}}
        (applied client-side; server always sends all entries)
    """
    if session_from_request(ws) is None:
        await ws.close(code=4401)
        return

    await ws.accept()
    LOG.info("ws livelog: client connected")

    import sys
    sys.path.insert(0, "/opt/nfw")
    from modules.firewall.livelog import reader

    # Initial snapshot — last 100 entries
    try:
        snap = await reader.snapshot(limit=100)
        await ws.send_text(json.dumps({
            "type": "snapshot",
            "entries": snap.get("entries", []),
            "total": snap.get("total", 0),
        }))
    except Exception as e:
        LOG.warning("ws livelog: initial snapshot failed: %s", e)

    last_ts = time.time()
    last_ping = time.time()
    watcher = asyncio.create_task(_recv_watcher(ws))

    try:
        while not watcher.done():
            await asyncio.sleep(1)
            if watcher.done():
                break

            # Push any new entries since last send
            try:
                new_entries = await reader.tail_after(last_ts)
            except Exception as e:
                LOG.warning("ws livelog: tail failed: %s", e)
                new_entries = []

            if new_entries:
                last_ts = new_entries[-1].ts
                try:
                    await ws.send_text(json.dumps({
                        "type": "append",
                        "entries": [e.to_dict() for e in new_entries],
                    }))
                except (WebSocketDisconnect, RuntimeError):
                    break

            # Heartbeat every 30s to keep proxies from closing idle conns
            now = time.time()
            if now - last_ping >= 30:
                try:
                    await ws.send_text(json.dumps({"type": "ping"}))
                except (WebSocketDisconnect, RuntimeError):
                    break
                last_ping = now
    except Exception as e:
        LOG.exception("ws livelog error: %s", e)
    finally:
        if not watcher.done():
            watcher.cancel()
        LOG.info("ws livelog: client disconnected")
