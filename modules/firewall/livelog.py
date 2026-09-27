"""Live firewall log reader.

Spawns `journalctl -k -f` as a subprocess, parses lines matching the NFW
log prefix pattern, and pushes entries into a bounded ring buffer. Exposed
via REST snapshot + (Piece 3) WebSocket stream.

Prefixes parsed:
    NFW-DROP-INPUT:      terminal input policy drop
    NFW-DROP-FORWARD:    terminal forward policy drop
    NFW-DROP-OUTPUT:     terminal output policy drop (not emitted today)
    NFW-DROP-RULE-<id>:  user rule, action=block
    NFW-ACCEPT-RULE-<id>:user rule, action=pass
    NFW-REJECT-RULE-<id>:user rule, action=reject
    NFW-MARTIAN:         martian source packet

Requires `systemd-journal` group membership on the API service user.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from collections import deque
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

LOG = logging.getLogger("firewall.livelog")

RING_SIZE = 5000
PREFIX_RE = re.compile(
    r'NFW-(?P<kind>DROP|ACCEPT|REJECT)-'
    r'(?P<scope>INPUT|FORWARD|OUTPUT|RULE-\d+|MARTIAN):\s*'
)
KV_RE = re.compile(r'([A-Z_]+)=("[^"]*"|\S+)')


@dataclass
class Entry:
    ts: float
    kind: str            # DROP | ACCEPT | REJECT
    scope: str           # INPUT | FORWARD | OUTPUT | RULE-<id> | MARTIAN
    rule_id: Optional[str]
    src: str = ""
    dst: str = ""
    sport: str = ""
    dport: str = ""
    proto: str = ""
    in_if: str = ""
    out_if: str = ""
    mac: str = ""
    raw: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class LiveLogReader:
    def __init__(self) -> None:
        self._ring: deque[Entry] = deque(maxlen=RING_SIZE)
        self._lock = asyncio.Lock()
        self._task: Optional[asyncio.Task] = None
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._total = 0
        self._last_line_ts = 0.0
        self._consecutive_errors = 0

    async def start(self) -> None:
        if self._task is not None:
            return
        self._task = asyncio.create_task(self._run(), name="livelog-reader")
        LOG.info("livelog reader started")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        if self._proc is not None:
            try:
                self._proc.terminate()
            except ProcessLookupError:
                pass
            self._proc = None
        LOG.info("livelog reader stopped")

    async def _run(self) -> None:
        """Supervisor loop — restart journalctl if it dies."""
        while True:
            try:
                await self._read_loop()
                self._consecutive_errors = 0
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self._consecutive_errors += 1
                LOG.warning("livelog reader error (%d): %s",
                            self._consecutive_errors, e)
            # Backoff: 1s, 2s, 4s, max 30s
            delay = min(30, 2 ** min(self._consecutive_errors, 5))
            await asyncio.sleep(delay)

    async def _read_loop(self) -> None:
        self._proc = await asyncio.create_subprocess_exec(
            "journalctl", "-k", "-f", "-o", "short-iso", "--no-pager",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        LOG.info("journalctl subprocess pid=%s", self._proc.pid)

        try:
            assert self._proc.stdout is not None
            async for raw in self._proc.stdout:
                line = raw.decode("utf-8", errors="replace").rstrip("\n")
                entry = self._parse(line)
                if entry is not None:
                    async with self._lock:
                        self._ring.append(entry)
                        self._total += 1
                        self._last_line_ts = entry.ts
        finally:
            if self._proc is not None:
                try:
                    self._proc.terminate()
                except ProcessLookupError:
                    pass
                self._proc = None

    def _parse(self, line: str) -> Optional[Entry]:
        m = PREFIX_RE.search(line)
        if not m:
            return None

        kind = m.group("kind")
        scope = m.group("scope")
        rule_id = None
        if scope.startswith("RULE-"):
            rule_id = scope[5:]
            scope = "RULE"

        ts = time.time()
        # journalctl short-iso prefixes each line with an ISO timestamp.
        # Extract it if present, fallback to now().
        ts_m = re.match(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', line)
        if ts_m:
            try:
                import datetime as _dt
                ts = _dt.datetime.fromisoformat(ts_m.group(1)).timestamp()
            except Exception:
                pass

        kv: dict[str, str] = {}
        for k, v in KV_RE.findall(line[m.end():]):
            kv[k] = v.strip('"')

        return Entry(
            ts=ts,
            kind=kind,
            scope=scope,
            rule_id=rule_id,
            src=kv.get("SRC", ""),
            dst=kv.get("DST", ""),
            sport=kv.get("SPT", ""),
            dport=kv.get("DPT", ""),
            proto=kv.get("PROTO", ""),
            in_if=kv.get("IN", ""),
            out_if=kv.get("OUT", ""),
            mac=kv.get("MAC", ""),
            raw=line,
        )

    async def snapshot(self, limit: int = 200,
                       kind: Optional[str] = None,
                       scope: Optional[str] = None,
                       search: str = "") -> dict[str, Any]:
        async with self._lock:
            items = list(self._ring)

        if kind:
            items = [e for e in items if e.kind == kind.upper()]
        if scope:
            items = [e for e in items if e.scope == scope.upper()]
        if search:
            q = search.lower()
            items = [e for e in items
                     if q in e.src.lower()
                     or q in e.dst.lower()
                     or q in (e.rule_id or "")
                     or q in e.raw.lower()]

        items = items[-limit:]
        items.reverse()  # newest first

        return {
            "entries": [e.to_dict() for e in items],
            "total": self._total,
            "ring_size": RING_SIZE,
            "ring_used": len(self._ring),
            "last_line_ts": self._last_line_ts,
        }

    async def tail_after(self, ts: float, limit: int = 500) -> list[Entry]:
        """Return entries with ts > given timestamp. For WS streaming."""
        async with self._lock:
            items = [e for e in self._ring if e.ts > ts]
        return items[-limit:]


# Singleton
reader = LiveLogReader()
