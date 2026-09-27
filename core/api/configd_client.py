"""
Async client for nfw-configd.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

SOCK_PATH = "/run/nfw/configd.sock"
MAX_FRAME = 32 * 1024 * 1024


class ConfigdError(Exception):
    def __init__(self, message: str, code: str = "error"):
        super().__init__(message)
        self.code = code


async def call(action: str, data: dict[str, Any] | None = None,
               timeout: float = 120.0) -> Any:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(SOCK_PATH), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError) as e:
        raise ConfigdError(f"cannot connect to configd: {e}", "unavailable")

    try:
        payload = {"action": action, "data": data or {}}
        writer.write((json.dumps(payload) + "\n").encode("utf-8"))
        await writer.drain()

        buf = bytearray()
        while True:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            if not chunk:
                break
            buf.extend(chunk)
            if len(buf) > MAX_FRAME:
                raise ConfigdError("response too large", "bad_frame")
            if buf.endswith(b"\n"):
                break

        if not buf:
            raise ConfigdError("empty response from configd", "bad_frame")

        resp = json.loads(buf.decode("utf-8"))
        if not resp.get("ok"):
            raise ConfigdError(resp.get("error", "configd error"),
                               resp.get("code", "error"))
        return resp.get("result")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
