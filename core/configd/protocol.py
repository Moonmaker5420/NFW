"""
NFW configd wire protocol.

Framing: single-line JSON terminated by '\n'. Requests and responses are
JSON objects. Max frame size is 1 MiB.
"""
from __future__ import annotations

import json
from typing import Any

MAX_FRAME = 32 * 1024 * 1024
ENCODING = "utf-8"


class ProtocolError(Exception):
    """Raised when a frame is malformed or too large."""


def encode(obj: dict[str, Any]) -> bytes:
    return (json.dumps(obj, separators=(",", ":")) + "\n").encode(ENCODING)


def decode(buf: bytes) -> dict[str, Any]:
    if len(buf) > MAX_FRAME:
        raise ProtocolError(f"frame exceeds {MAX_FRAME} bytes")
    try:
        obj = json.loads(buf.decode(ENCODING))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ProtocolError(f"invalid JSON: {e}") from e
    if not isinstance(obj, dict):
        raise ProtocolError("top-level frame must be a JSON object")
    return obj


def ok(result: Any = None) -> dict[str, Any]:
    return {"ok": True, "result": result}


def err(message: str, code: str = "error") -> dict[str, Any]:
    return {"ok": False, "error": message, "code": code}
