#!/usr/bin/env python3
"""Trigger refresh of due URL/GeoIP aliases via configd."""
from __future__ import annotations
import json, logging, socket, sys

LOG = logging.getLogger("alias-refresh")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s",
                    handlers=[logging.FileHandler("/var/log/nfw/alias-refresh.log"),
                              logging.StreamHandler()])

SOCK = "/run/nfw/configd.sock"
MAX_FRAME = 4 * 1024 * 1024


def call(action: str, data: dict | None = None, timeout: float = 180.0) -> dict:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(SOCK)
        s.sendall((json.dumps({"action": action, "data": data or {}}) + "\n").encode())
        buf = bytearray()
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            buf.extend(chunk)
            if len(buf) > MAX_FRAME:
                raise RuntimeError("response too large")
            if buf.endswith(b"\n"): break
    finally:
        s.close()
    if not buf:
        raise RuntimeError("empty response from configd")
    resp = json.loads(buf.decode())
    if not resp.get("ok"):
        raise RuntimeError(resp.get("error", "configd error"))
    return resp.get("result") or {}


def main() -> int:
    try:
        r = call("firewall.aliases.refresh_due")
        n = r.get("count", 0)
        LOG.info("refresh_due ok: %d alias(es)", n)
        return 0
    except Exception as e:
        LOG.error("refresh_due failed: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
