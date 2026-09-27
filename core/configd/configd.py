#!/usr/bin/env python3
"""
nfw-configd — privileged action daemon for NFW.
"""
from __future__ import annotations

import errno
import grp
import os
import signal
import socket
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from configd import __version__  # noqa: E402
from configd import authz, logsetup, protocol, registry  # noqa: E402
from configd.actions import (
    advanced,
    auth_acl,
    auth_oauth,
    auth_providers,
    base,
    ca,
    captiveportal,
    config,
    diagnostics,
    firewall,
    firewall_normalization,
    firewall_rules,
    gateway,
    ids,
    interfaces,
    nat,
    network,
    network_discover,
    network_iface,
    radius,
    reporting,
    schedules,
    service,
    services,
    shaper,
    system,
    users,
    vpn,
    wizard,
)  # noqa: E402  # noqa: E402  # noqa: E402  # noqa: E402  # noqa: E402  # noqa: E402  # noqa: E402  # noqa: E402  # noqa: E402

import logging  # noqa: E402

LOG = logging.getLogger("configd")

SOCK_PATH = Path("/run/nfw/configd.sock")
RUN_DIR = SOCK_PATH.parent
NFW_GROUP = "nfw"
BACKLOG = 32
RECV_CHUNK = 4096


class Server:
    def __init__(self, sock_path: Path) -> None:
        self.sock_path = sock_path
        self.sock: socket.socket | None = None
        self._stop = threading.Event()

    def _bind(self) -> None:
        RUN_DIR.mkdir(parents=True, exist_ok=True)
        # systemd's RuntimeDirectory= creates /run/nfw as root:root 0750
        # because the service runs Group=root. The nfw group needs to be
        # able to traverse this dir to reach the socket, so fix it here.
        try:
            gid = grp.getgrnam(NFW_GROUP).gr_gid
            os.chown(RUN_DIR, 0, gid)
            os.chmod(RUN_DIR, 0o750)
        except KeyError:
            LOG.warning("group '%s' missing; /run/nfw stays root-only", NFW_GROUP)
        try:
            if self.sock_path.exists() or self.sock_path.is_socket():
                self.sock_path.unlink()
        except FileNotFoundError:
            pass
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old_umask = os.umask(0o117)
        try:
            s.bind(str(self.sock_path))
        finally:
            os.umask(old_umask)
        try:
            gid = grp.getgrnam(NFW_GROUP).gr_gid
            os.chown(self.sock_path, 0, gid)
            os.chmod(self.sock_path, 0o660)
        except KeyError:
            LOG.warning("group '%s' missing; socket will be root-only", NFW_GROUP)
            os.chmod(self.sock_path, 0o600)
        s.listen(BACKLOG)
        self.sock = s
        LOG.info("listening on %s (version %s)", self.sock_path, __version__)

    def _read_frame(self, conn: socket.socket) -> bytes:
        buf = bytearray()
        while True:
            chunk = conn.recv(RECV_CHUNK)
            if not chunk:
                if not buf:
                    raise ConnectionError("client closed before sending")
                break
            buf.extend(chunk)
            if len(buf) > protocol.MAX_FRAME:
                raise protocol.ProtocolError("frame exceeds max size")
            if buf.endswith(b"\n"):
                break
        return bytes(buf)

    def _dispatch(self, conn: socket.socket) -> None:
        peer = authz.get_peer(conn)
        log = logging.getLogger(f"configd.peer[{peer.pid}]")
        try:
            raw = self._read_frame(conn)
        except (ConnectionError, protocol.ProtocolError) as e:
            log.warning("bad frame from uid=%s: %s", peer.uid, e)
            conn.sendall(protocol.encode(protocol.err(str(e), "bad_frame")))
            return
        try:
            req = protocol.decode(raw)
        except protocol.ProtocolError as e:
            log.warning("decode error: %s", e)
            conn.sendall(protocol.encode(protocol.err(str(e), "bad_frame")))
            return
        name = req.get("action")
        data = req.get("data") or {}
        if not isinstance(name, str):
            conn.sendall(protocol.encode(protocol.err("missing action", "bad_request")))
            return
        if not isinstance(data, dict):
            conn.sendall(protocol.encode(protocol.err("data must be object", "bad_request")))
            return
        allowed, reason = authz.is_authorized(peer, name)
        if not allowed:
            log.warning("DENY action=%s uid=%s (%s)", name, peer.uid, reason)
            conn.sendall(protocol.encode(protocol.err(f"unauthorized: {reason}", "forbidden")))
            return
        try:
            fn = registry.get(name)
        except registry.UnknownAction:
            log.warning("unknown action=%s", name)
            conn.sendall(protocol.encode(protocol.err(f"unknown action '{name}'", "unknown_action")))
            return
        try:
            result = fn(data)
        except Exception as e:
            log.exception("action %s raised", name)
            conn.sendall(protocol.encode(protocol.err(f"{type(e).__name__}: {e}", "action_error")))
            return
        log.info("OK action=%s uid=%s", name, peer.uid)
        conn.sendall(protocol.encode(protocol.ok(result)))

    def _handle(self, conn: socket.socket) -> None:
        with conn:
            try:
                self._dispatch(conn)
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception:
                LOG.exception("unhandled error in handler")

    def serve_forever(self) -> None:
        self._bind()
        assert self.sock is not None
        self.sock.settimeout(1.0)
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError as e:
                if e.errno == errno.EINTR:
                    continue
                if self._stop.is_set() or e.errno == errno.EBADF:
                    # Socket closed by shutdown() while we were in accept().
                    break
                raise
            t = threading.Thread(target=self._handle, args=(conn,), daemon=True)
            t.start()

    def shutdown(self, *_a) -> None:
        LOG.info("shutdown requested")
        self._stop.set()
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
        try:
            self.sock_path.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    logsetup.setup()
    log = logging.getLogger("configd")
    log.info("nfw-configd %s starting (uid=%d)", __version__, os.getuid())
    if os.getuid() != 0:
        log.error("must run as root")
        return 1
    srv = Server(SOCK_PATH)
    signal.signal(signal.SIGTERM, srv.shutdown)
    signal.signal(signal.SIGINT, srv.shutdown)
    # SIGHUP: reload hint. Currently a no-op (actions are already
    # imported), but crucially it must not terminate the daemon.
    signal.signal(signal.SIGHUP, lambda *_: log.info("SIGHUP received (no-op)"))
    try:
        srv.serve_forever()
    except Exception:
        log.exception("fatal")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
