"""
Authorization for configd.

Policy:
  * Socket is root:nfw 0660.
  * SO_PEERCRED gives the caller's UID/GID.
  * Root: full access.
  * nfw user or nfw group: allowed, EXCEPT for ROOT_ONLY_ACTIONS.
  * Anything else: denied.
"""
from __future__ import annotations

import grp
import os
import pwd
import socket
import struct
from dataclasses import dataclass

ROOT_ONLY_ACTIONS = {
    "system.modules",
    "system.modprobe",
    "system.reboot",
    "system.shutdown",
    "system.reload",
    "firewall.apply",
}

ROOT_ONLY_PREFIXES = (
    "system.reboot",
    "system.shutdown",
    "system.power",
)

NFW_USER = "nfw"
NFW_GROUP = "nfw"


@dataclass(frozen=True)
class Peer:
    pid: int
    uid: int
    gid: int

    @property
    def username(self) -> str:
        try:
            return pwd.getpwuid(self.uid).pw_name
        except KeyError:
            return f"uid:{self.uid}"

    @property
    def in_nfw_group(self) -> bool:
        try:
            g = grp.getgrnam(NFW_GROUP).gr_gid
        except KeyError:
            return False
        if self.gid == g:
            return True
        try:
            return g in os.getgrouplist(self.username, self.gid)
        except (KeyError, OSError):
            return False


def get_peer(conn: socket.socket) -> Peer:
    raw = conn.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
    )
    pid, uid, gid = struct.unpack("3i", raw)
    return Peer(pid=pid, uid=uid, gid=gid)


def nfw_uid() -> int:
    try:
        return pwd.getpwnam(NFW_USER).pw_uid
    except KeyError:
        return -1


def nfw_gid() -> int:
    try:
        return grp.getgrnam(NFW_GROUP).gr_gid
    except KeyError:
        return -1


def is_authorized(peer: Peer, action_name: str) -> tuple[bool, str]:
    if peer.uid == 0:
        return True, "root"

    if peer.uid == nfw_uid() or peer.in_nfw_group:
        if action_name in ROOT_ONLY_ACTIONS:
            return False, f"action '{action_name}' requires root"
        for p in ROOT_ONLY_PREFIXES:
            if action_name.startswith(p):
                return False, f"action '{action_name}' requires root"
        return True, f"nfw ({peer.username})"

    return False, f"uid {peer.uid} ({peer.username}) not permitted"
