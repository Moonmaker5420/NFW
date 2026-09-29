"""Diagnostics actions (Phase 9.8).

Every subprocess uses list-form (no shell), a fixed binary path, and a
hard timeout. Inputs are validated with strict regexes before use.
"""
from __future__ import annotations
import ipaddress
import logging
import os
import re
import signal
import subprocess
import sys
import time
from typing import Any

from configd.registry import action

LOG = logging.getLogger("configd.diagnostics")

PCAP_DIR = "/var/lib/nfw/pcap"
PCAP_PIDFILE = os.path.join(PCAP_DIR, ".current")


# =============================================================================
# Helpers
# =============================================================================
def _run(cmd: list[str], timeout: int = 15) -> dict:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, check=False)
        return {"rc": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
    except subprocess.TimeoutExpired:
        return {"rc": 124, "stdout": "", "stderr": f"timeout after {timeout}s"}
    except FileNotFoundError as e:
        return {"rc": 127, "stdout": "", "stderr": str(e)}


_HOST_RE = re.compile(r"^[A-Za-z0-9._:-]{1,253}$")
_IFACE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,15}$")
_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def _validate_host(h: str) -> str:
    h = (h or "").strip()
    if not h or not _HOST_RE.match(h):
        raise ValueError("invalid host")
    return h


def _validate_iface(i: str) -> str:
    i = (i or "").strip()
    if not i or not _IFACE_RE.match(i):
        raise ValueError("invalid interface")
    return i


def _validate_port(p) -> int:
    try:
        n = int(p)
    except (TypeError, ValueError):
        raise ValueError("invalid port")
    if not (1 <= n <= 65535):
        raise ValueError("port out of range")
    return n


def _validate_filter(f: str) -> str:
    f = (f or "").strip()
    if not f:
        return ""
    if len(f) > 500:
        raise ValueError("filter too long")
    # Reject chars that could be shell metacharacters if the wrapper ever
    # regressed to shell invocation. Cheap defence in depth.
    if any(c in f for c in ";|&$`<>()"):
        raise ValueError("filter contains forbidden characters")
    return f


# =============================================================================
# ping
# =============================================================================
@action("diagnostics.ping")
def diag_ping(data):
    target = _validate_host(data.get("target"))
    try:
        count = int(data.get("count", 4))
    except (TypeError, ValueError):
        count = 4
    count = max(1, min(count, 20))
    family = data.get("family", "auto")
    source = (data.get("source") or "").strip()

    cmd = ["/bin/ping", "-n", "-c", str(count)]
    if family == "ipv4":
        cmd.append("-4")
    elif family == "ipv6":
        cmd.append("-6")
    if source:
        # source must be an IP or interface name
        if not (_IFACE_RE.match(source) or _is_ip(source)):
            raise ValueError("invalid source")
        cmd += ["-I", source]
    cmd.append(target)

    r = _run(cmd, timeout=count * 3 + 5)
    return {
        "command": " ".join(cmd),
        "rc": r["rc"],
        "stdout": r["stdout"],
        "stderr": r["stderr"],
    }


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# =============================================================================
# traceroute
# =============================================================================
@action("diagnostics.traceroute")
def diag_traceroute(data):
    target = _validate_host(data.get("target"))
    try:
        max_hops = int(data.get("max_hops", 20))
    except (TypeError, ValueError):
        max_hops = 20
    max_hops = max(1, min(max_hops, 30))
    family = data.get("family", "auto")

    if not os.path.exists("/usr/bin/traceroute"):
        raise RuntimeError(
            "traceroute not installed. Run: apt install traceroute"
        )

    cmd = ["/usr/bin/traceroute", "-n", "-w", "2", "-q", "1", "-m", str(max_hops)]
    if family == "ipv4":
        cmd.append("-4")
    elif family == "ipv6":
        cmd.append("-6")
    cmd.append(target)

    r = _run(cmd, timeout=max_hops * 4 + 10)
    return {
        "command": " ".join(cmd),
        "rc": r["rc"],
        "stdout": r["stdout"],
        "stderr": r["stderr"],
    }


# =============================================================================
# DNS lookup
# =============================================================================
@action("diagnostics.dns_lookup")
def diag_dns_lookup(data):
    query = _validate_host(data.get("query"))
    qtype = (data.get("type") or "A").upper()
    if qtype not in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR", "ANY"):
        raise ValueError("invalid record type")
    server = (data.get("server") or "").strip()
    cmd = ["/usr/bin/dig", "+short", query, qtype]
    if server:
        if not _is_ip(server):
            raise ValueError("server must be an IP address")
        cmd = ["/usr/bin/dig", f"@{server}", "+short", query, qtype]
    r = _run(cmd, timeout=10)
    return {
        "command": " ".join(cmd),
        "rc": r["rc"],
        "stdout": r["stdout"],
        "stderr": r["stderr"],
    }


# =============================================================================
# Port test (TCP and UDP)
# =============================================================================
@action("diagnostics.port_test")
def diag_port_test(data):
    host = _validate_host(data.get("host"))
    port = _validate_port(data.get("port"))
    proto = (data.get("proto") or "tcp").lower()
    if proto not in ("tcp", "udp"):
        raise ValueError("proto must be tcp or udp")
    try:
        timeout = float(data.get("timeout", 3))
    except (TypeError, ValueError):
        timeout = 3.0
    timeout = max(0.5, min(timeout, 15.0))

    if proto == "tcp":
        cmd = ["/usr/bin/nc", "-z", "-w", str(int(timeout)), host, str(port)]
    else:
        # UDP has no handshake — use nc with -u and rely on ICMP unreachable
        cmd = ["/usr/bin/nc", "-u", "-z", "-w", str(int(timeout)), host, str(port)]

    t0 = time.time()
    r = _run(cmd, timeout=int(timeout) + 3)
    dt = round((time.time() - t0) * 1000)
    return {
        "command": " ".join(cmd),
        "host": host,
        "port": port,
        "proto": proto,
        "rc": r["rc"],
        "stdout": r["stdout"],
        "stderr": r["stderr"],
        "elapsed_ms": dt,
        "open": r["rc"] == 0,
    }


# =============================================================================
# ARP / NDP
# =============================================================================
@action("diagnostics.arp_table")
def diag_arp_table(_data):
    r = _run(["/usr/sbin/ip", "-j", "neigh", "show"], timeout=5)
    return {"rc": r["rc"], "raw": r["stdout"], "stderr": r["stderr"]}


@action("diagnostics.ndp_table")
def diag_ndp_table(_data):
    r = _run(["/usr/sbin/ip", "-6", "-j", "neigh", "show"], timeout=5)
    return {"rc": r["rc"], "raw": r["stdout"], "stderr": r["stderr"]}


# =============================================================================
# Packet capture
# =============================================================================
def _pcap_read_state() -> dict | None:
    if not os.path.exists(PCAP_PIDFILE):
        return None
    try:
        with open(PCAP_PIDFILE) as f:
            pid, name, iface, filt = f.read().split("\t", 3)
        return {"pid": int(pid), "name": name, "iface": iface, "filter": filt}
    except Exception:
        return None


def _pcap_is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


@action("diagnostics.pcap_status")
def diag_pcap_status(_data):
    st = _pcap_read_state()
    if st and _pcap_is_alive(st["pid"]):
        path = os.path.join(PCAP_DIR, st["name"])
        size = os.path.getsize(path) if os.path.exists(path) else 0
        return {"running": True, **st, "size": size, "path": path}
    if st:
        # stale
        try: os.unlink(PCAP_PIDFILE)
        except OSError: pass
    return {"running": False}


@action("diagnostics.pcap_start")
def diag_pcap_start(data):
    if _pcap_read_state() and _pcap_is_alive(_pcap_read_state()["pid"]):
        raise ValueError("a capture is already running")

    iface = _validate_iface(data.get("interface"))
    filt = _validate_filter(data.get("filter") or "")
    try:
        max_sec = int(data.get("max_seconds", 300))
    except (TypeError, ValueError):
        max_sec = 300
    max_sec = max(5, min(max_sec, 3600))
    try:
        max_mb = int(data.get("max_mb", 100))
    except (TypeError, ValueError):
        max_mb = 100
    max_mb = max(1, min(max_mb, 500))

    ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    name = f"capture-{ts}.pcap"
    out = os.path.join(PCAP_DIR, name)

    try:
        proc = subprocess.Popen(
            ["/usr/local/sbin/nfw-pcap-run.sh",
             iface, filt or "ip", str(max_sec), str(max_mb), out],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
    except Exception as e:
        raise RuntimeError(f"could not start tcpdump: {e}")

    with open(PCAP_PIDFILE, "w") as f:
        f.write(f"{proc.pid}\t{name}\t{iface}\t{filt}")

    LOG.info("pcap started pid=%s iface=%s filter=%r name=%s",
             proc.pid, iface, filt, name)

    return {"started": True, "pid": proc.pid, "name": name, "interface": iface,
            "filter": filt, "max_seconds": max_sec, "max_mb": max_mb}


@action("diagnostics.pcap_stop")
def diag_pcap_stop(_data):
    st = _pcap_read_state()
    if not st:
        return {"stopped": False, "reason": "no capture running"}
    pid = st["pid"]
    if _pcap_is_alive(pid):
        # SIGINT is tcpdump's clean shutdown signal — flushes the file properly
        try:
            os.kill(pid, signal.SIGINT)
        except OSError:
            pass
        for _ in range(20):
            time.sleep(0.25)
            if not _pcap_is_alive(pid):
                break
        else:
            try: os.kill(pid, signal.SIGKILL)
            except OSError: pass
    try: os.unlink(PCAP_PIDFILE)
    except OSError: pass
    path = os.path.join(PCAP_DIR, st["name"])
    size = os.path.getsize(path) if os.path.exists(path) else 0
    return {"stopped": True, "name": st["name"], "size": size}


@action("diagnostics.pcap_list")
def diag_pcap_list(_data):
    items = []
    if os.path.isdir(PCAP_DIR):
        for fn in sorted(os.listdir(PCAP_DIR), reverse=True):
            if fn.startswith(".") or not fn.endswith(".pcap"):
                continue
            p = os.path.join(PCAP_DIR, fn)
            try:
                st = os.stat(p)
                items.append({"name": fn, "size": st.st_size,
                              "mtime": st.st_mtime})
            except OSError:
                continue
    return {"captures": items}


@action("diagnostics.pcap_delete")
def diag_pcap_delete(data):
    name = (data.get("name") or "").strip()
    if not _NAME_RE.match(name) or not name.endswith(".pcap"):
        raise ValueError("invalid capture name")
    path = os.path.join(PCAP_DIR, name)
    if not os.path.exists(path):
        raise FileNotFoundError(f"no such capture: {name}")
    os.unlink(path)
    return {"deleted": name}


# =============================================================================
# Restricted command runner
# =============================================================================
_ALLOWED = {
    "date":             ["/bin/date"],
    "uptime":           ["/usr/bin/uptime"],
    "uname":            ["/usr/bin/uname", "-a"],
    "free":             ["/usr/bin/free", "-m"],
    "df":               ["/bin/df", "-h"],
    "ip-addr":          ["/usr/sbin/ip", "addr"],
    "ip-route":         ["/usr/sbin/ip", "route"],
    "ip-rule":          ["/usr/sbin/ip", "rule"],
    "ip-neigh":         ["/usr/sbin/ip", "neigh"],
    "ss-listen":        ["/usr/bin/ss", "-tulnp"],
    "nft-tables":       ["/usr/sbin/nft", "list", "tables"],
    "nft-ruleset":      ["/usr/sbin/nft", "list", "ruleset"],
    "conntrack-count":  ["/usr/sbin/conntrack", "-C"],
    "systemctl-failed": ["/usr/bin/systemctl", "list-units",
                         "--state=failed", "--no-pager"],
    "nfw-configd-log":  ["/usr/bin/journalctl", "-u", "nfw-configd",
                         "-n", "80", "--no-pager"],
    "nfw-api-log":      ["/usr/bin/journalctl", "-u", "nfw-api",
                         "-n", "80", "--no-pager"],
    "miniupnpd-log":    ["/usr/bin/journalctl", "-u", "miniupnpd",
                         "-n", "80", "--no-pager"],
}


@action("diagnostics.commands")
def diag_commands(_data):
    return {"commands": sorted(_ALLOWED.keys())}


@action("diagnostics.command")
def diag_command(data):
    name = data.get("name")
    if name not in _ALLOWED:
        raise ValueError(f"command '{name}' not allowed")
    cmd = _ALLOWED[name]
    r = _run(cmd, timeout=15)
    return {"command": " ".join(cmd), "rc": r["rc"],
            "stdout": r["stdout"], "stderr": r["stderr"]}
