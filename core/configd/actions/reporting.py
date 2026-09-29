"""Reporting actions: graph rendering, top-talkers, netflow control (Phase 9.14)."""
from __future__ import annotations
import base64
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from configd.registry import action

sys.path.insert(0, "/opt/nfw")
sys.path.insert(0, "/opt/nfw/core")

from config import store as cfg_store
from config.schema import validate

LOG = logging.getLogger("configd.reporting")

RRD_DIR = Path("/var/lib/nfw/rrd")
RRDTOOL = "/usr/bin/rrdtool"
SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")

# Range → seconds
RANGES = {
    "hour":  3600,
    "day":   86400,
    "week":  604800,
    "month": 2592000,
    "year":  31536000,
}


def _effective_config() -> dict:
    staged = cfg_store.get_staging()
    return dict(staged if staged is not None else cfg_store.read())


def _run(cmd, timeout=20) -> dict:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"rc": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
    except subprocess.TimeoutExpired:
        return {"rc": 124, "stdout": "", "stderr": "timeout"}
    except FileNotFoundError as e:
        return {"rc": 127, "stdout": "", "stderr": str(e)}


# ============================================================================
# Graph definitions
# ============================================================================
def _defs_system() -> tuple[list[str], str, str]:
    """Return (rrdtool args, title, vlabel)."""
    return (
        [
            "DEF:cpu_user=SYS:system.rrd:cpu_user:AVERAGE",
            "DEF:cpu_sys=SYS:system.rrd:cpu_sys:AVERAGE",
            "DEF:cpu_idle=SYS:system.rrd:cpu_idle:AVERAGE",
            "DEF:cpu_iowait=SYS:system.rrd:cpu_iowait:AVERAGE",
            "CDEF:cpu_busy=cpu_user,cpu_sys,cpu_iowait,+,+",
            "CDEF:cpu_total=cpu_busy,cpu_idle,+",
            "CDEF:cpu_pct=cpu_busy,cpu_total,/,100,*",
            "AREA:cpu_pct#3fb950:CPU busy",
            "GPRINT:cpu_pct:LAST:  last\\: %5.1lf%%",
            "GPRINT:cpu_pct:AVERAGE:  avg\\: %5.1lf%%",
            "GPRINT:cpu_pct:MAX:  max\\: %5.1lf%%\\n",
            "LINE1:cpu_user#58a6ff:user",
            "LINE1:cpu_sys#d29922:system",
            "LINE1:cpu_iowait#f85149:iowait",
        ],
        "CPU utilization",
        "percent",
    )


def _defs_mem() -> tuple[list[str], str, str]:
    return (
        [
            "DEF:used=SYS:system.rrd:mem_used:AVERAGE",
            "DEF:total=SYS:system.rrd:mem_total:AVERAGE",
            "CDEF:used_mb=used,1024,/",
            "CDEF:total_mb=total,1024,/",
            "CDEF:free_mb=total_mb,used_mb,-",
            "AREA:used_mb#58a6ff:used",
            "STACK:free_mb#3fb950:free",
            "GPRINT:used_mb:LAST:  last\\: %6.1lf MiB",
            "GPRINT:used_mb:AVERAGE:  avg\\: %6.1lf MiB",
            "GPRINT:total_mb:MAX:  total\\: %6.1lf MiB\\n",
        ],
        "Memory usage",
        "MiB",
    )


def _defs_load() -> tuple[list[str], str, str]:
    return (
        [
            "DEF:l1=SYS:system.rrd:load1:AVERAGE",
            "DEF:l5=SYS:system.rrd:load5:AVERAGE",
            "DEF:l15=SYS:system.rrd:load15:AVERAGE",
            "LINE1:l1#58a6ff:load 1m",
            "LINE1:l5#d29922:load 5m",
            "LINE1:l15#f85149:load 15m",
            "GPRINT:l1:LAST:  last 1m\\: %5.2lf",
            "GPRINT:l5:LAST:  5m\\: %5.2lf",
            "GPRINT:l15:LAST:  15m\\: %5.2lf\\n",
        ],
        "System load",
        "load",
    )


def _defs_conntrack() -> tuple[list[str], str, str]:
    return (
        [
            "DEF:c=SYS:conntrack.rrd:count:AVERAGE",
            "DEF:m=SYS:conntrack.rrd:max:AVERAGE",
            "AREA:c#58a6ff:count",
            "LINE1:m#f85149:max",
            "GPRINT:c:LAST:  last\\: %6.0lf",
            "GPRINT:c:AVERAGE:  avg\\: %6.0lf",
            "GPRINT:c:MAX:  max\\: %6.0lf\\n",
            "GPRINT:m:LAST:  limit\\: %6.0lf\\n",
        ],
        "Conntrack entries",
        "entries",
    )


def _defs_disk() -> tuple[list[str], str, str]:
    return (
        [
            "DEF:used=SYS:disk.rrd:used:AVERAGE",
            "DEF:total=SYS:disk.rrd:total:AVERAGE",
            "CDEF:used_gb=used,1073741824,/",
            "CDEF:total_gb=total,1073741824,/",
            "CDEF:free_gb=total_gb,used_gb,-",
            "AREA:used_gb#d29922:used",
            "STACK:free_gb#3fb950:free",
            "GPRINT:used_gb:LAST:  last\\: %5.1lf GiB",
            "GPRINT:used_gb:AVERAGE:  avg\\: %5.1lf GiB",
            "GPRINT:total_gb:MAX:  total\\: %5.1lf GiB\\n",
        ],
        "Root filesystem",
        "GiB",
    )


def _defs_iface(iface: str) -> tuple[list[str], str, str]:
    f = f"if_{iface}.rrd"
    return (
        [
            f"DEF:rx=SYS:{f}:rx_bytes:AVERAGE",
            f"DEF:tx=SYS:{f}:tx_bytes:AVERAGE",
            "CDEF:rx_bps=rx,8,*",
            "CDEF:tx_bps=tx,8,*",
            "CDEF:rx_bps_neg=rx_bps,-1,*",
            "CDEF:rx_mbps=rx_bps,1000000,/",
            "CDEF:tx_mbps=tx_bps,1000000,/",
            "CDEF:rx_mbps_neg=rx_mbps,-1,*",
            "AREA:rx_mbps#3fb950:in",
            "LINE1:tx_mbps#58a6ff:out",
            "GPRINT:rx_mbps:LAST:  in last\\: %7.3lf Mbps",
            "GPRINT:rx_mbps:AVERAGE:  avg\\: %7.3lf",
            "GPRINT:rx_mbps:MAX:  max\\: %7.3lf\\n",
            "GPRINT:tx_mbps:LAST:  out last\\: %7.3lf Mbps",
            "GPRINT:tx_mbps:AVERAGE:  avg\\: %7.3lf",
            "GPRINT:tx_mbps:MAX:  max\\: %7.3lf\\n",
        ],
        f"Traffic — {iface}",
        "Mbps",
    )


def _defs_iface_pkts(iface: str) -> tuple[list[str], str, str]:
    f = f"if_{iface}.rrd"
    return (
        [
            f"DEF:rx=SYS:{f}:rx_pkts:AVERAGE",
            f"DEF:tx=SYS:{f}:tx_pkts:AVERAGE",
            "CDEF:rx_pps=rx",
            "CDEF:tx_pps=tx",
            "AREA:rx_pps#3fb950:in",
            "LINE1:tx_pps#58a6ff:out",
            "GPRINT:rx_pps:LAST:  in last\\: %7.1lf pps",
            "GPRINT:rx_pps:AVERAGE:  avg\\: %7.1lf",
            "GPRINT:rx_pps:MAX:  max\\: %7.1lf\\n",
            "GPRINT:tx_pps:LAST:  out last\\: %7.1lf pps",
            "GPRINT:tx_pps:AVERAGE:  avg\\: %7.1lf",
            "GPRINT:tx_pps:MAX:  max\\: %7.1lf\\n",
        ],
        f"Packets — {iface}",
        "pps",
    )


def _defs_iface_errs(iface: str) -> tuple[list[str], str, str]:
    f = f"if_{iface}.rrd"
    return (
        [
            f"DEF:rxe=SYS:{f}:rx_errs:AVERAGE",
            f"DEF:txe=SYS:{f}:tx_errs:AVERAGE",
            f"DEF:rxd=SYS:{f}:rx_drop:AVERAGE",
            f"DEF:txd=SYS:{f}:tx_drop:AVERAGE",
            "LINE1:rxe#f85149:rx errors",
            "LINE1:txe#d29922:tx errors",
            "LINE1:rxd#f85149:rx drops",
            "LINE1:txd#d29922:tx drops",
            "GPRINT:rxe:LAST:  rx_err\\: %5.0lf",
            "GPRINT:txe:LAST:  tx_err\\: %5.0lf",
            "GPRINT:rxd:LAST:  rx_drop\\: %5.0lf",
            "GPRINT:txd:LAST:  tx_drop\\: %5.0lf\\n",
        ],
        f"Errors / drops — {iface}",
        "per second",
    )


GRAPH_DEFS = {
    "system_cpu":        _defs_system,
    "system_mem":        _defs_mem,
    "system_load":       _defs_load,
    "system_conntrack":  _defs_conntrack,
    "system_disk":       _defs_disk,
    # Interface graphs constructed dynamically by suffix
}


def _resolve_graph(name: str):
    """Return (rrd_args, title, vlabel) for a graph name, or None."""
    if name in GRAPH_DEFS:
        return GRAPH_DEFS[name]()
    if name.startswith("if_"):
        rest = name[3:]
        if rest.endswith("_pkts"):
            iface = rest[:-5]
            if SAFE_NAME.match(iface):
                return _defs_iface_pkts(iface)
        elif rest.endswith("_errs"):
            iface = rest[:-5]
            if SAFE_NAME.match(iface):
                return _defs_iface_errs(iface)
        else:
            iface = rest
            if SAFE_NAME.match(iface):
                return _defs_iface(iface)
    return None



def _expand_sys(args: list[str]) -> list[str]:
    """Expand the `SYS:` placeholder in DEF: args to the real RRD dir."""
    prefix = f"{RRD_DIR}/"
    out: list[str] = []
    for a in args:
        if a.startswith("DEF:") and "=SYS:" in a:
            a = a.replace("=SYS:", f"={prefix}", 1)
        out.append(a)
    return out


def _graph_png(name: str, rng: str, width: int = 700,
               height: int = 200) -> bytes:
    """Render a PNG using rrdtool. Returns the PNG bytes."""
    g = _resolve_graph(name)
    if g is None:
        raise ValueError(f"unknown graph: {name}")
    rrd_args, title, vlabel = g

    seconds = RANGES.get(rng)
    if seconds is None:
        raise ValueError(f"unknown range: {rng}")

    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
        out_path = f.name
    try:
        cmd = [
            RRDTOOL, "graph", out_path,
            "--start", f"-{seconds}",
            "--end", "now",
            "--width", str(width),
            "--height", str(height),
            "--title", title,
            "--vertical-label", vlabel,
            "--lower-limit", "0",
            "--slope-mode",
            "--watermark", "NFW",
            "--font", "DEFAULT:9:",
            "--color", "BACK#0d1117",
            "--color", "CANVAS#0d1117",
            "--color", "FONT#c9d1d9",
            "--color", "FONT#8b949e",
            "--color", "AXIS#30363d",
            "--color", "ARROW#8b949e",
            "--color", "GRID#21262d",
            "--color", "MGRID#30363d",
            "--color", "SHADEA#30363d",
            "--color", "SHADEB#30363d",
        ]
        cmd += _expand_sys(rrd_args)
        with tempfile.TemporaryDirectory() as tmpdir:
            r = _run(cmd, timeout=30)
            if r["rc"] != 0:
                raise RuntimeError(f"rrdtool graph failed: {r['stderr'][:300]}")
        with open(out_path, "rb") as f:
            return f.read()
    finally:
        try: os.unlink(out_path)
        except OSError: pass


# ============================================================================
# Actions
# ============================================================================
@action("reporting.status")
def reporting_status(_data):
    cfg = _effective_config()
    r = cfg.get("reporting", {}) or {}
    rrd_files = []
    if RRD_DIR.exists():
        for p in sorted(RRD_DIR.glob("*.rrd")):
            try:
                st = p.stat()
                rrd_files.append({
                    "name": p.name,
                    "size": st.st_size,
                    "mtime": st.st_mtime,
                })
            except OSError:
                continue
    # Current collector state
    sys_status = _run(["/usr/bin/systemctl", "is-active", "nfw-rrd-collector.timer"])
    return {
        "config": r,
        "rrd_dir": str(RRD_DIR),
        "files": rrd_files,
        "collector": sys_status["stdout"].strip(),
    }


@action("reporting.graph_list")
def reporting_graph_list(_data):
    """Return the list of available graph names."""
    names = list(GRAPH_DEFS.keys())
    if RRD_DIR.exists():
        for p in sorted(RRD_DIR.glob("if_*.rrd")):
            iface = p.stem[3:]  # strip if_
            if not SAFE_NAME.match(iface):
                continue
            names.append(f"if_{iface}")
            names.append(f"if_{iface}_pkts")
            names.append(f"if_{iface}_errs")
    return {"graphs": names}


@action("reporting.graph")
def reporting_graph(data):
    """Render a PNG. Returns base64 for transport."""
    name = data.get("name")
    rng = data.get("range", "day")
    width = int(data.get("width", 700))
    height = int(data.get("height", 200))
    if not isinstance(name, str) or not name:
        raise ValueError("missing name")
    if width < 200 or width > 2000 or height < 80 or height > 800:
        raise ValueError("invalid dimensions")
    try:
        png = _graph_png(name, rng, width, height)
    except ValueError:
        raise
    except Exception as e:
        raise RuntimeError(str(e))
    return {"png_b64": base64.b64encode(png).decode()}


# ============================================================================
# Top talkers (from conntrack)
# ============================================================================
_CONN_RE = re.compile(
    r"^(?P<proto>\w+)\s+\d+\s+\d+\s+"
    r"src=(?P<src>[0-9a-fA-F:.]+)\s+dst=(?P<dst>[0-9a-fA-F:.]+)\s+"
    r"sport=(?P<sport>\d+)\s+dport=(?P<dport>\d+)"
)


@action("reporting.top_talkers")
def reporting_top_talkers(data):
    """Aggregate active conntrack entries into top-N lists."""
    limit = int(data.get("limit", 20))
    limit = max(1, min(limit, 200))

    # Prefer iproute2's conntrack tool; falls back to /proc/net/nf_conntrack.
    lines: list[str] = []
    r = _run(["/usr/sbin/conntrack", "-L"], timeout=10)
    if r["rc"] == 0 and r["stdout"]:
        # conntrack -L output: "tcp 6 431999 ESTABLISHED src=... dst=... ..."
        for line in r["stdout"].splitlines():
            lines.append(line)
    else:
        try:
            with open("/proc/net/nf_conntrack") as f:
                lines = f.read().splitlines()
        except OSError:
            return {"by_src": [], "by_dst": [], "by_port": [],
                    "total_flows": 0, "error": "cannot read conntrack"}

    by_src: dict[str, int] = {}
    by_dst: dict[str, int] = {}
    by_port: dict[str, int] = {}     # dport:proto -> count

    for line in lines:
        m = _CONN_RE.match(line)
        if not m:
            continue
        g = m.groupdict()
        by_src[g["src"]] = by_src.get(g["src"], 0) + 1
        by_dst[g["dst"]] = by_dst.get(g["dst"], 0) + 1
        key = f'{g["dport"]}/{g["proto"].lower()}'
        by_port[key] = by_port.get(key, 0) + 1

    def top(d, n):
        return [{"key": k, "count": v}
                for k, v in sorted(d.items(), key=lambda kv: kv[1], reverse=True)[:n]]

    return {
        "by_src": top(by_src, limit),
        "by_dst": top(by_dst, limit),
        "by_port": top(by_port, limit),
        "total_flows": len(lines),
    }


# ============================================================================
# Netflow config + apply (softflowd)
# ============================================================================
NETFLOW_CONF = "/etc/nfw/softflowd.conf"
NETFLOW_SERVICE = "softflowd.service"


def _render_softflowd(cfg: dict) -> str:
    nf = (cfg.get("reporting", {}) or {}).get("netflow", {}) or {}
    target = nf.get("target", "").strip()
    port = int(nf.get("port", 2055))
    proto = nf.get("protocol", "v9")
    ifaces = nf.get("interfaces") or []
    max_flows = int(nf.get("max_flows", 8192))

    ifaces_list = ",".join(ifaces) if ifaces else "any"

    L = []
    L.append("# NFW — GENERATED softflowd config. Do not edit by hand.")
    L.append("")
    L.append(f'OPTIONS="-n {target}:{port} -v {proto[1:]} -m {max_flows} -i {ifaces_list} -t maxlife=300 -D"')
    L.append("")
    return "\n".join(L)


@action("reporting.netflow_status")
def reporting_netflow_status(_data):
    r = _run(["/usr/bin/systemctl", "is-active", NETFLOW_SERVICE])
    active = r["stdout"].strip()
    cfg = _effective_config()
    nf = (cfg.get("reporting", {}) or {}).get("netflow", {}) or {}
    return {"active": active, "config": nf,
            "conf_file": NETFLOW_CONF, "conf_exists": os.path.exists(NETFLOW_CONF)}


@action("reporting.netflow_set")
def reporting_netflow_set(data):
    nf = data.get("netflow")
    if not isinstance(nf, dict):
        raise ValueError("missing netflow")
    cfg = _effective_config()
    rep = cfg.setdefault("reporting", {})
    rep["netflow"] = nf
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"staged": True, "netflow": nf}


@action("reporting.netflow_apply")
def reporting_netflow_apply(_data):
    cfg = _effective_config()
    nf = (cfg.get("reporting", {}) or {}).get("netflow", {}) or {}
    enabled = bool(nf.get("enabled", False))

    # Write the config
    text = _render_softflowd(cfg)
    try:
        os.makedirs(os.path.dirname(NETFLOW_CONF), exist_ok=True)
        with open(NETFLOW_CONF, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(NETFLOW_CONF, 0o644)
    except OSError as e:
        raise RuntimeError(f"cannot write {NETFLOW_CONF}: {e}")

    if not enabled:
        _run(["/usr/bin/systemctl", "stop", NETFLOW_SERVICE])
        _run(["/usr/bin/systemctl", "disable", NETFLOW_SERVICE])
        _run(["/usr/bin/systemctl", "reset-failed", NETFLOW_SERVICE])
        return {"enabled": False, "service": "stopped"}

    if not nf.get("target"):
        raise ValueError("netflow.target required when enabled")

    # softflowd reads its own /etc/default/softflowd on Debian. We overwrite it.
    try:
        with open("/etc/default/softflowd", "w") as f:
            f.write(text)
    except OSError:
        pass

    _run(["/usr/bin/systemctl", "unmask", NETFLOW_SERVICE])
    en = _run(["/usr/bin/env", "SYSTEMCTL_SKIP_SYSV=1",
               "/usr/bin/systemctl", "enable", NETFLOW_SERVICE])
    if en["rc"] != 0:
        LOG.warning("enable %s failed rc=%s err=%s",
                    NETFLOW_SERVICE, en["rc"], (en.get("stderr") or "").strip()[:200])
    r = _run(["/usr/bin/systemctl", "restart", NETFLOW_SERVICE], timeout=20)
    return {"enabled": True, "service_rc": r["rc"], "stderr": r["stderr"][:300]}
