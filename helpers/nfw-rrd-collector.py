#!/usr/bin/env python3
"""
NFW RRD collector. Runs every minute from a systemd timer.

Writes to /var/lib/nfw/rrd/:
    system.rrd          CPU, mem, load, procs
    conntrack.rrd       conntrack count/max
    disk.rrd            root fs used/total
    if_<iface>.rrd      per-interface throughput + errors + drops
"""
from __future__ import annotations
import logging
import os
import re
import subprocess
import sys
import time
from pathlib import Path

RRD_DIR = Path("/var/lib/nfw/rrd")
LOG = logging.getLogger("rrd.collector")

RRDTOOL = "/usr/bin/rrdtool"


def _run(cmd, timeout=15):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return 1, "", str(e)


def _ensure_rrd(path: Path, ds_lines: list[str], rra_lines: list[str],
                step: int = 60) -> bool:
    """Create the RRD if it doesn't exist. Returns True if it exists (or was created)."""
    if path.exists():
        return True
    args = [RRDTOOL, "create", str(path), "--step", str(step)]
    args += ds_lines
    args += rra_lines
    rc, out, err = _run(args)
    if rc != 0:
        LOG.error("rrdtool create %s failed: %s", path.name, err.strip())
        return False
    os.chmod(path, 0o640)
    return True


def _update(path: Path, values: list[str]) -> bool:
    ts = int(time.time())
    update = f"{ts}:" + ":".join(values)
    rc, out, err = _run([RRDTOOL, "update", str(path), update])
    if rc != 0 and "illegal attempt to update" not in err:
        LOG.warning("rrd update %s failed: %s", path.name, err.strip())
        return False
    return True


# ---------------------------------------------------------------------------
# System
# ---------------------------------------------------------------------------
def collect_system() -> None:
    p = RRD_DIR / "system.rrd"
    ok = _ensure_rrd(p,
        ["DS:cpu_user:DERIVE:120:0:U",
         "DS:cpu_sys:DERIVE:120:0:U",
         "DS:cpu_idle:DERIVE:120:0:U",
         "DS:cpu_iowait:DERIVE:120:0:U",
         "DS:mem_used:GAUGE:120:0:U",
         "DS:mem_total:GAUGE:120:0:U",
         "DS:mem_cache:GAUGE:120:0:U",
         "DS:load1:GAUGE:120:0:U",
         "DS:load5:GAUGE:120:0:U",
         "DS:load15:GAUGE:120:0:U",
         "DS:procs:GAUGE:120:0:U"],
        ["RRA:AVERAGE:0.5:1:1440",
         "RRA:AVERAGE:0.5:5:2016",
         "RRA:AVERAGE:0.5:60:8760",
         "RRA:MAX:0.5:1:1440",
         "RRA:MAX:0.5:5:2016",
         "RRA:MAX:0.5:60:8760"])
    if not ok:
        return

    # CPU from /proc/stat (first line)
    try:
        with open("/proc/stat") as f:
            line = f.readline()
        parts = line.split()
        nums = [int(x) for x in parts[1:9]]
        user, nice, system, idle, iowait, irq, softirq, steal = (nums + [0]*8)[:8]
        cpu_user = user + nice
        cpu_sys = system + irq + softirq
        cpu_idle = idle
        cpu_iowait = iowait
    except Exception as e:
        LOG.warning("cpu read failed: %s", e)
        cpu_user = cpu_sys = cpu_idle = cpu_iowait = 0

    # Mem from /proc/meminfo
    mem_total = mem_free = mem_avail = mem_cached = 0
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    mem_total = int(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    mem_avail = int(line.split()[1])
                elif line.startswith("Cached:"):
                    mem_cached = int(line.split()[1])
        mem_used = mem_total - mem_avail
    except Exception as e:
        LOG.warning("mem read failed: %s", e)
        mem_used = 0

    # Load
    try:
        with open("/proc/loadavg") as f:
            la = f.read().split()
        load1, load5, load15 = float(la[0]), float(la[1]), float(la[2])
    except Exception:
        load1 = load5 = load15 = 0.0

    # Procs
    procs = 0
    try:
        for entry in os.listdir("/proc"):
            if entry.isdigit():
                procs += 1
    except Exception:
        pass

    _update(p, [
        str(cpu_user), str(cpu_sys), str(cpu_idle), str(cpu_iowait),
        str(mem_used), str(mem_total), str(mem_cached),
        f"{load1}", f"{load5}", f"{load15}", str(procs),
    ])


# ---------------------------------------------------------------------------
# Conntrack
# ---------------------------------------------------------------------------
def collect_conntrack() -> None:
    p = RRD_DIR / "conntrack.rrd"
    ok = _ensure_rrd(p,
        ["DS:count:GAUGE:120:0:U",
         "DS:max:GAUGE:120:0:U"],
        ["RRA:AVERAGE:0.5:1:1440",
         "RRA:AVERAGE:0.5:5:2016",
         "RRA:AVERAGE:0.5:60:8760",
         "RRA:MAX:0.5:1:1440",
         "RRA:MAX:0.5:5:2016",
         "RRA:MAX:0.5:60:8760"])
    if not ok:
        return
    count = mx = 0
    try:
        with open("/proc/sys/net/netfilter/nf_conntrack_count") as f:
            count = int(f.read().strip())
    except Exception:
        pass
    try:
        with open("/proc/sys/net/netfilter/nf_conntrack_max") as f:
            mx = int(f.read().strip())
    except Exception:
        pass
    _update(p, [str(count), str(mx)])


# ---------------------------------------------------------------------------
# Disk
# ---------------------------------------------------------------------------
def collect_disk() -> None:
    p = RRD_DIR / "disk.rrd"
    ok = _ensure_rrd(p,
        ["DS:used:GAUGE:600:0:U",
         "DS:total:GAUGE:600:0:U"],
        ["RRA:AVERAGE:0.5:1:288",
         "RRA:AVERAGE:0.5:12:168",
         "RRA:AVERAGE:0.5:288:366"],
        step=300)
    if not ok:
        return
    try:
        st = os.statvfs("/")
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        used = total - free
    except Exception:
        return
    _update(p, [str(used), str(total)])


# ---------------------------------------------------------------------------
# Interfaces
# ---------------------------------------------------------------------------
_SKIP_IFACES = re.compile(r"^(lo|docker\d*|br-.*|veth.*|virbr.*|dummy\d*)$")


def collect_interfaces() -> None:
    try:
        ifaces = os.listdir("/sys/class/net")
    except Exception:
        return
    for iface in ifaces:
        if _SKIP_IFACES.match(iface):
            continue
        base = Path(f"/sys/class/net/{iface}/statistics")
        if not base.is_dir():
            continue
        try:
            rx_bytes = int((base / "rx_bytes").read_text().strip())
            tx_bytes = int((base / "tx_bytes").read_text().strip())
            rx_pkts  = int((base / "rx_packets").read_text().strip())
            tx_pkts  = int((base / "tx_packets").read_text().strip())
            rx_errs  = int((base / "rx_errors").read_text().strip())
            tx_errs  = int((base / "tx_errors").read_text().strip())
            rx_drop  = int((base / "rx_dropped").read_text().strip())
            tx_drop  = int((base / "tx_dropped").read_text().strip())
        except Exception:
            continue

        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", iface)
        p = RRD_DIR / f"if_{safe}.rrd"
        ok = _ensure_rrd(p,
            ["DS:rx_bytes:COUNTER:120:0:U",
             "DS:tx_bytes:COUNTER:120:0:U",
             "DS:rx_pkts:COUNTER:120:0:U",
             "DS:tx_pkts:COUNTER:120:0:U",
             "DS:rx_errs:COUNTER:120:0:U",
             "DS:tx_errs:COUNTER:120:0:U",
             "DS:rx_drop:COUNTER:120:0:U",
             "DS:tx_drop:COUNTER:120:0:U"],
            ["RRA:AVERAGE:0.5:1:1440",
             "RRA:AVERAGE:0.5:5:2016",
             "RRA:AVERAGE:0.5:60:8760",
             "RRA:MAX:0.5:1:1440",
             "RRA:MAX:0.5:5:2016",
             "RRA:MAX:0.5:60:8760"])
        if not ok:
            continue
        _update(p, [str(rx_bytes), str(tx_bytes),
                    str(rx_pkts), str(tx_pkts),
                    str(rx_errs), str(tx_errs),
                    str(rx_drop), str(tx_drop)])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    # Ensure the dir exists
    RRD_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(RRD_DIR, 0o750)
    except OSError:
        pass

    try:
        collect_system()
        collect_conntrack()
        collect_disk()
        collect_interfaces()
    except Exception as e:
        LOG.exception("collector error: %s", e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
