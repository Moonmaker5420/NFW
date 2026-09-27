#!/usr/bin/env python3
"""Captive portal byte accounting collector (Phase 9.18b5).

Reads tc u32 filter counters, computes deltas, updates sessions table,
writes a rate snapshot for the GUI.

Runs every 30s. Never raises for per-iface failures — logs and continues.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

CP_DIR = Path("/var/lib/nfw/captiveportal")
DB_PATH = CP_DIR / "sessions.db"
FILTERS = Path("/var/lib/nfw/shaper/cp_filters.json")
SNAPSHOT = CP_DIR / "tc_snapshot.json"
CP_STATE_DIR = Path("/var/lib/nfw/shaper")

LAN_HANDLE = "3:"       # download (dst match)
WAN_HANDLE = "2:"       # upload   (src match)

LOG = logging.getLogger("cp-bytes")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler("/var/log/nfw/cp-bytes.log"),
        logging.StreamHandler(),
    ],
)


# --------------------------------------------------------------------------
def _run(cmd, timeout=10):
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
    except Exception as e:
        LOG.warning("cmd failed %s: %s", cmd[:2], e)
        return None


def parse_filter_stats(iface: str) -> dict[int, dict]:
    """Parse `tc -s filter show dev <iface>`.

    Returns {prio_int: {"bytes": N, "pkts": N, "flowid": "3:105"}}.
    Only u32 filters with `Sent` lines contribute.
    """
    r = _run(["/sbin/tc", "-s", "filter", "show", "dev", iface])
    if r is None or r.returncode != 0:
        return {}

    out: dict[int, dict] = {}
    current_prio = None
    current_flowid = ""

    for raw in r.stdout.splitlines():
        line = raw.rstrip()
        s = line.lstrip()

        if s.startswith("filter parent"):
            # "filter parent 3: protocol ip pref 256 u32 chain 0 [fh ...]
            #  [order N key ht X bkt Y] [*flowid 3:105 not_in_hw]"
            current_prio = None
            current_flowid = ""
            toks = s.split()
            try:
                i = toks.index("pref")
                current_prio = int(toks[i + 1])
            except (ValueError, IndexError):
                continue
            # flowid can appear as "flowid X" or "*flowid X" on the SAME line
            for marker in ("*flowid", "flowid"):
                if marker in toks:
                    try:
                        fi = toks.index(marker)
                        current_flowid = toks[fi + 1]
                    except (ValueError, IndexError):
                        pass
                    break
            out.setdefault(current_prio, {"bytes": 0, "pkts": 0,
                                          "flowid": current_flowid})
            if current_flowid:
                out[current_prio]["flowid"] = current_flowid
        elif current_prio is not None and "*flowid" in s:
            # "*flowid 3:105 not_in_hw"
            for tok in s.split():
                if ":" in tok and not tok.startswith("*"):
                    current_flowid = tok
                    out[current_prio]["flowid"] = tok
                    break
        elif current_prio is not None and s.startswith("Sent "):
            # "Sent 12345 bytes 100 pkt (dropped 0, overlimits 0 requeues 0)"
            toks = s.split()
            try:
                out[current_prio]["bytes"] = int(toks[1])
                out[current_prio]["pkts"] = int(toks[3])
            except (ValueError, IndexError):
                pass

    return out


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text())
    except Exception:
        return default


def write_json(path: Path, data) -> None:
    try:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True))
        os.chmod(tmp, 0o660)
        try:
            import grp
            os.chown(tmp, 0, grp.getgrnam("nfw").gr_gid)
        except Exception:
            pass
        os.replace(tmp, path)
    except OSError as e:
        LOG.warning("write %s failed: %s", path, e)


# --------------------------------------------------------------------------
def main() -> int:
    now = time.time()

    # Load the persisted filter map (from tc.py state file)
    filters_by_iface = load_json(FILTERS, {}) or {}
    if not filters_by_iface:
        # Nothing to account for — still refresh the snapshot with empty state
        write_json(SNAPSHOT, {"generated_at": int(now), "ifaces": {}})
        return 0

    # Read the previous snapshot for delta computation
    prev_snapshot = load_json(SNAPSHOT, {}) or {}
    prev_ifaces = prev_snapshot.get("ifaces") or {}

    new_ifaces: dict[str, dict] = {}
    updates_by_ip: dict[str, dict] = {}   # {ip: {"bytes_in": N, "bytes_out": N}}

    for iface, ip_map in filters_by_iface.items():
        stats = parse_filter_stats(iface)
        handle = LAN_HANDLE if iface.endswith("s0") and _is_lan(iface, ip_map) else WAN_HANDLE
        # Simpler: direction comes from the state file entry itself (dir field)
        prev_iface = prev_ifaces.get(iface) or {}
        new_iface: dict[str, dict] = {}

        for ip, entry in ip_map.items():
            prio = entry.get("fh")
            if prio is None:
                continue
            cur = stats.get(prio)
            if cur is None:
                continue
            cur_bytes = int(cur.get("bytes") or 0)

            prev = prev_iface.get(str(prio)) or {}
            prev_bytes = int(prev.get("bytes") or 0)
            prev_ts = float(prev.get("ts") or now)

            if cur_bytes < prev_bytes:
                delta = cur_bytes
                LOG.info("counter reset for %s prio=%d (prev=%d cur=%d)",
                         iface, prio, prev_bytes, cur_bytes)
            else:
                delta = cur_bytes - prev_bytes

            dt = max(1.0, now - prev_ts)
            rate_bps = int(delta * 8 / dt)

            # Direction is authoritative from the state file, not from tc
            # output parsing. Fall back to flowid only if dir is missing.
            dir_ = (entry.get("dir") or "").lower()
            if not dir_:
                flowid = str(cur.get("flowid") or "")
                if flowid.startswith("3:"):
                    dir_ = "ingress"
                elif flowid.startswith("2:"):
                    dir_ = "egress"

            new_iface[str(prio)] = {
                "ip": ip,
                "bytes": cur_bytes,
                "pkts": int(cur.get("pkts") or 0),
                "flowid": cur.get("flowid", ""),
                "dir": dir_,
                "ts": now,
                "delta_bytes": delta,
                "rate_bps": rate_bps,
            }

            if delta > 0:
                bucket = updates_by_ip.setdefault(ip, {"bytes_in": 0, "bytes_out": 0})
                if dir_ == "ingress":
                    bucket["bytes_in"] += delta
                else:
                    bucket["bytes_out"] += delta

        new_ifaces[iface] = new_iface

    # Update sessions DB
    applied = 0
    if updates_by_ip:
        try:
            conn = sqlite3.connect(str(DB_PATH), timeout=5)
            conn.row_factory = sqlite3.Row
            for ip, d in updates_by_ip.items():
                cur = conn.execute(
                    "UPDATE sessions "
                    "SET bytes_in = bytes_in + ?, "
                    "    bytes_out = bytes_out + ?, "
                    "    last_seen_at = ? "
                    "WHERE ip = ? AND revoked_at IS NULL",
                    (d["bytes_in"], d["bytes_out"], int(now), ip),
                )
                if cur.rowcount > 0:
                    applied += 1
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            LOG.warning("DB update failed: %s", e)

    # Persist new snapshot
    write_json(SNAPSHOT, {
        "generated_at": int(now),
        "ifaces": new_ifaces,
    })

    LOG.info("collected: ifaces=%d filters=%d DB-updates=%d",
             len(new_ifaces),
             sum(len(v) for v in new_ifaces.values()),
             applied)
    return 0


def _is_lan(iface: str, ip_map: dict) -> bool:
    """Best-effort: any entry with dir='ingress' means this is the LAN iface."""
    for e in (ip_map or {}).values():
        if (e.get("dir") or "").lower() == "ingress":
            return True
    return False


if __name__ == "__main__":
    sys.exit(main())
