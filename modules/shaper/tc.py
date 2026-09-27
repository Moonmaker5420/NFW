"""
Traffic shaping via `tc`.

Supports:
  - CAKE (modern, easy, bufferbloat-aware) — attach a qdisc to an iface
  - HTB (hierarchical token bucket) — classes + filters

Config schema (in config.services.shaper_config):
{
  "enabled": true,
  "interfaces": [
    {"role": "wan", "download_kbps": 100000, "upload_kbps": 20000,
     "algorithm": "cake", "host_isolate": true}
  ]
}

Apply writes tc commands and runs them. Persist via systemd unit
(similar to our other services).
"""
from __future__ import annotations
import os
import subprocess
from typing import Any

STATE_DIR = "/var/lib/nfw/shaper"
STATE_FILE = f"{STATE_DIR}/state.json"


def _run(cmd: list[str], timeout: int = 15) -> dict:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"rc": r.returncode, "out": r.stdout, "err": r.stderr}
    except subprocess.TimeoutExpired:
        return {"rc": 124, "out": "", "err": "timeout"}
    except FileNotFoundError as e:
        return {"rc": 127, "out": "", "err": str(e)}


def _resolve_iface(config: dict, role: str) -> str:
    resolved = config.get("_resolved_interfaces") or {}
    return resolved.get(role, config.get("network", {}).get(role, role))


def _clear_qdiscs(iface: str) -> None:
    _run(["/sbin/tc", "qdisc", "del", "dev", iface, "root"])


def _apply_cake(iface: str, upload_kbps: int, opts: dict) -> dict:
    """Attach a CAKE qdisc to the interface."""
    _clear_qdiscs(iface)
    bandwidth = f"{upload_kbps}kbit"
    args = ["/sbin/tc", "qdisc", "add", "dev", iface, "root", "cake",
            "bandwidth", bandwidth]
    if opts.get("host_isolate", True):
        args.append("dual-srchost")
    if opts.get("nat", True):
        args.append("nat")
    if opts.get("wash", True):
        args.append("wash")
    return _run(args)


def _apply_htb(iface: str, download_kbps: int, upload_kbps: int) -> dict:
    """Simple HTB: root qdisc + one class at the total rate."""
    _clear_qdiscs(iface)
    r1 = _run(["/sbin/tc", "qdisc", "add", "dev", iface, "root", "handle", "1:",
              "htb", "default", "10"])
    r2 = _run(["/sbin/tc", "class", "add", "dev", iface, "parent", "1:",
              "classid", "1:10", "htb",
              "rate", f"{upload_kbps}kbit", "ceil", f"{upload_kbps}kbit"])
    return {"rc": r1["rc"] or r2["rc"], "r1": r1, "r2": r2}


def apply(config: dict) -> dict:
    sc = config.get("services", {}).get("shaper_config", {}) or {}
    enabled = bool(sc.get("enabled", False))
    ifaces = sc.get("interfaces", []) or []

    results = []
    if not enabled:
        # Clear all known qdiscs
        for it in ifaces:
            iface = _resolve_iface(config, it.get("role", "wan"))
            _clear_qdiscs(iface)
            results.append({"iface": iface, "action": "cleared"})
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(STATE_FILE, "w") as f:
            f.write('{"enabled": false}')
        return {"applied": True, "enabled": False, "results": results}

    for it in ifaces:
        iface = _resolve_iface(config, it.get("role", "wan"))
        algo = (it.get("algorithm") or "cake").lower()
        upload = int(it.get("upload_kbps") or 0)
        download = int(it.get("download_kbps") or 0)

        if upload <= 0:
            results.append({"iface": iface, "error": "upload_kbps required"})
            continue

        if algo == "cake":
            r = _apply_cake(iface, upload, it)
        elif algo == "htb":
            r = _apply_htb(iface, download, upload)
        else:
            results.append({"iface": iface, "error": f"unknown algo {algo}"})
            continue

        results.append({
            "iface": iface,
            "algorithm": algo,
            "upload_kbps": upload,
            "download_kbps": download,
            "rc": r["rc"],
            "err": (r.get("err") or "")[:300],
        })

    # Persist state
    os.makedirs(STATE_DIR, exist_ok=True)
    import json
    with open(STATE_FILE, "w") as f:
        json.dump({
            "enabled": True,
            "interfaces": ifaces,
        }, f, indent=2)

    return {"applied": True, "enabled": True, "results": results}


def status(config: dict) -> dict:
    """Return current qdisc state for each managed interface."""
    sc = config.get("services", {}).get("shaper_config", {}) or {}
    ifaces = sc.get("interfaces", []) or []
    out = []
    for it in ifaces:
        iface = _resolve_iface(config, it.get("role", "wan"))
        r = _run(["/sbin/tc", "-j", "qdisc", "show", "dev", iface])
        out.append({
            "role": it.get("role"),
            "iface": iface,
            "qdisc": r["out"][:800],
            "rc": r["rc"],
        })
    return {"interfaces": out}

# ===========================================================================
# Phase 9.18b5 — Captive-portal per-session bandwidth shaping
# ===========================================================================
#
# Architecture:
#
#   Direction       Target iface    Match field    Direction hint
#   ------------    -----------     -----------    --------------
#   Upload          WAN egress      src_ip         'egress'
#   Download        LAN egress      dst_ip         'ingress'
#
#   HTB class hierarchy (per shaped interface):
#       root: handle CP_HANDLE_UPLOAD (2:) or CP_HANDLE_DOWNLOAD (3:)
#       ├── 1   total rate   (ceil = config total_kbps or 10gbit)
#       ├── 10  default      (unlimited, matches unfiltered traffic)
#       └── 100..114  bucket classes (fixed ladder, reused across clients)
#
#   Per-client filters:
#       u32 match ip src/dst <IP>/32 flowid <handle><bucket_class>
#       Each filter carries a persisted fh (handle) value for O(1) removal.
#
#   State file: /var/lib/nfw/shaper/cp_filters.json
#       { "<iface>": { "<ip>": {"fh": N, "bucket": B, "kbps": K, "dir": "egress" } } }
#
# Coexistence with shaper module:
#   - shaper uses handle 1: for its HTB.
#   - CP uses 2: (WAN) and 3: (LAN) so they never collide.
#   - CP preflight refuses to touch an iface whose root qdisc is not
#     replaceable (mq/fq_codel/pfifo_fast/noqueue) or already ours.
# ===========================================================================
import json as _json


CP_HANDLE_UPLOAD   = "2:"
CP_HANDLE_DOWNLOAD = "3:"
CP_ROOT_CLASS      = "1"
CP_DEFAULT_CLASS   = "10"
CP_BUCKET_BASE     = 100

# Fixed bandwidth ladder (kbps). Clients round UP to the nearest bucket.
CP_BUCKETS_KBPS = [
    256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
    131072, 262144, 524288, 1048576,
]

CP_STATE_FILE = f"{STATE_DIR}/cp_filters.json"


def _cp_load_state() -> dict:
    try:
        with open(CP_STATE_FILE) as f:
            return _json.load(f)
    except Exception:
        return {}


def _cp_save_state(state: dict) -> None:
    os.makedirs(STATE_DIR, exist_ok=True)
    tmp = CP_STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        _json.dump(state, f, indent=2, sort_keys=True)
    os.replace(tmp, CP_STATE_FILE)


def cp_bucket_for_kbps(kbps: int) -> int:
    """Return bucket index (0..N-1) for a kbps value; -1 means 'no limit'."""
    if kbps <= 0:
        return -1
    for i, b in enumerate(CP_BUCKETS_KBPS):
        if b >= kbps:
            return i
    return len(CP_BUCKETS_KBPS) - 1


def cp_class_id(handle: str, bucket_idx: int) -> str:
    return f"{handle}{CP_BUCKET_BASE + bucket_idx}"


def _cp_root_is_replaceable(iface: str, want_handle: str) -> tuple[bool, str]:
    """Return (ok, reason) — ok=True if root qdisc is ours already, or is
    a replaceable default (mq / fq_codel / pfifo_fast / noqueue)."""
    r = _run(["/sbin/tc", "-j", "qdisc", "show", "dev", iface, "root"])
    if r["rc"] != 0:
        return False, f"cannot inspect root qdisc: {r['err'][:120]}"
    try:
        data = _json.loads(r["out"])
    except Exception as e:
        return False, f"cannot parse qdisc json: {e}"
    for entry in data:
        kind = entry.get("kind")
        handle = entry.get("handle")
        if kind in ("mq", "fq_codel", "pfifo_fast", "noqueue", "pfifo"):
            return True, f"replaceable ({kind})"
        if kind == "htb" and handle == want_handle:
            return True, "already ours"
        if kind == "htb":
            return False, f"non-CP HTB on {iface} (handle {handle}) — refusing to clobber"
        return False, f"unexpected qdisc {kind} (handle {handle})"
    return True, "no root qdisc"


def cp_ensure_root(iface: str, handle: str, total_kbps: int = 0) -> dict:
    """Install HTB root + total class + default class + all bucket classes.

    Idempotent: if the root already has our handle, ensures classes exist.
    Returns {'rc': 0|1, 'detail': str, 'installed': bool}.
    """
    ok, reason = _cp_root_is_replaceable(iface, handle)
    if not ok:
        return {"rc": 1, "detail": reason, "installed": False}

    # Only replace the root if it isn't already ours
    r = _run(["/sbin/tc", "-j", "qdisc", "show", "dev", iface, "root"])
    current_handle = ""
    try:
        for entry in _json.loads(r["out"]):
            if entry.get("kind") == "htb":
                current_handle = entry.get("handle") or ""
                break
    except Exception:
        pass

    errors = []
    if current_handle != handle:
        # Wipe existing and install fresh HTB
        _run(["/sbin/tc", "qdisc", "del", "dev", iface, "root"])
        # NB: HTB's 'default' argument takes a MINOR class ID only,
        # not the full handle. So 'default 10', not 'default 3:10'.
        r1 = _run(["/sbin/tc", "qdisc", "add", "dev", iface,
                   "root", "handle", handle, "htb",
                   "default", str(CP_DEFAULT_CLASS)])
        if r1["rc"] != 0:
            errors.append(r1["err"][:200])

    # Total class
    total_rate = f"{total_kbps}kbit" if total_kbps > 0 else "10gbit"
    r2 = _run(["/sbin/tc", "class", "replace", "dev", iface,
               "parent", handle, "classid", f"{handle}{CP_ROOT_CLASS}",
               "htb", "rate", total_rate, "ceil", total_rate])
    if r2["rc"] != 0:
        errors.append(r2["err"][:200])

    # Default class (unlimited)
    r3 = _run(["/sbin/tc", "class", "replace", "dev", iface,
               "parent", f"{handle}{CP_ROOT_CLASS}",
               "classid", f"{handle}{CP_DEFAULT_CLASS}",
               "htb", "rate", total_rate, "ceil", total_rate])
    if r3["rc"] != 0:
        errors.append(r3["err"][:200])

    # Pre-create all bucket classes
    for i, kbps in enumerate(CP_BUCKETS_KBPS):
        cls = cp_class_id(handle, i)
        rb = _run(["/sbin/tc", "class", "replace", "dev", iface,
                   "parent", f"{handle}{CP_ROOT_CLASS}",
                   "classid", cls, "htb",
                   "rate", f"{kbps}kbit", "ceil", f"{kbps}kbit"])
        if rb["rc"] != 0:
            errors.append(f"bucket {i}: {rb['err'][:120]}")

    return {
        "rc": 0 if not errors else 1,
        "detail": "; ".join(errors) if errors else "ok",
        "installed": current_handle != handle,
        "handle": handle,
    }


def cp_remove_root(iface: str, handle: str) -> dict:
    """Remove the CP root qdisc if and only if it's our handle.
    Also clears any persisted filters for this iface."""
    r = _run(["/sbin/tc", "-j", "qdisc", "show", "dev", iface, "root"])
    try:
        entries = _json.loads(r["out"])
    except Exception:
        entries = []
    for entry in entries:
        if entry.get("kind") == "htb" and entry.get("handle") == handle:
            _run(["/sbin/tc", "qdisc", "del", "dev", iface, "root"])
            state = _cp_load_state()
            state.pop(iface, None)
            _cp_save_state(state)
            return {"rc": 0, "removed": True}
    return {"rc": 0, "removed": False, "detail": "not our handle"}


def _cp_alloc_fh(state: dict, iface: str) -> int:
    """Allocate a filter identifier used as tc 'prio' (not 'handle').

    u32 filters use their 'handle' as the internal hash-table slot; sharing
    one handle across many clients causes ENOSPC. Using 'prio' per filter
    avoids the hash-table exhaustion and gives deterministic delete-by-prio.
    """
    used = {v.get("fh", 0) for v in (state.get(iface) or {}).values()}
    for n in range(0x100, 0xFFFF):
        if n not in used:
            return n
    raise RuntimeError("filter priority space exhausted")


def cp_add_client(iface: str, ip: str, kbps: int,
                  handle: str, direction: str) -> dict:
    """Install or update a client's filter.

    direction: 'egress'  → match ip src (upload path, on WAN)
               'ingress' → match ip dst (download path, on LAN)
    """
    import ipaddress
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return {"rc": 1, "detail": f"invalid ip: {ip}"}
    if ip_obj.version != 4:
        return {"rc": 1, "detail": "only ipv4 supported in v1"}

    bucket = cp_bucket_for_kbps(kbps)
    state = _cp_load_state()
    iface_map = state.setdefault(iface, {})

    # Remove any prior filter for this IP
    if ip in iface_map:
        old_fh = iface_map[ip].get("fh")
        if old_fh:
            _run(["/sbin/tc", "filter", "del", "dev", iface,
                  "protocol", "ip", "parent", handle,
                  "prio", str(old_fh)])
        iface_map.pop(ip, None)

    if bucket < 0:
        _cp_save_state(state)
        return {"rc": 0, "detail": "no limit; filter removed", "bucket": -1}

    cls = cp_class_id(handle, bucket)
    fh = _cp_alloc_fh(state, iface)
    match_field = "src" if direction == "egress" else "dst"

    r = _run(["/sbin/tc", "filter", "add", "dev", iface,
              "protocol", "ip", "parent", handle,
              "prio", str(fh),
              "u32", "match", "ip", match_field, f"{ip}/32",
              "flowid", cls])
    if r["rc"] != 0:
        return {"rc": r["rc"], "detail": r["err"][:200]}

    iface_map[ip] = {
        "fh": fh, "bucket": bucket, "kbps": kbps, "dir": direction,
    }
    _cp_save_state(state)
    return {"rc": 0, "bucket": bucket, "kbps": kbps, "class": cls, "fh": fh}


def cp_remove_client(iface: str, ip: str, handle: str) -> dict:
    """Remove the filter for a client's IP, if any."""
    state = _cp_load_state()
    iface_map = state.get(iface, {})
    entry = iface_map.get(ip)
    if not entry:
        return {"rc": 0, "removed": False}
    fh = entry.get("fh")
    if fh:
        _run(["/sbin/tc", "filter", "del", "dev", iface,
              "protocol", "ip", "parent", handle,
              "prio", str(fh)])
    iface_map.pop(ip, None)
    _cp_save_state(state)
    return {"rc": 0, "removed": True}


def cp_list_clients(iface: str) -> dict:
    """Return the persisted filter map for an interface."""
    return _cp_load_state().get(iface, {}) or {}


def cp_clear_all(lan_iface: str, wan_iface: str) -> dict:
    """Remove all CP filters + roots from both interfaces."""
    for iface, handle in ((wan_iface, CP_HANDLE_UPLOAD),
                          (lan_iface, CP_HANDLE_DOWNLOAD)):
        # Remove all filters first (by handle list)
        for ip, entry in (cp_list_clients(iface) or {}).items():
            fh = entry.get("fh")
            if fh:
                _run(["/sbin/tc", "filter", "del", "dev", iface,
                      "protocol", "ip", "parent", handle,
                      "prio", str(fh)])
        cp_remove_root(iface, handle)
    return {"cleared": [wan_iface, lan_iface]}


def cp_class_stats(iface: str, handle: str) -> dict:
    """Parse `tc -s class show` output. Returns {classid: {bytes, pkts, ...}}."""
    r = _run(["/sbin/tc", "-s", "class", "show", "dev", iface])
    if r["rc"] != 0:
        return {}
    out = {}
    current = None
    for line in r["out"].splitlines():
        line = line.rstrip()
        if line.startswith("class htb "):
            # class htb 2:101 parent 2:1 prio 0 rate 1Gbit ceil 1Gbit ...
            parts = line.split()
            if len(parts) >= 3:
                cls = parts[2]
                current = {"classid": cls, "bytes": 0, "pkts": 0}
                out[cls] = current
        elif current is not None and "Sent " in line:
            # " Sent 12345 bytes 678 pkt (dropped 0, overlimits 0 requeues 0)"
            try:
                toks = line.split()
                current["bytes"] = int(toks[1])
                current["pkts"] = int(toks[3])
            except Exception:
                pass
    return out

