"""
Advanced interfaces: VLAN, Bridge, Bond/LAGG, GRE, VXLAN, Loopback.

Design principles (post-incident):
  1. NEVER restart systemd-networkd (breaks live interfaces)
  2. NEVER touch /etc/systemd/network/10-nfw-*.network (interface configs)
  3. Files we own use the 50-nfw- prefix
  4. Create interfaces live with `ip` commands first
  5. Persist via .netdev/.network for boot
  6. Graceful rollback if creation fails
"""
from __future__ import annotations
import os
import re
import subprocess
from typing import Any

NETWORK_DIR = "/etc/systemd/network"
OUR_PREFIX = "50-nfw-"


class IfaceError(ValueError):
    pass


def _run(cmd: list[str], timeout: int = 15) -> dict:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"rc": r.returncode, "out": r.stdout, "err": r.stderr}
    except subprocess.TimeoutExpired:
        return {"rc": 124, "out": "", "err": "timeout"}
    except FileNotFoundError as e:
        return {"rc": 127, "out": "", "err": str(e)}


def _safe(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", s)[:100]


def _write(path: str, content: str, mode: int = 0o644) -> None:
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    except OSError:
        pass
    with open(path, "w") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    try:
        os.chmod(path, mode)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Live interface creation (runtime) — no networkd involvement
# ---------------------------------------------------------------------------
def _live_create(dev: dict) -> dict:
    """Create the interface live using ip commands. Idempotent."""
    kind = dev["kind"]
    name = dev["name"]

    # If it already exists, delete first for clean re-create
    _run(["/usr/sbin/ip", "link", "del", name])

    if kind == "vlan":
        parent = dev.get("parent", "")
        vid = int(dev.get("vlan_id", 0))
        if not parent:
            raise IfaceError("VLAN needs 'parent'")
        r = _run(["/usr/sbin/ip", "link", "add", "link", parent,
                  "name", name, "type", "vlan", "id", str(vid)])
        if r["rc"] != 0:
            raise IfaceError(f"vlan create failed: {r['err'].strip()}")

    elif kind == "bridge":
        members = dev.get("members", []) or []
        r = _run(["/usr/sbin/ip", "link", "add", "name", name, "type", "bridge"])
        if r["rc"] != 0:
            raise IfaceError(f"bridge create failed: {r['err'].strip()}")
        for m in members:
            _run(["/usr/sbin/ip", "link", "set", m, "master", name])
            _run(["/usr/sbin/ip", "link", "set", m, "up"])

    elif kind in ("bond", "lagg"):
        members = dev.get("members", []) or []
        mode = dev.get("mode", "802.3ad")
        r = _run(["/usr/sbin/ip", "link", "add", "name", name, "type", "bond",
                  "mode", mode])
        if r["rc"] != 0:
            raise IfaceError(f"bond create failed: {r['err'].strip()}")
        for m in members:
            _run(["/usr/sbin/ip", "link", "set", m, "master", name])

    elif kind == "gre":
        remote = dev.get("remote", "")
        local = dev.get("local", "")
        if not remote:
            raise IfaceError("GRE needs 'remote'")
        cmd = ["/usr/sbin/ip", "link", "add", "name", name, "type", "gre",
               "remote", remote]
        if local:
            cmd += ["local", local]
        r = _run(cmd)
        if r["rc"] != 0:
            raise IfaceError(f"gre create failed: {r['err'].strip()}")

    elif kind == "vxlan":
        vni = int(dev.get("vni", 0))
        remote = dev.get("remote", "")
        r = _run(["/usr/sbin/ip", "link", "add", "name", name, "type", "vxlan",
                  "id", str(vni), "remote", remote, "dstport", "4789"])
        if r["rc"] != 0:
            raise IfaceError(f"vxlan create failed: {r['err'].strip()}")

    elif kind == "loopback":
        r = _run(["/usr/sbin/ip", "link", "add", "name", name, "type", "dummy"])
        if r["rc"] != 0:
            raise IfaceError(f"loopback create failed: {r['err'].strip()}")

    else:
        raise IfaceError(f"unsupported kind: {kind}")

    # Bring up
    _run(["/usr/sbin/ip", "link", "set", name, "up"])

    # Assign address if configured
    if dev.get("dhcp") and kind in ("vlan", "bridge", "bond", "lagg"):
        # DHCP on the new interface — best effort
        _run(["/usr/sbin/dhclient", "-1", "-v", name], timeout=20)
    elif dev.get("address"):
        _run(["/usr/sbin/ip", "addr", "add", dev["address"], "dev", name])

    return {"created": name}


def _live_delete(dev: dict) -> dict:
    """Delete the interface live."""
    name = dev.get("name", "")
    if not name:
        return {"deleted": None}
    r = _run(["/usr/sbin/ip", "link", "del", name])
    return {"deleted": name, "rc": r["rc"], "err": r["err"].strip()[:200]}


# ---------------------------------------------------------------------------
# Persistence (netdev + network files for boot)
# ---------------------------------------------------------------------------
def _render_netdev(dev: dict) -> str | None:
    kind = dev["kind"]
    name = dev["name"]

    if kind == "vlan":
        return f"""[NetDev]
Name={name}
Kind=vlan

[VLAN]
Id={int(dev['vlan_id'])}
"""

    if kind == "bridge":
        return f"""[NetDev]
Name={name}
Kind=bridge

[Bridge]
STP={'yes' if dev.get('stp', True) else 'no'}
"""

    if kind in ("bond", "lagg"):
        mode = dev.get("mode", "802.3ad")
        return f"""[NetDev]
Name={name}
Kind=bond

[Bond]
Mode={mode}
MIIMonitorSec=1s
"""

    if kind == "gre":
        lines = [f"[NetDev]\nName={name}\nKind=gre\n", "[GRE]"]
        if dev.get("local"):
            lines.append(f"Local={dev['local']}")
        lines.append(f"Remote={dev['remote']}")
        return "\n".join(lines) + "\n"

    if kind == "vxlan":
        return f"""[NetDev]
Name={name}
Kind=vxlan

[VXLAN]
VNI={int(dev['vni'])}
Remote={dev['remote']}
DestinationPort=4789
"""

    if kind == "loopback":
        return f"""[NetDev]
Name={name}
Kind=dummy
"""

    return None


def _render_network(dev: dict) -> str:
    name = dev["name"]
    L = [f"[Match]\nName={name}\n", "[Network]"]
    if dev.get("dhcp"):
        L.append("DHCP=ipv4")
    else:
        L.append("DHCP=no")
        if dev.get("address"):
            L.append(f"Address={dev['address']}")
    return "\n".join(L) + "\n"


def _persist(dev: dict) -> list[str]:
    paths = []
    name = _safe(dev["name"])
    nd = _render_netdev(dev)
    if nd:
        p = f"{NETWORK_DIR}/{OUR_PREFIX}{name}.netdev"
        _write(p, nd)
        paths.append(p)
    p = f"{NETWORK_DIR}/{OUR_PREFIX}{name}.network"
    _write(p, _render_network(dev))
    paths.append(p)
    return paths


def _persisted_names() -> set[str]:
    """Names of advanced interfaces we previously persisted.

    Derived from 50-nfw-*.{netdev,network} files in NETWORK_DIR. Used to
    reconcile runtime state: apply() must delete every live device we own,
    including ones removed from the config since the last apply.
    """
    out: set[str] = set()
    if not os.path.isdir(NETWORK_DIR):
        return out
    for fn in os.listdir(NETWORK_DIR):
        if not fn.startswith(OUR_PREFIX):
            continue
        rest = fn[len(OUR_PREFIX):]
        for suffix in (".netdev", ".network"):
            if rest.endswith(suffix):
                out.add(rest[: -len(suffix)])
                break
    return out


def _clean_our_files() -> list[str]:
    """Remove only files WE created (50-nfw-*)."""
    removed = []
    if not os.path.isdir(NETWORK_DIR):
        return removed
    for fn in os.listdir(NETWORK_DIR):
        if fn.startswith(OUR_PREFIX):
            try:
                os.unlink(os.path.join(NETWORK_DIR, fn))
                removed.append(fn)
            except OSError:
                pass
    return removed


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def apply(config: dict) -> dict:
    """
    Apply all advanced interfaces:
      1. Delete existing advanced interfaces (live)
      2. Clean our persisted files (50-nfw-* only)
      3. Create each enabled interface live
      4. Persist for boot
      5. NEVER restart networkd
    """
    ifaces = config.get("network", {}).get("advanced_interfaces", []) or []

    live_results: list[dict] = []
    persist_paths: list[str] = []
    errors: list[dict] = []

    # Step 1: reconcile live state. Delete every advanced interface we
    # own — both those still wanted (so they get recreated cleanly) and
    # those removed from the config since the last apply. The old code
    # only iterated the current config, so removing the LAST advanced
    # interface left its runtime device up: the loop had nothing to
    # delete, and _clean_our_files() only touches the on-disk files.
    wanted = {_safe(d.get("name", "")) for d in ifaces if d.get("name")}
    previous = _persisted_names()
    removed: list[str] = []
    for name in (previous | wanted):
        try:
            _live_delete({"name": name})
        except Exception:
            pass
        if name not in wanted:
            removed.append(name)

    # Step 2: clean only our persisted files
    _clean_our_files()

    # Step 3+4: create and persist each enabled interface
    for dev in ifaces:
        if not dev.get("enabled", True):
            continue
        try:
            live_results.append(_live_create(dev))
            persist_paths.extend(_persist(dev))
        except IfaceError as e:
            errors.append({"device": dev.get("name", "?"), "error": str(e)})

    return {
        "live": live_results,
        "persisted": persist_paths,
        "removed": removed,
        "errors": errors,
    }


def preview(config: dict) -> dict:
    """Show what would be created + persisted. Never raises."""
    ifaces = config.get("network", {}).get("advanced_interfaces", []) or []
    files: list[dict] = []
    errors: list[dict] = []
    for dev in ifaces:
        if not dev.get("enabled", True):
            continue
        name = dev.get("name", "?")
        try:
            nd = _render_netdev(dev)
            if nd:
                files.append({
                    "device": name, "kind": "netdev",
                    "path": f"{NETWORK_DIR}/{OUR_PREFIX}{_safe(name)}.netdev",
                    "content": nd,
                })
            files.append({
                "device": name, "kind": "network",
                "path": f"{NETWORK_DIR}/{OUR_PREFIX}{_safe(name)}.network",
                "content": _render_network(dev),
            })
        except Exception as e:
            errors.append({"device": name, "error": str(e)})
    return {"files": files, "errors": errors}


def status() -> dict:
    r = _run(["/usr/sbin/ip", "-j", "link", "show"])
    out = []
    try:
        import json
        for l in json.loads(r["out"] or "[]"):
            if l.get("ifname") == "lo":
                continue
            out.append({
                "name": l.get("ifname", ""),
                "kind": l.get("link_type", ""),
                "state": l.get("operstate", ""),
                "mac": l.get("address", ""),
                "mtu": l.get("mtu", 0),
            })
    except Exception:
        pass
    return {"links": out}
