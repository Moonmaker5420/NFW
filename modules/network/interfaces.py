"""
Interface discovery + logical role mapping.
"""
from __future__ import annotations

import json
import subprocess
from typing import Any

IP = "/usr/sbin/ip"


class InterfaceError(RuntimeError):
    pass


def _run(cmd, timeout=5):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, check=False)
        return p.returncode, p.stdout, p.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return 1, "", str(e)


def list_devices() -> list[dict[str, Any]]:
    rc, out, err = _run([IP, "-j", "link", "show"])
    if rc != 0:
        raise InterfaceError(f"ip link failed: {err}")
    try:
        links = json.loads(out or "[]")
    except json.JSONDecodeError as e:
        raise InterfaceError(f"ip link json: {e}")

    rc2, out2, _ = _run([IP, "-j", "addr", "show"])
    addrs_by_name: dict[str, list[dict[str, Any]]] = {}
    if rc2 == 0:
        try:
            for iface in json.loads(out2 or "[]"):
                name = iface.get("ifname")
                addrs_by_name[name] = [
                    {"family": a.get("family"),
                     "address": a.get("local"),
                     "prefixlen": a.get("prefixlen")}
                    for a in iface.get("addr_info", [])
                ]
        except json.JSONDecodeError:
            pass

    result = []
    for link in links:
        name = link.get("ifname", "")
        if name == "lo":
            continue
        result.append({
            "name": name,
            "state": link.get("operstate", "UNKNOWN"),
            "mac": link.get("address", ""),
            "link_type": link.get("link_type", ""),
            "addrs": addrs_by_name.get(name, []),
        })
    return result


def device_exists(name: str) -> bool:
    if not name:
        return False
    rc, _, _ = _run([IP, "link", "show", name])
    return rc == 0


def default_route_iface() -> str | None:
    rc, out, _ = _run([IP, "-j", "route", "show", "default"])
    if rc != 0 or not out.strip():
        return None
    try:
        routes = json.loads(out)
    except json.JSONDecodeError:
        return None
    for r in routes:
        if r.get("dst") == "default" and "dev" in r:
            return r["dev"]
    return None


def auto_assign() -> dict[str, str]:
    devs = list_devices()
    if not devs:
        raise InterfaceError("no network interfaces found")
    up = [d for d in devs if d["state"] == "UP"]
    pool = up or devs
    wan = default_route_iface()
    if wan is None or wan not in [d["name"] for d in pool]:
        wan = sorted(d["name"] for d in pool)[0]
    remaining = [d["name"] for d in pool if d["name"] != wan]
    if not remaining:
        return {"wan": wan, "lan": wan}
    lan = sorted(remaining)[0]
    opts = sorted([n for n in remaining if n != lan])
    out = {"wan": wan, "lan": lan}
    for i, name in enumerate(opts, start=1):
        out[f"opt{i}"] = name
    return out


def resolve_roles(network_cfg: dict[str, Any]) -> dict[str, str]:
    """
    Resolve logical roles to physical devices.

    Explicit values in network_cfg take precedence. "auto" or empty
    triggers the heuristic. Invalid device names fall back to auto.
    """
    auto = auto_assign()

    def pick(role: str) -> str:
        val = network_cfg.get(role) or "auto"
        if val in ("auto", ""):
            return auto.get(role, auto.get("wan", "auto"))
        # If explicitly set, verify it still exists
        if not device_exists(val):
            return auto.get(role, auto.get("wan", "auto"))
        return val

    out: dict[str, str] = {"wan": pick("wan"), "lan": pick("lan")}

    opt_list = network_cfg.get("opt", []) or []
    for i, entry in enumerate(opt_list, start=1):
        name = f"opt{i}"
        if isinstance(entry, dict):
            dev = entry.get("device") or entry.get("iface") or "auto"
        elif isinstance(entry, str):
            dev = entry or "auto"
        else:
            dev = "auto"
        if dev == "auto" or not dev or not device_exists(dev):
            dev = auto.get(name, dev)
        out[name] = dev

    for k, v in auto.items():
        if k.startswith("opt") and k not in out:
            out[k] = v

    return out


def validate_assignment(network_cfg: dict[str, Any]) -> list[str]:
    """
    Validate a proposed role assignment. Returns a list of errors (empty = OK).
    """
    errors: list[str] = []
    seen: dict[str, str] = {}  # device -> role
    devs = {d["name"]: d for d in list_devices()}

    for role in ("wan", "lan"):
        val = network_cfg.get(role) or "auto"
        if val == "auto":
            continue
        if val not in devs:
            errors.append(f"{role}: device '{val}' does not exist")
            continue
        if val in seen:
            errors.append(f"{role}: device '{val}' already assigned to {seen[val]}")
        seen[val] = role

    opt_list = network_cfg.get("opt", []) or []
    for i, entry in enumerate(opt_list, start=1):
        if isinstance(entry, dict):
            dev = entry.get("device") or entry.get("iface") or "auto"
        else:
            dev = entry or "auto"
        if dev == "auto":
            continue
        if dev not in devs:
            errors.append(f"opt{i}: device '{dev}' does not exist")
            continue
        if dev in seen:
            errors.append(f"opt{i}: device '{dev}' already assigned to {seen[dev]}")
        seen[dev] = f"opt{i}"

    return errors
