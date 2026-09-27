"""Network introspection actions — return raw payloads.

The dispatcher wraps everything in {"ok": true, "result": ...}, so actions
must NOT add their own "ok" wrapper.
"""
from __future__ import annotations

import json
import subprocess
from typing import Any

from configd.registry import action

IP = "/usr/sbin/ip"


def _run(cmd: list[str], timeout: int = 10) -> dict[str, Any]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return {"rc": 124, "stdout": "", "stderr": "timeout"}
    except FileNotFoundError as e:
        return {"rc": 127, "stdout": "", "stderr": str(e)}
    return {"rc": p.returncode, "stdout": p.stdout, "stderr": p.stderr}


@action("network.interfaces")
def network_interfaces(_data: dict[str, Any]) -> dict[str, Any]:
    r = _run([IP, "-j", "addr"])
    if r["rc"] != 0:
        raise RuntimeError(f"ip addr failed: {r['stderr']}")
    data = json.loads(r["stdout"] or "[]")
    out = []
    for iface in data:
        addrs = []
        for a in iface.get("addr_info", []):
            addrs.append({
                "family": a.get("family"),
                "local": a.get("local"),
                "prefixlen": a.get("prefixlen"),
                "scope": a.get("scope"),
            })
        out.append({
            "ifname": iface.get("ifname"),
            "operstate": iface.get("operstate"),
            "mac": iface.get("address"),
            "mtu": iface.get("mtu"),
            "addresses": addrs,
        })
    return {"interfaces": out}


@action("network.routes")
def network_routes(_data: dict[str, Any]) -> dict[str, Any]:
    r4 = _run([IP, "-j", "route"])
    r6 = _run([IP, "-j", "-6", "route"])
    if r4["rc"] != 0:
        raise RuntimeError(f"ip route failed: {r4['stderr']}")
    routes = json.loads(r4["stdout"] or "[]")
    routes6 = json.loads(r6["stdout"] or "[]") if r6["rc"] == 0 else []
    return {"routes": routes, "routes6": routes6, "json": r4["stdout"]}


@action("network.neighbors")
def network_neighbors(_data: dict[str, Any]) -> dict[str, Any]:
    r = _run([IP, "-j", "neigh"])
    if r["rc"] != 0:
        raise RuntimeError(f"ip neigh failed: {r['stderr']}")
    return {"neighbors": json.loads(r["stdout"] or "[]")}


@action("network.links")
def network_links(_data: dict[str, Any]) -> dict[str, Any]:
    r = _run([IP, "-j", "link"])
    if r["rc"] != 0:
        raise RuntimeError(f"ip link failed: {r['stderr']}")
    return {"links": json.loads(r["stdout"] or "[]")}


@action("network.conntrack_count")
def network_conntrack_count(_data: dict[str, Any]) -> dict[str, Any]:
    count = mx = 0
    try:
        with open("/proc/sys/net/netfilter/nf_conntrack_count") as f:
            count = int(f.read().strip())
    except OSError:
        pass
    try:
        with open("/proc/sys/net/netfilter/nf_conntrack_max") as f:
            mx = int(f.read().strip())
    except OSError:
        pass
    return {"count": count, "max": mx}
