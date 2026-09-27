"""Squid config generator."""
from __future__ import annotations
import os
import subprocess
from typing import Any

CONF = "/etc/squid/squid.conf"


def _run(cmd: list[str], timeout: int = 20) -> dict:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"rc": r.returncode, "out": r.stdout, "err": r.stderr}
    except subprocess.TimeoutExpired:
        return {"rc": 124, "out": "", "err": "timeout"}
    except FileNotFoundError as e:
        return {"rc": 127, "out": "", "err": str(e)}


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


def _render(config: dict) -> str:
    sq = config.get("services", {}).get("squid_config", {}) or {}
    port = sq.get("port", 3128)
    transparent = sq.get("transparent", False)
    cache_size = sq.get("cache_size_mb", 1000)
    allowed_nets = sq.get("allowed_nets") or ["192.168.0.0/16", "10.0.0.0/8"]
    blocked_domains = sq.get("blocked_domains") or []

    L: list[str] = []
    L.append("# NFW — GENERATED squid.conf. Manual edits will be overwritten.")
    L.append("")
    L.append("visible_hostname nfw-firewall")
    L.append(f"http_port {port}" + (" intercept" if transparent else ""))
    if transparent:
        L.append(f"https_port 3130 intercept ssl-bump "
                 "generate-host-certificates=on dynamic_cert_mem_cache_size=16MB")
    L.append("")
    L.append("# ACLs")
    L.append("acl localnet src " + " ".join(allowed_nets))
    L.append("acl SSL_ports port 443")
    L.append("acl Safe_ports port 80 21 443 70 210 1025-65535 280 488 591 777")
    L.append("acl CONNECT method CONNECT")
    L.append("")

    if blocked_domains:
        L.append("# Blocked domains")
        for i, d in enumerate(blocked_domains):
            L.append(f"acl blocked_domain_{i} dstdomain {d}")
        block_rule = " ".join(f"blocked_domain_{i}" for i in range(len(blocked_domains)))
        L.append(f"http_access deny {block_rule}")
        L.append("")

    L.append("# Access rules")
    L.append("http_access deny !Safe_ports")
    L.append("http_access deny CONNECT !SSL_ports")
    L.append("http_access allow localhost manager")
    L.append("http_access deny manager")
    L.append("http_access allow localnet")
    L.append("http_access allow localhost")
    L.append("http_access deny all")
    L.append("")
    L.append("# Cache")
    L.append(f"cache_dir ufs /var/spool/squid {cache_size} 16 256")
    L.append("coredump_dir /var/spool/squid")
    L.append("refresh_pattern ^ftp:           1440    20%     10080")
    L.append("refresh_pattern ^gopher:        1440    0%      1440")
    L.append("refresh_pattern -i (/cgi-bin/|\\?) 0     0%      0")
    L.append("refresh_pattern .               0       20%     4320")
    L.append("")
    return "\n".join(L)


def apply(config: dict) -> dict:
    sq = config.get("services", {}).get("squid_config", {}) or {}
    enabled = sq.get("enabled", False)

    _write(CONF, _render(config))

    # Validate
    v = _run(["/usr/sbin/squid", "-k", "parse", "-f", CONF])
    if v["rc"] != 0:
        return {"applied": False, "error": v["err"][:500]}

    results = []
    if enabled:
        # Initialize cache dirs on first start
        _run(["/usr/sbin/squid", "-z", "-f", CONF], timeout=60)
        _run(["/usr/bin/systemctl", "enable", "squid"])
        r = _run(["/usr/bin/systemctl", "restart", "squid"])
        results.append({"cmd": "restart", "rc": r["rc"], "err": r["err"][:200]})
    else:
        _run(["/usr/bin/systemctl", "stop", "squid"])
        _run(["/usr/bin/systemctl", "disable", "squid"])
        results.append({"cmd": "disabled", "rc": 0})

    return {"applied": True, "enabled": enabled, "service": results}


def status() -> dict:
    r = _run(["/usr/bin/systemctl", "is-active", "squid"])
    return {"active": r["out"].strip()}
