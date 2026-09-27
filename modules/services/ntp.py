"""Chrony compiler: config → /etc/chrony/chrony.conf."""
from __future__ import annotations


def compile_chrony(config: dict) -> str:
    svc = config.get("services", {}).get("ntp_config", {}) or {}

    L: list[str] = []
    L.append("# NFW — GENERATED chrony.conf. Do not edit by hand.")
    L.append("")
    L.append("driftfile /var/lib/chrony/chrony.drift")
    L.append("logdir /var/log/chrony")
    L.append("rtcsync")
    L.append("makestep 1.0 3")
    L.append("")

    servers = svc.get("servers") or []
    for s in servers:
        L.append(f"pool {s} iburst")

    mode = svc.get("mode", "client")
    if mode == "server":
        L.append("")
        L.append("# Act as an NTP server for LAN clients")
        L.append("allow 192.168.0.0/16")
        L.append("allow 10.0.0.0/8")
        L.append("allow 172.16.0.0/12")
        for net in svc.get("allow_clients", []) or []:
            if net not in ("192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"):
                L.append(f"allow {net}")
        L.append("local stratum 10")

    L.append("")
    return "\n".join(L)
