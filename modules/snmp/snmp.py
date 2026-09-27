"""SNMP config generator."""
from __future__ import annotations
import os
import subprocess

CONF = "/etc/snmp/snmpd.conf"


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
    snmp = config.get("services", {}).get("snmp_config", {}) or {}
    location = snmp.get("location", "Unknown")
    contact = snmp.get("contact", "admin@localhost")
    communities = snmp.get("communities") or [{"name": "public", "access": "ro"}]
    allowed_nets = snmp.get("allowed_nets") or ["127.0.0.1"]

    L = []
    L.append("# NFW — GENERATED snmpd.conf")
    L.append(f"sysLocation {location}")
    L.append(f"sysContact {contact}")
    L.append("sysServices 72")
    L.append("")
    for c in communities:
        L.append(f"rocommunity {c['name']} " + " ".join(allowed_nets) +
                 ("" if c["access"] == "ro" else " -V systemonly"))
    L.append("")
    L.append("includeAllDisks 10%")
    L.append("")
    return "\n".join(L)


def apply(config: dict) -> dict:
    snmp = config.get("services", {}).get("snmp_config", {}) or {}
    enabled = snmp.get("enabled", False)
    _write(CONF, _render(config))

    results = []
    if enabled:
        subprocess.run(["/usr/bin/systemctl", "enable", "snmpd"],
                       capture_output=True)
        r = subprocess.run(["/usr/bin/systemctl", "restart", "snmpd"],
                           capture_output=True, text=True)
        results.append({"cmd": "restart", "rc": r.returncode, "err": r.stderr[:200]})
    else:
        subprocess.run(["/usr/bin/systemctl", "stop", "snmpd"],
                       capture_output=True)
        subprocess.run(["/usr/bin/systemctl", "disable", "snmpd"],
                       capture_output=True)
    return {"applied": True, "enabled": enabled, "service": results}


def status() -> dict:
    r = subprocess.run(["/usr/bin/systemctl", "is-active", "snmpd"],
                       capture_output=True, text=True)
    return {"active": r.stdout.strip()}
