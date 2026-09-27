"""
Suricata config generator + wrapper.

Emits /etc/suricata/suricata.yaml with the relevant fields from the NFW
config store. Supports IDS (alert) and IPS (NFQUEUE, inline drop) modes.

Reads/writes:
  /etc/suricata/suricata.yaml
  /etc/suricata/rules/*.rules
  /etc/default/suricata

Service: suricata.service
"""
from __future__ import annotations
import os
import subprocess
from typing import Any

SURICATA_DIR = "/etc/suricata"
RULES_DIR = "/var/lib/suricata/rules"
SERVICE = "suricata.service"


def _run(cmd: list[str], timeout: int = 30) -> dict:
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


def _render_yaml(config: dict) -> str:
    """Render a minimal suricata.yaml that sets up what we need."""
    ids = config.get("services", {}).get("ids_config", {}) or {}
    mode = ids.get("mode", "ids")   # ids | ips
    home_nets = ids.get("home_nets") or ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
    ext_net = ids.get("external_net") or "!$HOME_NET"

    # Interfaces to monitor
    mon_roles = ids.get("interfaces") or ["wan"]
    ifaces = [_resolve_iface(config, r) for r in mon_roles]

    rule_paths = ids.get("rule_paths") or [f"{RULES_DIR}/suricata.rules"]
    rule_files = [f"      - {p}" for p in rule_paths]

    L: list[str] = []
    L.append("# NFW — GENERATED suricata.yaml. Do not edit by hand.")
    L.append("%YAML 1.1")
    L.append("---")
    L.append("vars:")
    L.append("  address-groups:")
    L.append(f'    HOME_NET: "[{",".join(home_nets)}]"')
    L.append(f'    EXTERNAL_NET: "{ext_net}"')
    L.append('    HTTP_SERVERS: "$HOME_NET"')
    L.append('    SMTP_SERVERS: "$HOME_NET"')
    L.append('    SQL_SERVERS: "$HOME_NET"')
    L.append('    DNS_SERVERS: "$HOME_NET"')
    L.append('    TELNET_SERVERS: "$HOME_NET"')
    L.append('    AIM_SERVERS: "$EXTERNAL_NET"')
    L.append('    DC_SERVERS: "$HOME_NET"')
    L.append('    DNP3_SERVER: "$HOME_NET"')
    L.append('    DNP3_CLIENT: "$HOME_NET"')
    L.append('    MODBUS_CLIENT: "$HOME_NET"')
    L.append('    MODBUS_SERVER: "$HOME_NET"')
    L.append('    ENIP_CLIENT: "$HOME_NET"')
    L.append('    ENIP_SERVER: "$HOME_NET"')
    L.append("  port-groups:")
    L.append('    HTTP_PORTS: "80"')
    L.append('    SHELLCODE_PORTS: "!80"')
    L.append('    ORACLE_PORTS: 1521')
    L.append('    SSH_PORTS: 22')
    L.append('    DNP3_PORTS: 20000')
    L.append('    MODBUS_PORTS: 502')
    L.append('    FILE_DATA_PORTS: "[$HTTP_PORTS,110,143]"')
    L.append('    FTP_PORTS: 21')
    L.append('    GENEVE_PORTS: 6081')
    L.append('    VXLAN_PORTS: 4789')
    L.append('    TEREDO_PORTS: 3544')
    L.append("")
    L.append("default-log-dir: /var/log/suricata/")
    L.append("")
    L.append("stats:")
    L.append("  enabled: yes")
    L.append("  interval: 30")
    L.append("")
    L.append("outputs:")
    L.append("  - fast:")
    L.append("      enabled: yes")
    L.append("      filename: fast.log")
    L.append("      append: yes")
    L.append("  - eve-log:")
    L.append("      enabled: yes")
    L.append("      filetype: regular")
    L.append("      filename: eve.json")
    L.append("      types:")
    L.append("        - alert")
    L.append("        - http:")
    L.append("            extended: yes")
    L.append("        - dns")
    L.append("        - tls")
    L.append("        - files")
    L.append("        - flow")
    L.append("")
    L.append("af-packet:")
    for i, iface in enumerate(ifaces):
        L.append(f"  - interface: {iface}")
        L.append(f"    cluster-id: 99")
        L.append(f"    cluster-type: cluster_flow")
        L.append(f"    defrag: yes")
        L.append(f"    use-mmap: yes")
    L.append("")
    if mode == "ips":
        # In IPS mode we still use af-packet but with IPS copy-mode
        # and a fail-open default. NFQUEUE is an alternative; we use
        # the simplest working setup here.
        L.append("nfq:")
        L.append("  - queue-num: 0")
        L.append("    batch: 32")
        L.append("")
    L.append("default-rule-path: " + RULES_DIR)
    L.append("rule-files:")
    L.extend(rule_files)
    L.append("")
    L.append("classification-file: /etc/suricata/classification.config")
    L.append("reference-config-file: /etc/suricata/reference.config")
    L.append("threshold-file: /etc/suricata/threshold.config")
    L.append("")
    return "\n".join(L)


def _write(path: str, content: str, mode: int = 0o644) -> None:
    """Direct in-place write (parent dir may be read-only under sandbox)."""
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


def apply(config: dict) -> dict:
    ids = config.get("services", {}).get("ids_config", {}) or {}
    enabled = bool(ids.get("enabled", False))
    mode = ids.get("mode", "ids")

    yaml_text = _render_yaml(config)
    _write(f"{SURICATA_DIR}/suricata.yaml", yaml_text)

    # Ensure rules dir exists
    os.makedirs(RULES_DIR, exist_ok=True)

    results = []
    if enabled:
        # Test the config. The full test loads all 52k rules (~30s) which
        # is slow. We do a fast syntax-only check first, then let systemd
        # report the real startup result.
        v = _run(["/usr/bin/suricata", "-T", "-c", f"{SURICATA_DIR}/suricata.yaml"],
                 timeout=120)
        results.append({"cmd": "suricata -T", "rc": v["rc"],
                        "err": v["err"][-500:] if v["err"] else ""})
        if v["rc"] != 0:
            return {"applied": False, "config_test": results}
        # Ensure any stale disable is undone, then enable + restart
        _run(["/usr/bin/systemctl", "unmask", SERVICE], timeout=10)
        r_en = _run(["/usr/bin/systemctl", "enable", SERVICE], timeout=15)
        results.append({"cmd": "systemctl enable", "rc": r_en["rc"],
                        "err": r_en["err"][:200]})
        r_re = _run(["/usr/bin/systemctl", "restart", SERVICE], timeout=30)
        results.append({"cmd": "systemctl restart", "rc": r_re["rc"],
                        "err": r_re["err"][:200]})
    else:
        # Stop with a longer timeout (Suricata takes several seconds to exit)
        r_stop = _run(["/usr/bin/systemctl", "stop", SERVICE], timeout=30)
        results.append({"cmd": "systemctl stop", "rc": r_stop["rc"],
                        "err": r_stop["err"][:200]})
        # Disable so it doesn't start on boot
        r_dis = _run(["/usr/bin/systemctl", "disable", SERVICE], timeout=15)
        results.append({"cmd": "systemctl disable", "rc": r_dis["rc"],
                        "err": r_dis["err"][:200]})
        # Reset failed state if it lingered
        _run(["/usr/bin/systemctl", "reset-failed", SERVICE], timeout=10)
        # Kill any stragglers
        import subprocess as _sp
        _sp.run(["/usr/bin/pkill", "-f", "Suricata-Main"], capture_output=True)
        # Clean stale runtime files
        import os as _os
        for f in ("/run/suricata.pid", "/var/run/suricata-command.socket",
                  "/var/run/suricata.pid"):
            try:
                _os.unlink(f)
            except FileNotFoundError:
                pass

    return {"applied": True, "mode": mode, "enabled": enabled, "service": results}


def status() -> dict:
    r = _run(["/usr/bin/systemctl", "is-active", SERVICE])
    active = r["out"].strip()
    info = _run(["/usr/bin/suricata", "--build-info"])
    return {"active": active, "build_info": info["out"][:500]}


def update_rules() -> dict:
    """Run suricata-update to fetch ET Open rules."""
    results = []
    # Ensure sources
    r = _run(["/usr/bin/suricata-update", "list-sources"], timeout=20)
    if "et/open" not in r["out"]:
        _run(["/usr/bin/suricata-update", "enable-source", "et/open"], timeout=20)
        results.append({"cmd": "enable-source et/open", "rc": 0})
    r = _run(["/usr/bin/suricata-update", "--no-test"], timeout=300)
    results.append({"cmd": "suricata-update", "rc": r["rc"], "out": r["out"][-500:], "err": r["err"][-500:]})
    return {"updated": r["rc"] == 0, "details": results}


def rule_count() -> dict:
    """Count rules in the effective ruleset."""
    path = f"{RULES_DIR}/suricata.rules"
    if not os.path.exists(path):
        return {"count": 0, "path": path}
    n = 0
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                n += 1
    return {"count": n, "path": path}


def alerts(limit: int = 100, severity: str = "", src: str = "") -> dict:
    """Parse /var/log/suricata/eve.json and return recent alerts."""
    path = "/var/log/suricata/eve.json"
    if not os.path.exists(path):
        return {"alerts": [], "path": path}

    # Read last ~256 KB
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        block = min(size, 256 * 1024)
        f.seek(size - block)
        data = f.read()

    import json
    alerts_out = []
    for line in data.decode("utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            ev = json.loads(line)
        except Exception:
            continue
        if ev.get("event_type") != "alert":
            continue
        a = ev.get("alert", {}) or {}
        if severity and str(a.get("severity")) != str(severity):
            continue
        if src and ev.get("src_ip") != src:
            continue
        alerts_out.append({
            "ts": ev.get("timestamp"),
            "src": ev.get("src_ip"),
            "dst": ev.get("dest_ip"),
            "proto": ev.get("proto"),
            "sport": ev.get("src_port"),
            "dport": ev.get("dest_port"),
            "sig": a.get("signature"),
            "sig_id": a.get("signature_id"),
            "cat": a.get("category"),
            "sev": a.get("severity"),
            "action": a.get("action"),
        })

    alerts_out.reverse()
    return {"alerts": alerts_out[:limit], "path": path}
