"""HAProxy config generator."""
from __future__ import annotations
import os
import subprocess
from typing import Any

CONF = "/etc/haproxy/haproxy.cfg"


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
    hp = config.get("services", {}).get("haproxy_config", {}) or {}
    frontends = hp.get("frontends", []) or []
    stats_enabled = hp.get("stats_enabled", True)
    stats_port = hp.get("stats_port", 8404)

    L: list[str] = []
    L.append("# NFW — GENERATED haproxy.cfg. Manual edits will be overwritten.")
    L.append("global")
    L.append("    log /dev/log local0")
    L.append("    log /dev/log local1 notice")
    L.append("    daemon")
    L.append("    maxconn 4096")
    L.append("    user haproxy")
    L.append("    group haproxy")
    L.append("")
    L.append("defaults")
    L.append("    log global")
    L.append("    mode http")
    L.append("    option httplog")
    L.append("    option dontlognull")
    L.append("    option forwardfor")
    L.append("    option http-server-close")
    L.append("    timeout connect 5s")
    L.append("    timeout client  30s")
    L.append("    timeout server  30s")
    L.append("")
    if stats_enabled:
        L.append("listen stats")
        L.append(f"    bind *:{stats_port}")
        L.append("    mode http")
        L.append("    stats enable")
        L.append("    stats uri /")
        L.append("    stats refresh 10s")
        L.append("    stats admin if TRUE")
        L.append("")

    for fe in frontends:
        name = fe.get("name", "web")
        bind_port = fe.get("bind_port", 80)
        ssl_cert = fe.get("ssl_cert", "")  # path to fullchain+privkey
        default_backend = fe.get("default_backend", name + "_back")

        L.append(f"frontend {name}_fe")
        L.append(f"    bind *:{bind_port}")

        # Phase 9.10b: prefer a CA-issued cert if a serial is set
        ca_serial = fe.get("ca_cert_serial", "")
        if ca_serial:
            cert_file = f"/var/lib/nfw/ca/certs/cert-{ca_serial}.crt"
            key_file  = f"/var/lib/nfw/ca/private/{ca_serial}.key"
            chain_file = f"/var/lib/nfw/ca/ca-chain.crt"
            import os as _os
            bundle_dir = "/etc/haproxy/certs"
            _os.makedirs(bundle_dir, exist_ok=True)
            bundle_path = f"{bundle_dir}/fe-{name}.pem"
            try:
                parts = []
                for path in (cert_file, key_file, chain_file):
                    with open(path, "r") as fh:
                        parts.append(fh.read().strip())
                with open(bundle_path, "w") as fh:
                    fh.write("\n".join(parts) + "\n")
                _os.chmod(bundle_path, 0o600)
                L.append(f"    bind *:443 ssl crt {bundle_path}")
                L.append("    http-request redirect scheme https unless { ssl_fc }")
            except FileNotFoundError as e:
                if ssl_cert:
                    L.append(f"    bind *:443 ssl crt {ssl_cert}")
                    L.append("    http-request redirect scheme https unless { ssl_fc }")
                else:
                    L.append(f"    # ca_cert_serial {ca_serial} — file missing: {e}")
        elif ssl_cert:
            L.append(f"    bind *:443 ssl crt {ssl_cert}")
            L.append("    http-request redirect scheme https unless { ssl_fc }")
        L.append(f"    default_backend {default_backend}")
        L.append("")

        # ACLs → backends
        for rule in fe.get("rules", []) or []:
            acl_name = rule.get("acl_name", "")
            host = rule.get("host", "")
            backend = rule.get("backend", "")
            if acl_name and host and backend:
                L.append(f"    acl {acl_name} hdr(host) -i {host}")
                L.append(f"    use_backend {backend} if {acl_name}")
        L.append("")

    # Backends
    for be in hp.get("backends", []) or []:
        name = be.get("name", "app")
        servers = be.get("servers", []) or []
        balance = be.get("balance", "roundrobin")
        L.append(f"backend {name}")
        L.append(f"    balance {balance}")
        L.append("    option httpchk GET /")
        for s in servers:
            sname = s.get("name", "srv")
            saddr = s.get("address", "127.0.0.1")
            sport = s.get("port", 8080)
            L.append(f"    server {sname} {saddr}:{sport} check")
        L.append("")

    return "\n".join(L)


def apply(config: dict) -> dict:
    hp = config.get("services", {}).get("haproxy_config", {}) or {}
    enabled = hp.get("enabled", False)

    _write(CONF, _render(config))

    # Validate
    v = _run(["/usr/sbin/haproxy", "-c", "-f", CONF])
    if v["rc"] != 0:
        return {"applied": False, "error": v["err"][:500]}

    results = []
    if enabled:
        _run(["/usr/bin/systemctl", "enable", "haproxy"])
        r = _run(["/usr/bin/systemctl", "restart", "haproxy"])
        results.append({"cmd": "restart", "rc": r["rc"], "err": r["err"][:200]})
    else:
        _run(["/usr/bin/systemctl", "stop", "haproxy"])
        _run(["/usr/bin/systemctl", "disable", "haproxy"])
        results.append({"cmd": "disabled", "rc": 0})

    return {"applied": True, "enabled": enabled, "service": results}


def status() -> dict:
    r = _run(["/usr/bin/systemctl", "is-active", "haproxy"])
    return {"active": r["out"].strip()}
