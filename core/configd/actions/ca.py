"""Certificate Authority actions (Phase 9.10)."""
from __future__ import annotations
import logging
import sys
from typing import Any

from configd.registry import action

sys.path.insert(0, "/opt/nfw")
sys.path.insert(0, "/opt/nfw/core")

from config import store as cfg_store
from config.schema import validate
from modules.ca import pki

LOG = logging.getLogger("configd.ca")


def _fix_ca_perms():
    """Ensure all CA files are readable by the nfw group."""
    import subprocess, glob
    try:
        subprocess.run(["/usr/local/sbin/nfw-fix-ca-perms.sh"],
                       capture_output=True, timeout=10)
    except Exception:
        pass


def _active_config() -> dict:
    return cfg_store.read()


@action("ca.status")
def ca_status(_data):
    return pki.status()


@action("ca.config.get")
def ca_config_get(_data):
    cfg = _active_config()
    return {"config": cfg.get("ca") or {}}


@action("ca.config.set")
def ca_config_set(data):
    new = data.get("config")
    if not isinstance(new, dict):
        raise ValueError("missing config")
    cfg = _active_config()
    ca = cfg.setdefault("ca", {})
    for k, v in new.items():
        ca[k] = v
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"staged": True, "config": ca}


@action("ca.init")
def ca_init(data):
    _fix_ca_perms()
    cfg = _active_config()
    force = bool(data.get("force", False))
    try:
        return {"ok": True, "status": pki.init_ca(cfg, force=force)}
    except pki.CaError as e:
        raise ValueError(str(e))


@action("ca.issue")
def ca_issue(data):
    _fix_ca_perms()
    cfg = _active_config()
    try:
        return pki.issue(cfg, data)
    except pki.CaError as e:
        raise ValueError(str(e))


@action("ca.sign_csr")
def ca_sign_csr(data):
    _fix_ca_perms()
    cfg = _active_config()
    try:
        return pki.sign_csr(cfg, data)
    except pki.CaError as e:
        raise ValueError(str(e))


@action("ca.list")
def ca_list(_data):
    return pki.list_certs()


@action("ca.get")
def ca_get(data):
    serial = data.get("serial")
    if not serial:
        raise ValueError("missing serial")
    try:
        return pki.get_cert(serial)
    except pki.CaError as e:
        raise FileNotFoundError(str(e))


@action("ca.revoke")
def ca_revoke(data):
    cfg = _active_config()
    serial = data.get("serial")
    reason = data.get("reason", "unspecified")
    if not serial:
        raise ValueError("missing serial")
    try:
        return pki.revoke(cfg, serial, reason)
    except pki.CaError as e:
        raise ValueError(str(e))


@action("ca.crl_regen")
def ca_crl_regen(_data):
    cfg = _active_config()
    try:
        return pki.generate_crl(cfg)
    except pki.CaError as e:
        raise ValueError(str(e))


@action("ca.export_p12")
def ca_export_p12(data):
    serial = data.get("serial")
    password = data.get("password") or ""
    if not serial:
        raise ValueError("missing serial")
    try:
        p12 = pki.export_p12(serial, password)
    except pki.CaError as e:
        raise ValueError(str(e))
    import base64
    return {"data_b64": base64.b64encode(p12).decode(),
            "filename": f"nfw-{serial}.p12"}


@action("ca.delete")
def ca_delete(data):
    cfg = _active_config()
    serial = data.get("serial")
    if not serial:
        raise ValueError("missing serial")
    try:
        return pki.delete_cert(cfg, serial)
    except pki.CaError as e:
        raise ValueError(str(e))


@action("ca.root_pem")
def ca_root_pem(_data):
    import base64
    try:
        return {"data_b64": base64.b64encode(pki.root_pem()).decode()}
    except pki.CaError as e:
        raise ValueError(str(e))


@action("ca.chain_pem")
def ca_chain_pem(_data):
    import base64
    try:
        return {"data_b64": base64.b64encode(pki.chain_pem()).decode()}
    except pki.CaError as e:
        raise ValueError(str(e))

# =============================================================================
# Phase 9.10b — integration helpers
# =============================================================================
@action("ca.issue_for_host")
def ca_issue_for_host(_data):
    cfg = _active_config()
    try:
        return pki.issue_for_host(cfg)
    except pki.CaError as e:
        raise ValueError(str(e))


@action("ca.expiring")
def ca_expiring(data):
    days = int(data.get("within_days", 30))
    return {"certs": pki.expiring(days)}


@action("ca.renew")
def ca_renew(data):
    _fix_ca_perms()
    cfg = _active_config()
    serial = data.get("serial")
    if not serial:
        raise ValueError("missing serial")
    try:
        return pki.renew_cert(cfg, serial)
    except pki.CaError as e:
        raise ValueError(str(e))


@action("ca.cert_paths")
def ca_cert_paths(data):
    serial = (data.get("serial") or "").upper().strip()
    if not serial:
        raise ValueError("missing serial")
    try:
        pki.get_cert(serial)
    except pki.CaError as e:
        raise FileNotFoundError(str(e))
    base = "/var/lib/nfw/ca"
    return {
        "serial": serial,
        "cert":    f"{base}/certs/cert-{serial}.crt",
        "key":     f"{base}/private/{serial}.key",
        "chain":   f"{base}/ca-chain.crt",
    }


@action("ca.tls_status")
def ca_tls_status(_data):
    cfg = _active_config()
    api = cfg.get("api", {}) or {}
    tls = api.get("tls", {}) or {}
    return {
        "enabled": bool(tls.get("enabled", False)),
        "cert_serial": tls.get("cert_serial", ""),
        "listen_port": tls.get("listen_port", 8443),
    }


@action("ca.tls_enable")
def ca_tls_enable(data):
    _fix_ca_perms()
    import subprocess, time as _time
    from pathlib import Path

    cfg = _active_config()
    if not pki.status().get("initialized"):
        raise ValueError("CA not initialized — set up the CA first")

    cert = pki.issue_for_host(cfg)
    serial = cert["serial"]

    api = cfg.setdefault("api", {})
    tls = api.setdefault("tls", {})
    tls["enabled"] = True
    tls["cert_serial"] = serial
    tls.setdefault("listen_port", 8443)
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")

    cert_path = f"/var/lib/nfw/ca/certs/cert-{serial}.crt"
    key_path  = f"/var/lib/nfw/ca/private/{serial}.key"

    drop_dir = Path("/etc/systemd/system/nfw-api.service.d")
    drop_dir.mkdir(parents=True, exist_ok=True)
    drop = drop_dir / "10-tls.conf"

    new_exec = (
        f"/opt/nfw/venv/bin/uvicorn api.main:app "
        f"--host 0.0.0.0 --port {tls['listen_port']} --workers 1 "
        f"--ssl-keyfile {key_path} --ssl-certfile {cert_path}"
    )
    content = "[Service]\nExecStart=\nExecStart=" + new_exec + "\n"
    drop.write_text(content)

    subprocess.run(["/usr/bin/systemctl", "daemon-reload"],
                   capture_output=True, text=True)
    r = subprocess.run(["/usr/bin/systemctl", "restart", "nfw-api"],
                       capture_output=True, text=True, timeout=90)
    _time.sleep(2)
    check = subprocess.run(["/usr/bin/systemctl", "is-active", "nfw-api"],
                           capture_output=True, text=True)
    active = check.stdout.strip() == "active"

    return {
        "enabled": True,
        "cert_serial": serial,
        "listen_port": tls["listen_port"],
        "url": f"https://{_primary_ip()}:{tls['listen_port']}/",
        "service_active": active,
        "restart_rc": r.returncode,
        "restart_stderr": r.stderr[:300] if r.stderr else "",
    }


@action("ca.tls_disable")
def ca_tls_disable(data):
    import subprocess
    from pathlib import Path

    cfg = _active_config()
    tls = cfg.setdefault("api", {}).setdefault("tls", {})
    tls["enabled"] = False
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")

    drop = Path("/etc/systemd/system/nfw-api.service.d/10-tls.conf")
    if drop.exists():
        drop.unlink()

    subprocess.run(["/usr/bin/systemctl", "daemon-reload"],
                   capture_output=True, text=True)
    subprocess.run(["/usr/bin/systemctl", "restart", "nfw-api"],
                   capture_output=True, text=True, timeout=90)
    return {"enabled": False}


def _primary_ip() -> str:
    try:
        import subprocess, json as _json
        r = subprocess.run(["/usr/sbin/ip", "-j", "addr"],
                           capture_output=True, text=True, timeout=5)
        for iface in _json.loads(r.stdout or "[]"):
            if iface.get("operstate") != "UP" or iface.get("ifname") == "lo":
                continue
            for a in iface.get("addr_info", []) or []:
                if a.get("family") == "inet" and not a.get("local", "").startswith("127."):
                    return a["local"]
    except Exception:
        pass
    return "127.0.0.1"

