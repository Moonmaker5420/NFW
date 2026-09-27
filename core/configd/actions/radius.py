"""FreeRADIUS configd actions (Phase 9.13a)."""
from __future__ import annotations
import logging
import os
import shutil
import subprocess
import sys
from typing import Any

from configd.registry import action

sys.path.insert(0, "/opt/nfw")
sys.path.insert(0, "/opt/nfw/core")

from config import store as cfg_store
from config.schema import validate
from modules.services.radius import (
    generate_clients_conf,
    generate_authorize,
    generate_eap_conf,
    generate_ldap_conf,
    generate_site_conf,
    generate_inner_tunnel,
    nt_hash,
)

LOG = logging.getLogger("configd.radius")

FR_ROOT = "/etc/freeradius/3.0"
FR_CERTS = f"{FR_ROOT}/certs"
FR_NFW = f"{FR_ROOT}/mods-config/nfw"
FR_SITES = f"{FR_ROOT}/sites-enabled"
BACKUP_DIR = "/etc/nfw/backups/freeradius-config"


def _effective_config() -> dict:
    staged = cfg_store.get_staging()
    return dict(staged if staged is not None else cfg_store.read())


def _atomic_write(path: str, content: str, mode: int = 0o644) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(content); f.flush(); os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _run(cmd, timeout: int = 15) -> dict:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"rc": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
    except subprocess.TimeoutExpired:
        return {"rc": 124, "stdout": "", "stderr": "timeout"}
    except FileNotFoundError as e:
        return {"rc": 127, "stdout": "", "stderr": str(e)}


def _backup_current() -> None:
    os.makedirs(BACKUP_DIR, exist_ok=True)
    for src in (f"{FR_ROOT}/clients.conf",
                f"{FR_ROOT}/mods-config/files/authorize",
                f"{FR_NFW}/eap",
                f"{FR_NFW}/ldap",
                f"{FR_SITES}/nfw",
                f"{FR_SITES}/nfw-inner-tunnel"):
        if os.path.exists(src):
            dst = os.path.join(BACKUP_DIR, os.path.basename(src) + ".bak")
            try: shutil.copy2(src, dst)
            except OSError: pass


def _ensure_cert(cfg: dict):
    """Issue a server cert from the internal CA and materialize it for FR."""
    rc = cfg.setdefault("services", {}).setdefault("radius_config", {})
    serial = rc.get("server_cert_serial") or ""
    if not serial:
        from modules.ca import pki
        try:
            import socket
            host = socket.gethostname()
        except Exception:
            host = "optimus"
        sans = ["radius.nfw", host, "localhost", "127.0.0.1"]
        if rc.get("listen_ip"):
            sans.append(rc["listen_ip"])
        result = pki.issue(cfg, {
            "kind": "server",
            "common_name": "radius.nfw",
            "san": ",".join(s for s in sans if s),
            "lifetime_days": 825,
        })
        serial = result["serial"]
        rc["server_cert_serial"] = serial
        cfg_store.stage(cfg, author="configd.radius")

    from modules.ca import pki
    cert_path = f"{pki.CERTS_DIR}/cert-{serial}.crt"
    key_path = f"{pki.PRIV_DIR}/{serial}.key"
    ca_path = f"{pki.CHAIN}"

    os.makedirs(FR_CERTS, exist_ok=True)
    for src, dst, mode in ((cert_path, f"{FR_CERTS}/server.crt", 0o644),
                           (ca_path,   f"{FR_CERTS}/ca.pem",     0o644),
                           (key_path,  f"{FR_CERTS}/server.key", 0o640)):
        with open(src, "rb") as f: data = f.read()
        with open(dst, "wb") as f: f.write(data)
        try:
            os.chmod(dst, mode)
            shutil.chown(dst, "root", "freerad")
        except (OSError, LookupError): pass

    dh_file = f"{FR_CERTS}/dh"
    if not os.path.exists(dh_file) or os.path.getsize(dh_file) < 100:
        LOG.info("generating DH parameters (this takes 10-30s)")
        r = _run(["openssl", "dhparam", "-out", dh_file, "2048"], timeout=180)
        if r["rc"] != 0:
            LOG.warning("dhparam failed: %s", r["stderr"][:200])
        try:
            os.chmod(dh_file, 0o644)
            shutil.chown(dh_file, "root", "freerad")
        except (OSError, LookupError): pass

    return cert_path, key_path, ca_path


def _install_config(cfg: dict) -> dict:
    rc = cfg.get("services", {}).get("radius_config", {}) or {}
    os.makedirs(FR_NFW, exist_ok=True)
    os.makedirs(f"{FR_ROOT}/mods-config/files", exist_ok=True)
    os.makedirs(FR_SITES, exist_ok=True)
    _backup_current()

    _atomic_write(f"{FR_ROOT}/clients.conf", generate_clients_conf(cfg))
    _atomic_write(f"{FR_ROOT}/mods-config/files/authorize", generate_authorize(cfg))
    _atomic_write(f"{FR_NFW}/eap", generate_eap_conf(cfg))
    _atomic_write(f"{FR_SITES}/nfw", generate_site_conf(cfg))
    _atomic_write(f"{FR_SITES}/nfw-inner-tunnel", generate_inner_tunnel(cfg))

    # Symlink NFW's eap module into mods-enabled
    eap_link = f"{FR_ROOT}/mods-enabled/eap"
    if os.path.lexists(eap_link): os.unlink(eap_link)
    os.symlink("../mods-config/nfw/eap", eap_link)

    # Ensure mschap module enabled
    ms_link = f"{FR_ROOT}/mods-enabled/mschap"
    if not os.path.lexists(ms_link):
        try: os.symlink("../mods-available/mschap", ms_link)
        except OSError: pass

    # LDAP module
    ldap_link = f"{FR_ROOT}/mods-enabled/ldap"
    if rc.get("use_ldap"):
        _atomic_write(f"{FR_NFW}/ldap", generate_ldap_conf(cfg))
        if os.path.lexists(ldap_link): os.unlink(ldap_link)
        os.symlink("../mods-config/nfw/ldap", ldap_link)
    else:
        if os.path.lexists(ldap_link): os.unlink(ldap_link)

    # Disable upstream default site to avoid port collision
    for stale in ("default", "inner-tunnel"):
        link = f"{FR_SITES}/{stale}"
        if os.path.lexists(link):
            try: os.unlink(link)
            except OSError: pass

    return {"wrote": [
        f"{FR_ROOT}/clients.conf",
        f"{FR_ROOT}/mods-config/files/authorize",
        f"{FR_NFW}/eap",
        f"{FR_SITES}/nfw",
        f"{FR_SITES}/nfw-inner-tunnel",
    ]}


# ---------------------------------------------------------------------------
@action("radius.config.get")
def radius_get(_data):
    cfg = _effective_config()
    return {"config": cfg.get("services", {}).get("radius_config", {})}


@action("radius.config.set")
def radius_set(data):
    new = data.get("config")
    if not isinstance(new, dict):
        raise ValueError("missing config")
    cfg = _effective_config()
    existing = cfg.get("services", {}).get("radius_config", {}) or {}
    merged = dict(existing)
    for k, v in new.items():
        merged[k] = v
    cfg.setdefault("services", {})["radius_config"] = merged
    cfg["services"]["radius"] = bool(merged.get("enabled"))
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"staged": True, "config": merged}


@action("radius.preview")
def radius_preview(_data):
    cfg = _effective_config()
    return {
        "clients": generate_clients_conf(cfg),
        "authorize": generate_authorize(cfg),
        "eap": generate_eap_conf(cfg),
        "site": generate_site_conf(cfg),
        "inner": generate_inner_tunnel(cfg),
    }


@action("radius.hash_nt")
def radius_hash_nt(data):
    pw = data.get("password") or ""
    if not pw:
        raise ValueError("password required")
    return {"nt_hash": nt_hash(pw)}


def _stage_then_commit(cfg: dict, message: str) -> dict:
    """Stage the (possibly further-mutated) config, then commit it.

    radius.apply is an explicit user action with side effects on the
    system (cert issuance, FR config write, service restart). Leaving
    those in staging would leave the system and the config out of sync.
    Auto-commit here.
    """
    validate(cfg)
    cfg_store.stage(cfg, author="configd.radius")
    try:
        result = cfg_store.commit(author="configd.radius", message=message)
    except TypeError:
        result = cfg_store.commit()
    # RevisionInfo is a dataclass — grab .revision if present, else fall back
    rev = ""
    if hasattr(result, "revision"):
        rev = str(getattr(result, "revision", "") or "")
    elif isinstance(result, dict):
        rev = result.get("revision", "") or result.get("rev", "")
    elif isinstance(result, str):
        rev = result
    return {"committed": True, "revision": rev}


def _ensure_firewall_rule(cfg: dict, rc: dict) -> bool:
    """Inject (or refresh) the LAN rule that allows RADIUS UDP in.

    The NFW Rule dataclass expects: id, order, enabled, action ('pass'|'block'),
    interface ('lan'|'wan'|...), direction ('in'), proto, source, dest,
    dport (comma-separated), description.

    Returns True if the config was changed.
    """
    port_auth = str(rc.get("auth_port", 1812))
    port_acct = str(rc.get("acct_port", 1813))
    dport_str = f"{port_auth},{port_acct}"
    rule_id = "sys-radius-lan"

    rules = cfg.setdefault("firewall", {}).setdefault("rules", [])
    for r in rules:
        if r.get("id") == rule_id:
            if r.get("dport") != dport_str or r.get("enabled") is not True:
                r["dport"] = dport_str
                r["enabled"] = True
                return True
            return False

    rules.insert(0, {
        "id": rule_id,
        "order": 10,
        "enabled": True,
        "action": "pass",
        "interface": "lan",
        "direction": "in",
        "proto": "udp",
        "source": "any",
        "dest": "any",
        "dport": dport_str,
        "log": False,
        "description": "RADIUS: allow LAN NAS clients (system-managed)",
    })
    return True


@action("radius.apply")
def radius_apply(_data):
    cfg = _effective_config()
    rc = cfg.setdefault("services", {}).setdefault("radius_config", {})
    enabled = bool(rc.get("enabled", False)) or bool(cfg.get("services", {}).get("radius"))

    if not enabled:
        _run(["systemctl", "stop", "freeradius"])
        _run(["systemctl", "disable", "freeradius"])
        _stage_then_commit(cfg, "radius: disable")
        return {"enabled": False, "note": "service disabled"}

    # Default listen to LAN IP if user left blank
    if not rc.get("listen_ip"):
        net = cfg.get("network", {})
        iface = net.get("lan") or ""
        for name, cfg_if in (net.get("interfaces", {}) or {}).items():
            if name == iface:
                rc["listen_ip"] = cfg_if.get("ipv4", {}).get("address", "")
                break

    _ensure_cert(cfg)
    if _ensure_firewall_rule(cfg, rc):
        LOG.info('injected/updated sys-radius-lan rule')
    validate(cfg)
    commit_result = _stage_then_commit(cfg, "radius: apply")
    written = _install_config(cfg)

    # Syntax check
    r = _run(["freeradius", "-XC"], timeout=30)
    if r["rc"] != 0:
        combined = (r.get("stdout") or "") + "\n" + (r.get("stderr") or "")
        tail = "\n".join(combined.splitlines()[-12:])
        LOG.error("freeradius check failed (rc=%s):\n%s", r["rc"], tail)
        raise RuntimeError(f"freeradius -XC failed:\n{tail}")

    _run(["systemctl", "enable", "freeradius"])
    r = _run(["systemctl", "restart", "freeradius"], timeout=30)
    if r["rc"] != 0:
        raise RuntimeError(f"freeradius restart failed: {r['stderr'][:400]}")

    # commit_result may contain non-serializable objects (Path, datetime).
    # Report only a short summary — the truth is in the config store.
    rev = ""
    if isinstance(commit_result, dict):
        rev = str(commit_result.get("revision", "") or "")
    return {"enabled": True, "wrote": written["wrote"], "revision": rev}


@action("radius.status")
def radius_status(_data):
    out: dict[str, Any] = {}
    r = _run(["systemctl", "is-active", "freeradius"])
    out["service"] = r["stdout"].strip() or "unknown"
    r = _run(["/usr/sbin/freeradius", "-v"])
    out["version"] = (r["stdout"].splitlines() or [""])[0] if r["rc"] == 0 else ""
    if os.path.exists("/var/log/freeradius/radius.log"):
        out["log_tail"] = _run(["tail", "-n", "30", "/var/log/freeradius/radius.log"])["stdout"]
    else:
        out["log_tail"] = ""
    # listening ports
    r = _run(["ss", "-lunp"])
    out["listening"] = "\n".join(
        line for line in r["stdout"].splitlines()
        if ":1812" in line or ":1813" in line
    )
    return out


@action("radius.test_user")
def radius_test_user(data):
    username = data.get("username") or ""
    password = data.get("password") or ""
    if not username or not password:
        raise ValueError("username and password required")
    cfg = _effective_config()
    rc = cfg.get("services", {}).get("radius_config", {}) or {}
    secret = rc.get("localhost_secret") or "testing123"
    cmd = ["radtest", username, password, "127.0.0.1", "0", secret]
    r = _run(cmd, timeout=15)
    return {"rc": r["rc"], "stdout": r["stdout"], "stderr": r["stderr"]}
