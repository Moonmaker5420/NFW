"""Captive portal configd actions (Phase 9.18a)."""
from __future__ import annotations
import json
import logging
import os
import subprocess
import sys
import time
from typing import Any

from configd.registry import action

sys.path.insert(0, "/opt/nfw")
sys.path.insert(0, "/opt/nfw/core")

from config import store as cfg_store
from config.schema import validate
from modules.services import captiveportal as cp

LOG = logging.getLogger("configd.captiveportal")


def _effective_config() -> dict:
    staged = cfg_store.get_staging()
    return dict(staged if staged is not None else cfg_store.read())


def _run(cmd, timeout: int = 15) -> dict:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"rc": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
    except subprocess.TimeoutExpired:
        return {"rc": 124, "stdout": "", "stderr": "timeout"}
    except FileNotFoundError as e:
        return {"rc": 127, "stdout": "", "stderr": str(e)}


def _stage_then_commit(cfg: dict, message: str) -> dict:
    validate(cfg)
    cfg_store.stage(cfg, author="configd.captiveportal")
    try:
        result = cfg_store.commit(author="configd.captiveportal", message=message)
    except TypeError:
        result = cfg_store.commit()
    rev = ""
    if hasattr(result, "revision"):
        rev = str(getattr(result, "revision", "") or "")
    elif isinstance(result, dict):
        rev = result.get("revision", "") or result.get("rev", "")
    elif isinstance(result, str):
        rev = result
    return {"committed": True, "revision": rev}


# ---------------------------------------------------------------------------
# Authentication backends
# ---------------------------------------------------------------------------
def _auth_local(cfg: dict, username: str, password: str) -> tuple[bool, str]:
    """Verify against /etc/nfw/users.json (bcrypt)."""
    try:
        with open("/etc/nfw/users.json") as f:
            users = json.load(f)
    except FileNotFoundError:
        return False, "local user store missing"
    u = users.get(username)
    if not u:
        return False, "unknown user"
    if u.get("disabled"):
        return False, "user disabled"
    stored = u.get("password_hash") or u.get("hash") or ""
    if not stored:
        return False, "no hash on record"
    try:
        import bcrypt
        if bcrypt.checkpw(password.encode(), stored.encode()):
            return True, "local"
        return False, "bad password"
    except Exception as e:
        return False, f"bcrypt error: {e}"


def _auth_ldap(cfg: dict, username: str, password: str) -> tuple[bool, str]:
    """Bind-as-user LDAP auth. Uses auth.ldap config (9.9b)."""
    ldap_cfg = cfg.get("auth", {}).get("ldap", {}) or {}
    if not ldap_cfg.get("enabled"):
        return False, "ldap disabled"
    server_uri = ldap_cfg.get("server") or ""
    port = int(ldap_cfg.get("port", 389))
    use_ssl = bool(ldap_cfg.get("use_ssl", False))
    use_starttls = bool(ldap_cfg.get("use_starttls", False))
    bind_dn = ldap_cfg.get("bind_dn") or ""
    bind_pw = ldap_cfg.get("bind_password") or ""
    base_dn = ldap_cfg.get("base_dn") or ""
    user_filter = ldap_cfg.get("user_filter") or "(uid={username})"

    try:
        import ldap3
    except ImportError:
        return False, "ldap3 not available"

    flt = user_filter.replace("{username}", username)
    try:
        server = ldap3.Server(server_uri, port=port,
                              use_ssl=use_ssl, get_info=ldap3.NONE,
                              connect_timeout=8)
        with ldap3.Connection(server, user=bind_dn, password=bind_pw,
                              authentication=ldap3.SIMPLE,
                              auto_bind=True, receive_timeout=8) as c:
            if use_starttls and not use_ssl:
                c.start_tls()
            c.search(base_dn, flt, search_scope=ldap3.SUBTREE,
                     attributes=["*"])
            if not c.entries:
                return False, "user not found"
            user_dn = c.entries[0].entry_dn
    except Exception as e:
        return False, f"ldap bind failed: {e}"

    try:
        server2 = ldap3.Server(server_uri, port=port,
                               use_ssl=use_ssl, get_info=ldap3.NONE,
                               connect_timeout=8)
        with ldap3.Connection(server2, user=user_dn, password=password,
                              authentication=ldap3.SIMPLE,
                              auto_bind=True, receive_timeout=8) as _c:
            return True, "ldap"
    except Exception as e:
        return False, f"ldap auth failed: {e}"


def _auth_radius(cfg: dict, username: str, password: str) -> tuple[bool, str]:
    """Not used in 9.18a. Stub returns False with a clear message."""
    return False, "radius backend not enabled in 9.18a"


def _chain_auth(cfg: dict, username: str, password: str,
                backends: list[str]) -> tuple[bool, str]:
    last_msg = ""
    for b in backends:
        if b == "local":
            ok, msg = _auth_local(cfg, username, password)
            if ok:
                return True, "local"
            last_msg = msg
        elif b == "ldap":
            ok, msg = _auth_ldap(cfg, username, password)
            if ok:
                return True, "ldap"
            last_msg = msg
        elif b == "radius":
            ok, msg = _auth_radius(cfg, username, password)
            if ok:
                return True, "radius"
            last_msg = msg
    return False, last_msg or "no backend succeeded"


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------
@action("captiveportal.config.get")
def cp_get(_data):
    cfg = _effective_config()
    return {"config": cfg.get("services", {}).get("captiveportal_config", {})}


@action("captiveportal.config.set")
def cp_set(data):
    new = data.get("config")
    if not isinstance(new, dict):
        raise ValueError("missing config")
    cfg = _effective_config()
    existing = cfg.get("services", {}).get("captiveportal_config", {}) or {}
    merged = dict(existing)
    for k, v in new.items():
        merged[k] = v
    cfg.setdefault("services", {})["captiveportal_config"] = merged
    cfg["services"]["captiveportal"] = bool(merged.get("enabled"))
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"staged": True, "config": merged}


def _call_configd(action: str, data: dict | None = None, timeout: float = 45.0) -> dict:
    """Talk to configd over its unix socket, returning the {ok, result} dict."""
    import socket as _sock
    s = _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect("/run/nfw/configd.sock")
        s.sendall((json.dumps({"action": action, "data": data or {}}) + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    finally:
        s.close()
    if not buf:
        return {"ok": False, "error": "empty response"}
    try:
        return json.loads(buf.decode())
    except Exception as e:
        return {"ok": False, "error": f"bad json: {e}"}


def _recompile_dhcp_after_cp() -> str:
    """Recompile dhcpd.conf so option 114 reflects the current CP state.

    Returns "ok" or an error string. Never raises.
    """
    try:
        from modules.services.dhcp import compile_dhcpd, dhcp_service_unit_interface
        cfg = _effective_config()
        try:
            from modules.network.interfaces import resolve_roles
            cfg["_resolved_interfaces"] = resolve_roles(cfg.get("network", {}))
        except Exception:
            pass
        text = compile_dhcpd(cfg)
        path = "/etc/dhcp/dhcpd.conf"
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            f.write(text)
            f.flush()
            import os as _os
            _os.fsync(f.fileno())
        import os as _os
        _os.replace(tmp, path)
        # Reload isc-dhcp-server
        _run(["systemctl", "reload-or-restart", "isc-dhcp-server"], timeout=15)
        return "ok"
    except Exception as e:
        LOG.warning("DHCP recompile after CP toggle failed: %s", e)
        return f"error: {e}"


def _enable_bytes_timer(enable: bool) -> str:
    """Enable/disable nfw-cp-bytes.timer (byte accounting)."""
    if enable:
        _run(["systemctl", "enable", "--now", "nfw-cp-bytes.timer"],
             timeout=15)
    else:
        _run(["systemctl", "disable", "--now", "nfw-cp-bytes.timer"],
             timeout=15)
    r = _run(["systemctl", "is-active", "nfw-cp-bytes.timer"])
    return r["stdout"].strip() or "unknown"


def _enable_bypass_timer(enable: bool) -> str:
    """Enable/disable nfw-cp-bypass-refresh.timer based on config."""
    if enable:
        _run(["systemctl", "enable", "--now", "nfw-cp-bypass-refresh.timer"],
             timeout=15)
    else:
        _run(["systemctl", "disable", "--now", "nfw-cp-bypass-refresh.timer"],
             timeout=15)
    r = _run(["systemctl", "is-active", "nfw-cp-bypass-refresh.timer"])
    return r["stdout"].strip() or "unknown"


@action("captiveportal.apply")
def cp_apply(_data):
    cfg = _effective_config()
    svc = cfg.setdefault("services", {}).setdefault("captiveportal_config", {})
    enabled = bool(svc.get("enabled", False)) or bool(cfg.get("services", {}).get("captiveportal"))

    # Always materialize portal.json + ensure DB exists
    cp.write_portal_config(cfg)
    cp.db().close()

    # 1. Commit config (so apply_staged sees the final revision as active)
    result = _stage_then_commit(
        cfg,
        "captiveportal: " + ("apply" if enabled else "disable"),
    )

    # 1b. Refresh bypass caches BEFORE the firewall compiles so the
    # compiler sees fresh MAC→IP and hostname→IP mappings.
    if enabled:
        try:
            cp.refresh_bypass(cfg)
            LOG.info("bypass refresh completed before firewall compile")
        except Exception as e:
            LOG.warning("bypass refresh failed: %s", e)

    # 1c-bis. Recompile DHCP with option 114 if CP state changed
    dhcp_result = _recompile_dhcp_after_cp()
    LOG.info("dhcp recompile after CP apply: %s", dhcp_result)

    # 1c. Install or remove shaping roots (9.18b5)
    shaping_info = {}
    if enabled:
        try:
            shaping_info = cp.shaping_install(cfg)
        except Exception as e:
            LOG.warning("shaping_install failed: %s", e)
            shaping_info = {"error": str(e)}
    else:
        try:
            shaping_info = cp.shaping_uninstall(cfg)
        except Exception as e:
            LOG.warning("shaping_uninstall failed: %s", e)
            shaping_info = {"error": str(e)}

    # 2. Ask the firewall to regenerate /etc/nftables.conf + reload nft
    fw = _call_configd("firewall.apply_staged")
    fw_ok = bool((fw or {}).get("ok"))
    fw_detail = ""
    if not fw_ok:
        fw_detail = str((fw or {}).get("stderr") or (fw or {}).get("error") or "unknown error")[:300]
        LOG.error("firewall.apply_staged failed: %s", fw_detail)

    # 3. Bring the portal service up/down accordingly
    portal_state = "disabled"
    bypass_timer = "disabled"
    bytes_timer = "disabled"
    if enabled:
        _run(["systemctl", "enable", "nfw-portal"], timeout=15)
        _run(["systemctl", "restart", "nfw-portal"], timeout=15)
        portal_state = _run(["systemctl", "is-active", "nfw-portal"])["stdout"].strip()
        bypass_timer = _enable_bypass_timer(True)
        bytes_timer = _enable_bytes_timer(True)
    else:
        _run(["systemctl", "stop", "nfw-portal"], timeout=15)
        _run(["systemctl", "disable", "nfw-portal"], timeout=15)
        portal_state = "stopped"
        bypass_timer = _enable_bypass_timer(False)
        bytes_timer = _enable_bytes_timer(False)

    auto_rules_enabled = enabled and not bool(svc.get("disable_auto_rules", False))
    return {
        "enabled": enabled,
        "auto_rules_enabled": auto_rules_enabled,
        "config_written": str(cp.CONF_JSON),
        "portal_service": portal_state,
        "bypass_timer": bypass_timer,
        "bytes_timer": bytes_timer,
        "dhcp_recompiled": dhcp_result,
        "shaping": shaping_info,
        "firewall_applied": fw_ok,
        "firewall_detail": fw_detail,
        **result,
    }



@action("captiveportal.authenticate")
def cp_authenticate(data):
    """Verify + authorize. Handles concurrent-login limits + hard timeout
    + welcome-back reactivation."""
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    ip       = data.get("ip") or ""
    mac      = (data.get("mac") or "").strip()
    ua       = data.get("user_agent") or ""
    if not username or not password:
        return {"ok": False, "error": "username and password required"}
    if not ip:
        return {"ok": False, "error": "client ip required"}
    try:
        import ipaddress
        ipaddress.ip_address(ip)
    except Exception:
        return {"ok": False, "error": "invalid client ip"}

    cfg = _effective_config()
    svc = cfg.get("services", {}).get("captiveportal_config", {}) or {}
    if not svc.get("enabled"):
        return {"ok": False, "error": "captive portal is disabled"}

    # If client didn't send MAC, look it up
    if not mac:
        mac = cp.get_mac_from_ip(ip)

    # --- Welcome Back check (before credential verification!) ---
    wb = int(svc.get("welcome_back", 0) or 0)
    if wb > 0 and mac:
        wb_sess = cp.find_welcome_back_session(mac, wb)
        if wb_sess:
            timeout_s = int(svc.get("session_timeout", 3600))
            react = cp.reactivate_welcome_back(wb_sess["id"], ip, timeout_s)
            if react:
                cp.nft_add_authenticated(ip, timeout_s)
                LOG.info("welcome-back OK mac=%s ip=%s user=%s",
                         mac, ip, react.get("username"))
                return {
                    "ok": True,
                    "welcome_back": True,
                    "username": react.get("username"),
                    "auth_backend": react.get("auth_backend"),
                    "ip": ip,
                    "session_id": react["id"],
                    "expires_in": timeout_s,
                }

    backends = svc.get("auth_backends") or ["local", "ldap"]
    ok, which = _chain_auth(cfg, username, password, backends)
    if not ok:
        LOG.info("portal auth FAIL user=%s ip=%s: %s", username, ip, which)
        return {"ok": False, "error": "invalid credentials", "reason": which}

    # --- Concurrency check ---
    max_concurrent = int(svc.get("concurrent_logins", 0) or 0)
    mode = svc.get("concurrent_mode", "deny_new")
    if max_concurrent > 0:
        active = cp.active_sessions_for_user(username)
        # Exclude our own IP if already present
        active = [a for a in active if a["ip"] != ip]
        if len(active) >= max_concurrent:
            if mode == "deny_new":
                LOG.info("concurrent limit reached for user=%s (%d active)",
                         username, len(active))
                return {"ok": False, "error": "concurrent login limit reached"}
            else:  # kick_oldest
                oldest = active[0]
                cp.revoke_session_by_id(oldest["id"], "concurrent_kick")
                cp.nft_remove_authenticated(oldest["ip"])
                LOG.info("kicked oldest session for user=%s (ip=%s)",
                         username, oldest["ip"])

    # --- Authorize ---
    timeout_s = int(svc.get("session_timeout", 3600))
    hard_timeout_s = int(svc.get("hard_timeout", 0) or 0)
    cp.nft_add_authenticated(ip, timeout_s)
    try:
        sid = cp.add_session(ip, mac, username, which, ua,
                             timeout_s, hard_timeout_s=hard_timeout_s)
    except Exception as e:
        LOG.warning("session DB write failed: %s", e)
        sid = 0

    LOG.info("portal auth OK user=%s ip=%s mac=%s backend=%s",
             username, ip, mac, which)
    return {
        "ok": True,
        "username": username,
        "auth_backend": which,
        "ip": ip,
        "session_id": sid,
        "expires_in": timeout_s,
    }


@action("captiveportal.splash_authorize")
def cp_splash_authorize(data):
    """Splash-only mode: authorize without credentials."""
    ip  = data.get("ip") or ""
    mac = (data.get("mac") or "").strip()
    ua  = data.get("user_agent") or ""
    if not ip:
        return {"ok": False, "error": "client ip required"}
    try:
        import ipaddress
        ipaddress.ip_address(ip)
    except Exception:
        return {"ok": False, "error": "invalid client ip"}

    cfg = _effective_config()
    svc = cfg.get("services", {}).get("captiveportal_config", {}) or {}
    if not svc.get("enabled"):
        return {"ok": False, "error": "captive portal is disabled"}
    if svc.get("auth_mode") != "splash":
        return {"ok": False, "error": "splash mode not enabled"}

    if not mac:
        mac = cp.get_mac_from_ip(ip)

    timeout_s = int(svc.get("session_timeout", 3600))
    hard_timeout_s = int(svc.get("hard_timeout", 0) or 0)
    cp.nft_add_authenticated(ip, timeout_s)
    try:
        sid = cp.add_session(ip, mac, "splash", "splash", ua,
                             timeout_s, hard_timeout_s=hard_timeout_s)
    except Exception as e:
        LOG.warning("session DB write failed: %s", e)
        sid = 0

    LOG.info("splash authorize OK ip=%s mac=%s", ip, mac)
    return {"ok": True, "ip": ip, "session_id": sid, "expires_in": timeout_s}


@action("captiveportal.welcome_back_reactivate")
def cp_welcome_back_reactivate(data):
    """Portal calls this on GET /. If a revoked session for the client's MAC
    is inside the grace window, reactivate it (no credentials needed)."""
    ip  = data.get("ip") or ""
    mac = (data.get("mac") or "").strip()
    ua  = data.get("user_agent") or ""
    if not ip:
        return {"ok": False, "reason": "ip required"}

    cfg = _effective_config()
    svc = cfg.get("services", {}).get("captiveportal_config", {}) or {}
    if not svc.get("enabled"):
        return {"ok": False, "reason": "portal disabled"}
    wb = int(svc.get("welcome_back", 0) or 0)
    if wb <= 0:
        return {"ok": False, "reason": "welcome_back disabled"}

    if not mac:
        mac = cp.get_mac_from_ip(ip)
    if not mac:
        return {"ok": False, "reason": "cannot resolve mac"}

    sess = cp.find_welcome_back_session(mac, wb)
    if not sess:
        return {"ok": False, "reason": "no eligible session"}

    timeout_s = int(svc.get("session_timeout", 3600))
    react = cp.reactivate_welcome_back(sess["id"], ip, timeout_s)
    if not react:
        return {"ok": False, "reason": "hard timeout exceeded"}

    cp.nft_add_authenticated(ip, timeout_s)
    LOG.info("welcome-back reactivate ip=%s mac=%s user=%s",
             ip, mac, react.get("username"))
    return {
        "ok": True,
        "username": react.get("username"),
        "auth_backend": react.get("auth_backend"),
        "session_id": react["id"],
        "expires_in": timeout_s,
    }



@action("captiveportal.logout")
def cp_logout(data):
    ip = data.get("ip") or ""
    if not ip:
        raise ValueError("ip required")
    existed = cp.end_session(ip)
    nft_res = cp.nft_remove_authenticated(ip)
    return {"ip": ip, "had_session": existed, "nft": nft_res}


@action("captiveportal.sessions.list")
def cp_sessions_list(data):
    limit = int(data.get("limit") or 500)
    kind = (data.get("kind") or "all").lower()
    q = (data.get("q") or "").strip()
    include_revoked = bool(data.get("include_revoked", False))
    return {
        "sessions": cp.list_sessions_filtered(
            kind=kind, q=q,
            include_revoked=include_revoked, limit=limit),
        "filter": {"kind": kind, "q": q, "include_revoked": include_revoked},
    }


@action("captiveportal.sessions.kick")
def cp_sessions_kick(data):
    ip = data.get("ip") or ""
    if not ip:
        raise ValueError("ip required")
    ttl = int(data.get("ttl") or 3600)

    # Look up the session to decide which kick semantics apply
    sess = cp.get_session_by_ip_any_state(ip)
    if sess and sess.get("auth_backend") == "mac_bypass" and sess.get("mac"):
        # Bypass kick: suppress the MAC for ttl, then refresh so nft updates
        result = cp.bypass_kick_mac(sess["mac"], ttl_s=ttl)
        cfg = _effective_config()
        try:
            cp.refresh_bypass(cfg)
        except Exception as e:
            LOG.warning("refresh after bypass kick failed: %s", e)
        # Recompile firewall so cp_bypassed_v4 reflects the kick
        fw = _call_configd("firewall.apply_staged")
        return {
            "ip": ip,
            "mac": sess["mac"],
            "kicked": True,
            "kind": "mac_bypass",
            "ttl_s": result["ttl_s"],
            "firewall_applied": bool((fw or {}).get("ok")),
        }

    # Regular auth/voucher/splash: just disconnect
    existed = cp.end_session(ip)
    nft_res = cp.nft_remove_authenticated(ip)
    return {"ip": ip, "kicked": existed, "kind": "session", "nft": nft_res}


@action("captiveportal.sessions.unkick")
def cp_sessions_unkick(data):
    """Clear a bypass kick so the MAC can be bypassed again."""
    ip = data.get("ip") or ""
    mac = (data.get("mac") or "").strip().upper()
    if not mac and ip:
        sess = cp.get_session_by_ip_any_state(ip)
        mac = (sess or {}).get("mac", "").upper()
    if not mac:
        raise ValueError("mac or ip required")
    cleared = cp.clear_bypass_kick(mac)
    cfg = _effective_config()
    try:
        cp.refresh_bypass(cfg)
    except Exception as e:
        LOG.warning("refresh after unkick failed: %s", e)
    fw = _call_configd("firewall.apply_staged")
    return {
        "mac": mac,
        "cleared": cleared,
        "firewall_applied": bool((fw or {}).get("ok")),
    }


@action("captiveportal.bypass.kicks_list")
def cp_bypass_kicks_list(_data):
    return {"kicks": cp.list_bypass_kicks()}


@action("captiveportal.prune")
def cp_prune(_data):
    cfg = _effective_config()
    svc = cfg.get("services", {}).get("captiveportal_config", {}) or {}
    idle = int(svc.get("idle_timeout", 600))
    wb = int(svc.get("welcome_back", 0) or 0)
    removed = cp.prune_expired(idle_timeout_s=idle, welcome_back_s=wb)
    for ip in removed:
        cp.nft_remove_authenticated(ip)
    return {"removed": removed, "count": len(removed)}


@action("captiveportal.status")
def cp_status(_data):
    cfg = _effective_config()
    svc = cfg.get("services", {}).get("captiveportal_config", {}) or {}
    out: dict[str, Any] = {
        "enabled": bool(svc.get("enabled")),
        "portal_port": svc.get("portal_port", 8081),
        "interface": svc.get("interface", "lan"),
        "session_timeout": svc.get("session_timeout", 3600),
        "auth_mode": svc.get("auth_mode", "multi"),
        "concurrent_logins": int(svc.get("concurrent_logins", 0) or 0),
        "hard_timeout": int(svc.get("hard_timeout", 0) or 0),
        "welcome_back": int(svc.get("welcome_back", 0) or 0),
    }
    # service state
    r = _run(["systemctl", "is-active", "nfw-portal"])
    out["service"] = r["stdout"].strip() or "unknown"
    # nft set size
    ips = cp.nft_list_authenticated()
    out["nft_authenticated_count"] = len(ips)
    out["nft_authenticated_sample"] = ips[:5]
    # sessions in DB
    try:
        sessions = cp.list_sessions(limit=500)
        out["sessions_count"] = len(sessions)
    except Exception as e:
        out["sessions_count"] = -1
        out["sessions_error"] = str(e)
    return out

# ---------------------------------------------------------------------------
# Phase 9.18b1 — Vouchers
# ---------------------------------------------------------------------------
@action("captiveportal.vouchers.generate")
def cp_vouchers_generate(data):
    cfg = _effective_config()
    vd = (cfg.get("services", {}).get("captiveportal_config", {}) or {}).get("voucher_defaults", {}) or {}

    count       = int(data.get("count") or 1)
    length      = int(data.get("length") or vd.get("code_length") or 8)
    alphabet    = data.get("alphabet") or vd.get("code_alphabet")
    prefix      = str(data.get("prefix") or vd.get("batch_prefix") or "")
    group_name  = str(data.get("group_name") or "").strip()
    notes       = str(data.get("notes") or "").strip()
    validity    = int(data.get("validity_minutes") or vd.get("validity_minutes") or 1440)
    session_t   = int(data.get("session_timeout") or vd.get("session_timeout") or 3600)
    max_s       = int(data.get("max_sessions") or vd.get("max_sessions") or 1)
    expires_at  = data.get("expires_at")  # unix ts or None
    if expires_at is not None:
        expires_at = int(expires_at)
    bw_up   = int(data.get("bandwidth_up_kbps") or 0)
    bw_down = int(data.get("bandwidth_down_kbps") or 0)

    created = cp.generate_vouchers(
        count=count, length=length, validity_minutes=validity,
        session_timeout=session_t, max_sessions=max_s,
        group_name=group_name, notes=notes, expires_at=expires_at,
        alphabet=alphabet, prefix=prefix,
        bandwidth_up_kbps=bw_up, bandwidth_down_kbps=bw_down,
    )
    return {"created": len(created), "vouchers": created}


@action("captiveportal.vouchers.list")
def cp_vouchers_list(data):
    group = data.get("group_name")
    include_used     = bool(data.get("include_used", True))
    include_disabled = bool(data.get("include_disabled", True))
    limit = int(data.get("limit") or 2000)
    return {
        "vouchers": cp.list_vouchers(
            group_name=group,
            include_used=include_used,
            include_disabled=include_disabled,
            limit=limit,
        )
    }


@action("captiveportal.vouchers.groups")
def cp_vouchers_groups(_data):
    return {"groups": cp.list_voucher_groups()}


@action("captiveportal.vouchers.delete")
def cp_vouchers_delete(data):
    vid = data.get("id")
    if vid is None:
        raise ValueError("id required")
    ok = cp.delete_voucher(int(vid))
    if not ok:
        raise FileNotFoundError(f"voucher {vid} not found")
    return {"deleted": vid}


@action("captiveportal.vouchers.delete_group")
def cp_vouchers_delete_group(data):
    group = data.get("group_name")
    if not group:
        raise ValueError("group_name required")
    n = cp.delete_voucher_group(group)
    return {"deleted": n, "group_name": group}


@action("captiveportal.vouchers.set_enabled")
def cp_vouchers_set_enabled(data):
    vid = int(data.get("id"))
    enabled = bool(data.get("enabled", True))
    ok = cp.set_voucher_enabled(vid, enabled)
    if not ok:
        raise FileNotFoundError(f"voucher {vid} not found")
    return {"id": vid, "enabled": enabled}


@action("captiveportal.vouchers.export_csv")
def cp_vouchers_export_csv(data):
    group = data.get("group_name")
    include_used = bool(data.get("include_used", True))
    include_disabled = bool(data.get("include_disabled", True))
    vouchers = cp.list_vouchers(
        group_name=group,
        include_used=include_used,
        include_disabled=include_disabled,
        limit=20000,
    )
    return {"csv": cp.vouchers_to_csv(vouchers), "count": len(vouchers)}


@action("captiveportal.vouchers.redeem")
def cp_vouchers_redeem(data):
    """Called by the portal app. Validates + consumes a voucher and
    authorizes the client's IP for the session duration."""
    code = str(data.get("code") or "").strip().upper()
    ip   = str(data.get("ip") or "")
    mac  = str(data.get("mac") or "")
    ua   = str(data.get("user_agent") or "")
    if not code:
        return {"ok": False, "error": "voucher code required"}
    if not ip:
        return {"ok": False, "error": "client ip required"}
    try:
        import ipaddress
        ipaddress.ip_address(ip)
    except Exception:
        return {"ok": False, "error": "invalid client ip"}

    cfg = _effective_config()
    svc = cfg.get("services", {}).get("captiveportal_config", {}) or {}
    if not svc.get("enabled"):
        return {"ok": False, "error": "captive portal is disabled"}

    if not mac:
        mac = cp.get_mac_from_ip(ip)

    result = cp.voucher_redeem(code, ip, mac)
    if not result.get("ok"):
        LOG.info("voucher redeem FAIL code=%s ip=%s: %s",
                 code, ip, result.get("reason"))
        return {"ok": False, "error": result.get("reason", "invalid voucher")}

    session_secs = int(result["session_seconds"])
    hard_timeout_s = int(svc.get("hard_timeout", 0) or 0)
    cp.nft_add_authenticated(ip, session_secs)

    # Store the session row with auth_backend="voucher"
    try:
        cp.add_session(ip, mac, code, "voucher", ua, session_secs,
                       hard_timeout_s=hard_timeout_s)
    except Exception as e:
        LOG.warning("session DB write failed: %s", e)

    LOG.info("voucher redeem OK code=%s ip=%s secs=%d",
             code, ip, session_secs)
    return {
        "ok": True,
        "code": code,
        "ip": ip,
        "expires_in": session_secs,
    }

# ---------------------------------------------------------------------------
# Phase 9.18b3 — Bypass (MAC + hostname)
# ---------------------------------------------------------------------------
@action("captiveportal.bypass_refresh")
def cp_bypass_refresh(_data):
    """Resolve MACs and hostnames, rewrite caches, recompile firewall if
    the caches changed."""
    cfg = _effective_config()
    svc = cfg.get("services", {}).get("captiveportal_config", {}) or {}
    if not svc.get("enabled"):
        return {"changed": False, "skipped": "portal disabled"}

    result = cp.refresh_bypass(cfg)

    if result.get("changed"):
        fw = _call_configd("firewall.apply_staged")
        fw_ok = bool((fw or {}).get("ok"))
        result["firewall_applied"] = fw_ok
        if not fw_ok:
            result["firewall_error"] = str((fw or {}).get("stderr") or
                                            (fw or {}).get("error") or "unknown")[:300]
            LOG.error("firewall.apply_staged after bypass change failed: %s",
                      result["firewall_error"])
        else:
            LOG.info("bypass refresh: caches changed, firewall reapplied "
                     "(mac=%d, host=%d)",
                     len(result.get("mac_ips") or []),
                     len(result.get("hostname_ips") or []))
    else:
        result["firewall_applied"] = False

    return result


@action("captiveportal.bypass_status")
def cp_bypass_status(_data):
    meta = cp.read_bypass_meta()
    svc = _effective_config().get("services", {}).get(
        "captiveportal_config", {}) or {}
    return {
        "configured_macs": svc.get("bypass_macs") or [],
        "configured_hostnames": svc.get("bypass_hostnames") or [],
        "refresh_seconds": int(svc.get("bypass_refresh_seconds", 120) or 120),
        "cache": meta,
        "current_mac_ips": cp.load_bypass_mac_ips(),
        "current_hostname_ips": cp.load_bypass_hostname_ips(),
    }

# ---------------------------------------------------------------------------
# Phase 9.18b4 — Template management
# ---------------------------------------------------------------------------
import base64 as _b64


@action("captiveportal.templates.list")
def cp_tpl_list(_data):
    return {"templates": cp.list_templates()}


@action("captiveportal.templates.upload")
def cp_tpl_upload(data):
    """ZIP payload arrives base64-encoded in data['zip_b64'] (simple over
    the JSON socket protocol)."""
    zip_b64 = data.get("zip_b64") or ""
    if not zip_b64:
        raise ValueError("zip_b64 required")
    try:
        raw = _b64.b64decode(zip_b64, validate=True)
    except Exception as e:
        raise ValueError(f"bad base64: {e}")
    name = (data.get("name") or "").strip()
    entry = cp.extract_template_zip(raw, name)
    return {"template": entry}


@action("captiveportal.templates.delete")
def cp_tpl_delete(data):
    tid = data.get("id") or ""
    if not tid:
        raise ValueError("id required")
    ok = cp.delete_template(tid)
    if not ok:
        raise FileNotFoundError(f"template {tid} not found")
    # Clear config reference if it pointed at this template
    cfg = _effective_config()
    rc = cfg.get("services", {}).get("captiveportal_config", {}) or {}
    if rc.get("template_id") == tid:
        rc["template_id"] = ""
        cfg["services"]["captiveportal_config"] = rc
        _stage_then_commit(cfg, f"captiveportal: template {tid} deleted, reverting to default")
    return {"deleted": tid}


@action("captiveportal.templates.files")
def cp_tpl_files(data):
    tid = data.get("id") or ""
    if not tid:
        raise ValueError("id required")
    if not cp.get_template(tid):
        raise FileNotFoundError(f"template {tid} not found")
    return {"files": cp.list_template_files(tid)}


@action("captiveportal.templates.file_get")
def cp_tpl_file_get(data):
    tid = data.get("id") or ""
    path = data.get("path") or ""
    f = cp.read_template_file(tid, path)
    if not f:
        raise FileNotFoundError(f"{path} not found")
    return f


@action("captiveportal.templates.file_put")
def cp_tpl_file_put(data):
    tid = data.get("id") or ""
    path = data.get("path") or ""
    content = data.get("content")
    if content is None:
        raise ValueError("content required")
    ok = cp.write_template_file(tid, path, content)
    if not ok:
        raise ValueError("write failed")
    return {"ok": True}


@action("captiveportal.templates.file_delete")
def cp_tpl_file_delete(data):
    tid = data.get("id") or ""
    path = data.get("path") or ""
    ok = cp.delete_template_file(tid, path)
    if not ok:
        raise FileNotFoundError(f"{path} not found")
    return {"deleted": path}


@action("captiveportal.templates.download_starter")
def cp_tpl_download_starter(_data):
    raw = cp.build_starter_zip()
    return {"zip_b64": _b64.b64encode(raw).decode("ascii"),
            "filename": "nfw-portal-starter.zip"}

