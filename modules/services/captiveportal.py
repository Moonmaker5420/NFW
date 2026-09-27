"""Captive portal state helpers (Phase 9.18a).

Responsibilities:
  - Write the JSON the portal frontend reads (branding, timeouts, walled garden)
  - Manage the SQLite session store
  - Manipulate the `cp_authenticated_v4` nftables sets
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import sqlite3
import subprocess
import time
from pathlib import Path
from typing import Any

LOG = logging.getLogger("captiveportal")

CP_DIR     = Path("/var/lib/nfw/captiveportal")
DB_PATH    = CP_DIR / "sessions.db"
CONF_JSON  = CP_DIR / "portal.json"
BYPASS_MAC_IPS   = CP_DIR / "bypass_mac_ips.txt"
BYPASS_HOST_IPS  = CP_DIR / "bypass_hostname_ips.txt"
BYPASS_META      = CP_DIR / "bypass.meta.json"

# Phase 9.18b4 — custom templates
TPL_DIR       = CP_DIR / "templates"
TPL_REGISTRY  = CP_DIR / "templates.json"
TPL_MAX_BYTES = 5 * 1024 * 1024
TPL_MAX_FILES = 200
TPL_ALLOWED_EXTS = {
    ".html", ".htm", ".css", ".js", ".png", ".jpg", ".jpeg",
    ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".otf",
    ".txt", ".md", ".json",
}

# Where the compiler will put the authenticated-source set
NFT_FILTER_TABLE = ("inet", "nfw_filter")
NFT_NAT_TABLE    = ("ip", "nfw_nat")
NFT_SET_NAME     = "cp_authenticated_v4"


# ---------------------------------------------------------------------------
# Filesystem
# ---------------------------------------------------------------------------
def ensure_dirs() -> None:
    """Create/repair the CP directory. 0770 root:nfw so nfw-portal
    (www-data:nfw) can write SQLite journals + read portal.json."""
    CP_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(CP_DIR, 0o770)
        os.chown(CP_DIR, 0, _gid_nfw())
    except OSError:
        pass


def _gid_nfw() -> int:
    try:
        import grp
        return grp.getgrnam("nfw").gr_gid
    except (KeyError, ImportError):
        return 0


def write_portal_config(cfg: dict) -> None:
    """Materialize the portal config JSON the frontend reads at startup."""
    ensure_dirs()
    svc = cfg.get("services", {}).get("captiveportal_config", {}) or {}

    # Resolve LAN IP so the portal knows where to redirect clients
    listen_ip = ""
    net = cfg.get("network", {}) or {}
    lan_iface = net.get("lan") or ""
    for name, icfg in (net.get("interfaces", {}) or {}).items():
        if name == lan_iface:
            listen_ip = icfg.get("ipv4", {}).get("address", "") or ""
            break
    if not listen_ip:
        listen_ip = "192.168.10.1"   # conservative fallback

    payload = {
        "gateway_name":      svc.get("gateway_name") or "NFW Captive Portal",
        "listen_ip":         listen_ip,
        "portal_port":       int(svc.get("portal_port", 8081)),
        "session_timeout":   int(svc.get("session_timeout", 3600)),
        "idle_timeout":      int(svc.get("idle_timeout", 600)),
        "auth_backends":     svc.get("auth_backends") or ["local", "ldap"],
        "tos_required":      bool(svc.get("tos_required", False)),
        "tos_text":          svc.get("tos_text") or "",
        "walled_garden":     svc.get("walled_garden") or [],
        "branding":          svc.get("branding") or {},
        # Phase 9.18b2 fields
        "auth_mode":         svc.get("auth_mode", "multi"),
        "splash_label":      svc.get("splash_label", "Connect"),
        "splash_extra_text": svc.get("splash_extra_text", ""),
        "concurrent_logins": int(svc.get("concurrent_logins", 0) or 0),
        "concurrent_mode":   svc.get("concurrent_mode", "deny_new"),
        "hard_timeout":      int(svc.get("hard_timeout", 0) or 0),
        "welcome_back":      int(svc.get("welcome_back", 0) or 0),
        # Phase 9.18b4 fields
        "template_id":       svc.get("template_id", "") or "",
        "dhcp_option_114":   bool(svc.get("dhcp_option_114", True)),
        "redirect_after_login": svc.get("redirect_after_login", "") or "",
        "generated_at":      int(time.time()),
    }
    tmp = CONF_JSON.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True))
    os.chmod(tmp, 0o660)
    try: os.chown(tmp, 0, _gid_nfw())
    except OSError: pass
    os.replace(tmp, CONF_JSON)


# ---------------------------------------------------------------------------
# SQLite session store
# ---------------------------------------------------------------------------
_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ip              TEXT NOT NULL,
    mac             TEXT,
    username        TEXT NOT NULL,
    auth_backend    TEXT NOT NULL,
    user_agent      TEXT,
    started_at      INTEGER NOT NULL,
    last_seen_at    INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    hard_expires_at INTEGER,
    revoked_at      INTEGER,
    revoke_reason   TEXT NOT NULL DEFAULT '',
    bytes_in        INTEGER DEFAULT 0,
    bytes_out       INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_sessions_ip ON sessions(ip);
CREATE INDEX IF NOT EXISTS ix_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS ix_sessions_user ON sessions(username);

CREATE TABLE IF NOT EXISTS vouchers (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    code                TEXT NOT NULL UNIQUE COLLATE NOCASE,
    group_name          TEXT NOT NULL DEFAULT '',
    notes               TEXT NOT NULL DEFAULT '',
    created_at          INTEGER NOT NULL,
    expires_at          INTEGER,                    -- NULL = no absolute deadline
    validity_minutes    INTEGER NOT NULL DEFAULT 1440,
    session_timeout     INTEGER NOT NULL DEFAULT 3600,
    max_sessions        INTEGER NOT NULL DEFAULT 1,
    session_count       INTEGER NOT NULL DEFAULT 0,
    redeemed_at         INTEGER,
    redeemed_by_ip      TEXT NOT NULL DEFAULT '',
    redeemed_by_mac     TEXT NOT NULL DEFAULT '',
    last_used_at        INTEGER,
    bandwidth_up_kbps   INTEGER NOT NULL DEFAULT 0,  -- enforced in 9.18b5
    bandwidth_down_kbps INTEGER NOT NULL DEFAULT 0,
    enabled             INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS ix_vouchers_code    ON vouchers(code);
CREATE INDEX IF NOT EXISTS ix_vouchers_group   ON vouchers(group_name);
CREATE INDEX IF NOT EXISTS ix_vouchers_enabled ON vouchers(enabled);

CREATE TABLE IF NOT EXISTS bypass_kicks (
    mac           TEXT PRIMARY KEY COLLATE NOCASE,
    kicked_at     INTEGER NOT NULL,
    kicked_until  INTEGER NOT NULL,
    reason        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_bypass_kicks_until ON bypass_kicks(kicked_until);
"""


def db() -> sqlite3.Connection:
    ensure_dirs()
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    conn.commit()
    _migrate_schema(conn)
    try:
        os.chmod(DB_PATH, 0o660)
        os.chown(DB_PATH, 0, _gid_nfw())
    except OSError:
        pass
    return conn


def _migrate_schema(conn: sqlite3.Connection) -> None:
    """Add 9.18b2 columns to pre-existing sessions tables."""
    cols = {r[1] for r in conn.execute("PRAGMA table_info(sessions)").fetchall()}
    for col, ddl in (
        ("hard_expires_at", "ALTER TABLE sessions ADD COLUMN hard_expires_at INTEGER"),
        ("revoked_at",      "ALTER TABLE sessions ADD COLUMN revoked_at INTEGER"),
        ("revoke_reason",   "ALTER TABLE sessions ADD COLUMN revoke_reason TEXT NOT NULL DEFAULT ''"),
    ):
        if col not in cols:
            try:
                conn.execute(ddl)
            except sqlite3.OperationalError:
                pass
    conn.commit()


def add_session(ip: str, mac: str | None, username: str,
                backend: str, user_agent: str | None,
                timeout_s: int, hard_timeout_s: int = 0) -> int:
    now = int(time.time())
    hard_exp = now + hard_timeout_s if hard_timeout_s > 0 else None
    mac = (mac or "").upper()
    with db() as conn:
        # Replace any existing session for this IP (re-login)
        conn.execute("DELETE FROM sessions WHERE ip = ?", (ip,))
        cur = conn.execute(
            "INSERT INTO sessions "
            "(ip, mac, username, auth_backend, user_agent, "
            " started_at, last_seen_at, expires_at, hard_expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ip, mac or "", username, backend, user_agent or "",
             now, now, now + timeout_s, hard_exp),
        )
        conn.commit()
        return cur.lastrowid or 0


def touch_session(ip: str) -> None:
    with db() as conn:
        conn.execute(
            "UPDATE sessions SET last_seen_at = ? WHERE ip = ?",
            (int(time.time()), ip),
        )
        conn.commit()


def get_session(ip: str) -> dict | None:
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE ip = ?", (ip,)
        ).fetchone()
    return dict(row) if row else None


def list_sessions(limit: int = 500) -> list[dict]:
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM sessions ORDER BY started_at DESC LIMIT ?",
            (int(limit),),
        ).fetchall()
    return [dict(r) for r in rows]


def end_session(ip: str) -> bool:
    with db() as conn:
        cur = conn.execute("DELETE FROM sessions WHERE ip = ?", (ip,))
        conn.commit()
        return cur.rowcount > 0


def prune_expired(idle_timeout_s: int = 0,
                  welcome_back_s: int = 0) -> list[str]:
    """Reap expired/idle sessions.

    Behaviour:
      - Sessions past hard_expires_at are revoked (cannot welcome back).
      - Sessions past expires_at are revoked (can welcome back).
      - Revoked sessions older than welcome_back_s are deleted outright.
      - Returns IPs that should have their nft set membership cleared.
    """
    now = int(time.time())
    with db() as conn:
        # Hard-expired sessions: revoke, no welcome back
        conn.execute(
            "UPDATE sessions SET revoked_at = ?, revoke_reason = 'hard_timeout' "
            "WHERE revoked_at IS NULL AND hard_expires_at IS NOT NULL "
            "AND hard_expires_at <= ?",
            (now, now),
        )
        # Soft-expired: revoke, allow welcome back
        conn.execute(
            "UPDATE sessions SET revoked_at = ?, revoke_reason = 'session_timeout' "
            "WHERE revoked_at IS NULL AND expires_at <= ?",
            (now, now),
        )
        # Idle timeout
        if idle_timeout_s > 0:
            idle_cut = now - idle_timeout_s
            conn.execute(
                "UPDATE sessions SET revoked_at = ?, revoke_reason = 'idle' "
                "WHERE revoked_at IS NULL AND last_seen_at <= ? "
                "AND auth_backend != 'mac_bypass'",
                (now, idle_cut),
            )
        rows = conn.execute(
            "SELECT ip FROM sessions WHERE revoked_at = ?", (now,)
        ).fetchall()
        removed_ips = [r["ip"] for r in rows]
        # Drop sessions past grace
        if welcome_back_s <= 0:
            conn.execute(
                "DELETE FROM sessions WHERE revoked_at IS NOT NULL AND revoked_at <= ?",
                (now,),
            )
        else:
            conn.execute(
                "DELETE FROM sessions WHERE revoked_at IS NOT NULL "
                "AND (revoked_at + ?) <= ?",
                (welcome_back_s, now),
            )
        conn.commit()
    return removed_ips


# ---------------------------------------------------------------------------
# MAC lookup (ARP/NDP) — needed for Welcome Back
# ---------------------------------------------------------------------------
def get_mac_from_ip(ip: str) -> str:
    """Read the kernel neighbour table for the MAC of a given IP.

    Tries /proc/net/arp first, then `ip neigh`. Returns uppercase
    colon-separated MAC or empty string.
    """
    try:
        with open("/proc/net/arp") as f:
            for line in f:
                parts = line.split()
                if (len(parts) >= 4 and parts[0] == ip
                        and parts[3] != "00:00:00:00:00:00"):
                    return parts[3].upper()
    except OSError:
        pass
    import subprocess as _sp
    try:
        r = _sp.run(["ip", "neigh", "show", ip],
                    capture_output=True, text=True, timeout=3)
        for line in r.stdout.splitlines():
            if "lladdr" in line:
                parts = line.split()
                idx = parts.index("lladdr")
                if idx + 1 < len(parts):
                    return parts[idx + 1].upper()
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------------------
# Concurrency + welcome back
# ---------------------------------------------------------------------------
def active_sessions_for_user(username: str) -> list[dict]:
    now = int(time.time())
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM sessions WHERE username = ? AND revoked_at IS NULL "
            "AND expires_at > ? ORDER BY started_at ASC",
            (username, now),
        ).fetchall()
    return [dict(r) for r in rows]


def revoke_session_by_id(session_id: int, reason: str) -> dict | None:
    now = int(time.time())
    with db() as conn:
        row = conn.execute("SELECT * FROM sessions WHERE id = ?",
                           (session_id,)).fetchone()
        if not row:
            return None
        conn.execute(
            "UPDATE sessions SET revoked_at = ?, revoke_reason = ? WHERE id = ?",
            (now, reason, session_id),
        )
        conn.commit()
    return dict(row)


def find_welcome_back_session(mac: str, grace_s: int) -> dict | None:
    """Return a revoked session in its grace window matching MAC."""
    if not mac or grace_s <= 0:
        return None
    now = int(time.time())
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM sessions "
            "WHERE mac = ? AND revoked_at IS NOT NULL "
            "AND (revoked_at + ?) > ? "
            "AND (hard_expires_at IS NULL OR hard_expires_at > ?) "
            "ORDER BY revoked_at DESC LIMIT 1",
            (mac.upper(), grace_s, now, now),
        ).fetchone()
    return dict(row) if row else None


def reactivate_welcome_back(session_id: int, new_ip: str,
                            timeout_s: int) -> dict | None:
    """Re-authorize a previously-revoked session. hard_expires_at unchanged."""
    now = int(time.time())
    with db() as conn:
        row = conn.execute("SELECT * FROM sessions WHERE id = ?",
                           (session_id,)).fetchone()
        if not row:
            return None
        if row["hard_expires_at"] and row["hard_expires_at"] <= now:
            return None
        conn.execute(
            "UPDATE sessions SET ip = ?, last_seen_at = ?, "
            "expires_at = ?, revoked_at = NULL, revoke_reason = '' "
            "WHERE id = ?",
            (new_ip, now, now + timeout_s, session_id),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM sessions WHERE id = ?",
                           (session_id,)).fetchone()
    return dict(row) if row else None


def get_session_by_ip_any_state(ip: str) -> dict | None:
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE ip = ? "
            "ORDER BY last_seen_at DESC LIMIT 1", (ip,),
        ).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# Vouchers
# ---------------------------------------------------------------------------
import secrets
import string

DEFAULT_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"   # no 0/O/1/I/L


def _generate_code(length: int, alphabet: str, prefix: str = "") -> str:
    body = "".join(secrets.choice(alphabet) for _ in range(length))
    return (prefix + body) if prefix else body


def generate_vouchers(count: int, length: int = 8,
                      validity_minutes: int = 1440,
                      session_timeout: int = 3600,
                      max_sessions: int = 1,
                      group_name: str = "",
                      notes: str = "",
                      expires_at: int | None = None,
                      alphabet: str | None = None,
                      prefix: str = "",
                      bandwidth_up_kbps: int = 0,
                      bandwidth_down_kbps: int = 0) -> list[dict]:
    """Generate `count` vouchers. Retries on UNIQUE collisions."""
    if count < 1 or count > 5000:
        raise ValueError("count must be 1..5000")
    if length < 4 or length > 32:
        raise ValueError("length must be 4..32")
    if validity_minutes < 1:
        raise ValueError("validity_minutes must be >= 1")
    if session_timeout < 60:
        raise ValueError("session_timeout must be >= 60")
    if max_sessions < 1 or max_sessions > 1000:
        raise ValueError("max_sessions must be 1..1000")

    alpha = alphabet or DEFAULT_ALPHABET
    # Dedupe alphabet and strip whitespace
    alpha = "".join(dict.fromkeys(c for c in alpha if not c.isspace()))
    if len(alpha) < 16:
        raise ValueError("alphabet must have >=16 unique chars")

    now = int(time.time())
    created: list[dict] = []

    with db() as conn:
        for _ in range(count):
            for attempt in range(8):
                code = _generate_code(length, alpha, prefix)
                try:
                    cur = conn.execute(
                        "INSERT INTO vouchers "
                        "(code, group_name, notes, created_at, expires_at, "
                        " validity_minutes, session_timeout, max_sessions, "
                        " bandwidth_up_kbps, bandwidth_down_kbps) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (code, group_name, notes, now, expires_at,
                         validity_minutes, session_timeout, max_sessions,
                         bandwidth_up_kbps, bandwidth_down_kbps),
                    )
                    created.append({
                        "id": cur.lastrowid,
                        "code": code,
                        "group_name": group_name,
                        "notes": notes,
                        "created_at": now,
                        "expires_at": expires_at,
                        "validity_minutes": validity_minutes,
                        "session_timeout": session_timeout,
                        "max_sessions": max_sessions,
                        "bandwidth_up_kbps": bandwidth_up_kbps,
                        "bandwidth_down_kbps": bandwidth_down_kbps,
                    })
                    break
                except sqlite3.IntegrityError:
                    continue
            else:
                # Exhausted retries — very unlikely with default alphabet
                raise RuntimeError("could not generate unique voucher after 8 attempts")
        conn.commit()
    LOG.info("generated %d voucher(s) group=%r", len(created), group_name)
    return created


def list_vouchers(group_name: str | None = None,
                  include_used: bool = True,
                  include_disabled: bool = True,
                  limit: int = 2000) -> list[dict]:
    q = "SELECT * FROM vouchers WHERE 1=1"
    params: list = []
    if group_name is not None:
        q += " AND group_name = ?"; params.append(group_name)
    if not include_used:
        q += " AND (max_sessions - session_count) > 0"
    if not include_disabled:
        q += " AND enabled = 1"
    q += " ORDER BY created_at DESC, id DESC LIMIT ?"
    params.append(int(limit))
    with db() as conn:
        rows = conn.execute(q, params).fetchall()
    return [dict(r) for r in rows]


def list_voucher_groups() -> list[dict]:
    with db() as conn:
        rows = conn.execute(
            "SELECT group_name, COUNT(*) AS n, "
            "       SUM(CASE WHEN redeemed_at IS NULL THEN 1 ELSE 0 END) AS unused, "
            "       SUM(CASE WHEN enabled = 0 THEN 1 ELSE 0 END) AS disabled "
            "FROM vouchers GROUP BY group_name ORDER BY group_name"
        ).fetchall()
    return [dict(r) for r in rows]


def delete_voucher(voucher_id: int) -> bool:
    with db() as conn:
        cur = conn.execute("DELETE FROM vouchers WHERE id = ?", (voucher_id,))
        conn.commit()
        return cur.rowcount > 0


def delete_voucher_group(group_name: str) -> int:
    with db() as conn:
        cur = conn.execute("DELETE FROM vouchers WHERE group_name = ?",
                           (group_name,))
        conn.commit()
        return cur.rowcount


def set_voucher_enabled(voucher_id: int, enabled: bool) -> bool:
    with db() as conn:
        cur = conn.execute("UPDATE vouchers SET enabled = ? WHERE id = ?",
                           (1 if enabled else 0, voucher_id))
        conn.commit()
        return cur.rowcount > 0


def voucher_lookup(code: str) -> dict | None:
    if not code:
        return None
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM vouchers WHERE code = ? COLLATE NOCASE",
            (code.strip(),),
        ).fetchone()
    return dict(row) if row else None


def voucher_redeem(code: str, ip: str, mac: str,
                   requested_seconds: int | None = None) -> dict:
    """Validate + consume one session of a voucher.

    Returns a dict:
      {ok: True, voucher: {...}, session_seconds: N}
      or
      {ok: False, reason: '...'}

    Never raises for expected failures; raises only on internal errors.
    """
    now = int(time.time())
    v = voucher_lookup(code)
    if not v:
        return {"ok": False, "reason": "voucher not found"}
    if not v.get("enabled"):
        return {"ok": False, "reason": "voucher disabled"}
    if v.get("expires_at") and now >= int(v["expires_at"]):
        return {"ok": False, "reason": "voucher expired"}
    used = int(v["session_count"] or 0)
    limit = int(v["max_sessions"] or 1)
    if used >= limit:
        return {"ok": False, "reason": "voucher already used"}

    # Determine session length: from config override OR voucher default
    validity = int(v["validity_minutes"] or 1440) * 60
    session_secs = int(v["session_timeout"] or 3600)
    if requested_seconds is not None:
        session_secs = max(60, min(validity, int(requested_seconds)))

    with db() as conn:
        conn.execute(
            "UPDATE vouchers "
            "SET session_count = session_count + 1, "
            "    redeemed_at   = COALESCE(redeemed_at, ?), "
            "    redeemed_by_ip = CASE WHEN redeemed_at IS NULL THEN ? ELSE redeemed_by_ip END, "
            "    redeemed_by_mac = CASE WHEN redeemed_at IS NULL THEN ? ELSE redeemed_by_mac END, "
            "    last_used_at  = ? "
            "WHERE id = ? AND session_count < max_sessions",
            (now, ip, mac or "", now, v["id"]),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM vouchers WHERE id = ?",
                           (v["id"],)).fetchone()
    return {"ok": True, "voucher": dict(row), "session_seconds": session_secs}


def vouchers_to_csv(vouchers: list[dict]) -> str:
    import io as _io
    import csv as _csv
    buf = _io.StringIO()
    w = _csv.writer(buf)
    w.writerow(["code", "group_name", "validity_minutes", "session_timeout",
                "max_sessions", "expires_at", "bandwidth_up_kbps",
                "bandwidth_down_kbps", "notes"])
    for v in vouchers:
        w.writerow([
            v.get("code", ""),
            v.get("group_name", ""),
            v.get("validity_minutes", ""),
            v.get("session_timeout", ""),
            v.get("max_sessions", ""),
            v.get("expires_at") or "",
            v.get("bandwidth_up_kbps", ""),
            v.get("bandwidth_down_kbps", ""),
            v.get("notes", ""),
        ])
    return buf.getvalue()


# ---------------------------------------------------------------------------
# nftables set manipulation
# ---------------------------------------------------------------------------
def _run(cmd: list[str], timeout: int = 10) -> dict:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"rc": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
    except subprocess.TimeoutExpired:
        return {"rc": 124, "stdout": "", "stderr": "timeout"}
    except FileNotFoundError as e:
        return {"rc": 127, "stdout": "", "stderr": str(e)}


def _set_exists(family: str, table: str) -> bool:
    r = _run(["nft", "list", "set", family, table, NFT_SET_NAME])
    return r["rc"] == 0


def set_present_anywhere() -> bool:
    return (_set_exists(*NFT_FILTER_TABLE) or _set_exists(*NFT_NAT_TABLE))


def nft_add_authenticated(ip: str, timeout_s: int) -> dict:
    """Add source IP to cp_authenticated_v4 in both tables. No-op if absent."""
    # Validate
    ipaddress.ip_address(ip)
    results: dict[str, Any] = {"filter": None, "nat": None}
    element = f"{{ {ip} timeout {int(timeout_s)}s }}"
    for key, (family, table) in (("filter", NFT_FILTER_TABLE),
                                 ("nat",    NFT_NAT_TABLE)):
        if not _set_exists(family, table):
            results[key] = "set-absent"
            continue
        r = _run(["nft", "add", "element", family, table, NFT_SET_NAME, element])
        results[key] = "ok" if r["rc"] == 0 else r["stderr"][:200]
    return results


def nft_remove_authenticated(ip: str) -> dict:
    ipaddress.ip_address(ip)
    results: dict[str, Any] = {"filter": None, "nat": None}
    for key, (family, table) in (("filter", NFT_FILTER_TABLE),
                                 ("nat",    NFT_NAT_TABLE)):
        if not _set_exists(family, table):
            results[key] = "set-absent"
            continue
        r = _run(["nft", "delete", "element", family, table,
                  NFT_SET_NAME, f"{{ {ip} }}"])
        results[key] = "ok" if r["rc"] == 0 else r["stderr"][:200]
    return results


def nft_list_authenticated() -> list[str]:
    """Return IPs currently in the filter-table set.

    nft -j emits elements in one of two shapes depending on whether they
    carry timeouts:
        "elem": ["1.2.3.4", "5.6.7.8"]                    # plain
        "elem": [{"elem": {"val": "1.2.3.4",
                            "timeout": 600,
                            "expires": 599}}, ...]        # with timeout
    Handle both.
    """
    family, table = NFT_FILTER_TABLE
    r = _run(["nft", "-j", "list", "set", family, table, NFT_SET_NAME])
    if r["rc"] != 0:
        return []
    try:
        data = json.loads(r["stdout"])
    except Exception:
        return []

    out: list[str] = []

    def _walk_elem(el):
        if isinstance(el, str):
            out.append(el); return
        if isinstance(el, dict):
            if "val" in el:
                out.append(str(el["val"])); return
            if "elem" in el and isinstance(el["elem"], dict):
                _walk_elem(el["elem"]); return
            if "prefix" in el and isinstance(el["prefix"], dict):
                _walk_elem(el["prefix"]); return

    for item in data.get("nftables", []):
        st = item.get("set")
        if not st:
            continue
        for el in st.get("elem", []) or []:
            _walk_elem(el)
    return out

# ---------------------------------------------------------------------------
# Phase 9.18b3 — Bypass (MAC + hostname)
# ---------------------------------------------------------------------------
def get_all_arp_entries() -> dict[str, str]:
    """Return {MAC: IP} from /proc/net/arp + `ip neigh` (v4 only)."""
    out: dict[str, str] = {}
    try:
        with open("/proc/net/arp") as f:
            next(f, None)
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                    ip, mac = parts[0], parts[3].upper()
                    if ":" in ip and ip.count(".") == 3:  # IPv4 only
                        out[mac] = ip
    except OSError:
        pass
    import subprocess as _sp
    try:
        r = _sp.run(["ip", "neigh"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            if "lladdr" not in line:
                continue
            parts = line.split()
            ip = parts[0]
            if ":" in ip:
                continue  # v6
            idx = parts.index("lladdr")
            if idx + 1 < len(parts):
                out[parts[idx + 1].upper()] = ip
    except Exception:
        pass
    return out


def resolve_bypass_macs(macs: list[str]) -> list[str]:
    """Given a list of MACs, return the current IPs of those devices."""
    want = {m.upper() for m in (macs or []) if m}
    if not want:
        return []
    arp = get_all_arp_entries()
    return sorted({ip for mac, ip in arp.items() if mac in want})


def _parse_wildcard(h: str) -> tuple[bool, str]:
    """Return (is_wildcard, base). Supports *.example.com and exact names."""
    h = (h or "").strip().lower()
    if h.startswith("*."):
        return True, h[2:]
    return False, h


def _wildcard_candidates(base: str, max_labels: int = 3) -> list[str]:
    """For *.example.com, yield plausible subdomains to resolve.

    DNS has no wildcard query. We probe a fixed set of common subdomains
    and any explicitly configured extras. This is bounded — no brute force.
    """
    common = [
        "", "www", "cdn", "api", "static", "assets", "media", "img",
        "images", "download", "updates", "update", "app", "apps",
        "login", "auth", "sso", "portal", "edge",
    ]
    out = []
    for sub in common:
        if not sub:
            continue
        out.append(f"{sub}.{base}")
    return out


def resolve_bypass_hostnames(hostnames: list[str]) -> list[str]:
    """DNS-resolve each hostname to IPv4 addresses.

    Supports:
      - exact FQDNs:   updates.example.com
      - wildcards:     *.example.com   (probes a fixed set of common labels)
      - IPs / CIDRs are ignored here (they go through walled_garden directly)
    """
    import socket
    out: set[str] = set()
    wildcard_bases: list[str] = []
    exact: list[str] = []

    for h in (hostnames or []):
        h = (h or "").strip().lower()
        if not h or h.startswith("#"):
            continue
        is_wild, base = _parse_wildcard(h)
        if is_wild:
            if base:
                wildcard_bases.append(base)
        else:
            exact.append(h)

    to_resolve: set[str] = set(exact)
    for base in wildcard_bases:
        for cand in _wildcard_candidates(base):
            to_resolve.add(cand)

    for name in to_resolve:
        try:
            infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
        except Exception:
            continue
        for info in infos:
            ip = info[4][0]
            try:
                a = ipaddress.ip_address(ip)
                if a.version == 4:
                    out.add(str(a))
            except ValueError:
                continue
    return sorted(out)


def _write_lines(path: Path, lines: list[str], mode: int = 0o660) -> None:
    ensure_dirs()
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text("\n".join(lines) + ("\n" if lines else ""))
    try:
        os.chmod(tmp, mode)
        os.chown(tmp, 0, _gid_nfw())
    except OSError:
        pass
    os.replace(tmp, path)


def load_bypass_mac_ips() -> list[str]:
    try:
        return [ln.strip() for ln in BYPASS_MAC_IPS.read_text().splitlines() if ln.strip()]
    except OSError:
        return []


def load_bypass_hostname_ips() -> list[str]:
    try:
        return [ln.strip() for ln in BYPASS_HOST_IPS.read_text().splitlines() if ln.strip()]
    except OSError:
        return []


def _write_bypass_meta(meta: dict) -> None:
    ensure_dirs()
    tmp = BYPASS_META.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(meta, indent=2, sort_keys=True))
    try:
        os.chmod(tmp, 0o660)
        os.chown(tmp, 0, _gid_nfw())
    except OSError:
        pass
    os.replace(tmp, BYPASS_META)


def read_bypass_meta() -> dict:
    try:
        return json.loads(BYPASS_META.read_text())
    except Exception:
        return {}


def refresh_bypass(cfg: dict) -> dict:
    """Resolve MACs (respecting active kicks) and hostnames, rewrite caches,
    sync bypass sessions. Returns 'changed' indicating firewall needs recompile."""
    svc = cfg.get("services", {}).get("captiveportal_config", {}) or {}
    macs = svc.get("bypass_macs") or []
    hosts = svc.get("bypass_hostnames") or []

    # Prune expired kicks so they stop suppressing the MAC
    pruned_kicks = _prune_expired_kicks()

    now = int(time.time())
    # Active kicks — {mac_upper: kicked_until}
    active_kicks = {row["mac"].upper(): row["kicked_until"]
                    for row in _list_bypass_kicks_raw()
                    if row["kicked_until"] > now}

    old_mac_ips = load_bypass_mac_ips()
    old_host_ips = load_bypass_hostname_ips()

    err = ""

    # Resolve MACs, excluding kicked ones
    mac_ip_map: dict[str, str] = {}
    try:
        arp = get_all_arp_entries()
        want = {m.upper() for m in macs if m}
        for mac in want:
            if mac in active_kicks:
                continue  # kicked → not bypassed
            if mac in arp:
                mac_ip_map[mac] = arp[mac]
        new_mac_ips = sorted(set(mac_ip_map.values()))
    except Exception as e:
        err += f"mac: {e}; "
        new_mac_ips = old_mac_ips

    try:
        new_host_ips = resolve_bypass_hostnames(hosts)
    except Exception as e:
        err += f"hostname: {e}; "
        new_host_ips = old_host_ips

    changed = (new_mac_ips != old_mac_ips) or (new_host_ips != old_host_ips)
    if changed:
        _write_lines(BYPASS_MAC_IPS, new_mac_ips)
        _write_lines(BYPASS_HOST_IPS, new_host_ips)

    # Sync sessions table
    try:
        mat = materialize_bypass_sessions(mac_ip_map)
    except Exception as e:
        err += f"materialize: {e}; "
        mat = {}

    _write_bypass_meta({
        "resolved_at": now,
        "macs_configured": len(macs),
        "macs_resolved": len(new_mac_ips),
        "hostnames_configured": len(hosts),
        "hostnames_resolved": len(new_host_ips),
        "mac_ips": new_mac_ips,
        "hostname_ips": new_host_ips,
        "active_kicks": len(active_kicks),
        "pruned_kicks": pruned_kicks,
        "materialized": mat,
        "error": err.strip(),
    })
    return {
        "changed": changed,
        "mac_ips": new_mac_ips,
        "hostname_ips": new_host_ips,
        "active_kicks": list(active_kicks.keys()),
        "materialize": mat,
        "error": err.strip(),
    }

# ---------------------------------------------------------------------------
# Phase 9.18b3 — Bypass kicks + session materialization
# ---------------------------------------------------------------------------
BYPASS_SESSION_EXPIRY_S = 365 * 86400   # 1 year — effectively permanent


def _classify_backend(backend: str) -> str:
    b = (backend or "").lower()
    if b in ("local", "ldap", "radius"):
        return "auth"
    if b == "voucher":
        return "voucher"
    if b == "splash":
        return "splash"
    if b == "mac_bypass":
        return "bypass"
    return "unknown"


def _list_bypass_kicks_raw() -> list[dict]:
    with db() as conn:
        rows = conn.execute("SELECT * FROM bypass_kicks").fetchall()
    return [dict(r) for r in rows]


def list_bypass_kicks() -> list[dict]:
    """Return active kicks (kicked_until > now) sorted by expiry."""
    now = int(time.time())
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM bypass_kicks WHERE kicked_until > ? "
            "ORDER BY kicked_until ASC",
            (now,),
        ).fetchall()
    return [dict(r) for r in rows]


def is_mac_kicked(mac: str) -> bool:
    mac = (mac or "").upper()
    if not mac:
        return False
    now = int(time.time())
    with db() as conn:
        row = conn.execute(
            "SELECT 1 FROM bypass_kicks WHERE mac = ? AND kicked_until > ?",
            (mac, now),
        ).fetchone()
    return bool(row)


def bypass_kick_mac(mac: str, ttl_s: int = 3600,
                    reason: str = "admin_kick") -> dict:
    """Temporarily remove a MAC from bypass. The client will be redirected
    to the portal for the next ttl_s seconds (or until cleared)."""
    mac = (mac or "").strip().upper()
    if not mac:
        raise ValueError("mac required")
    now = int(time.time())
    until = now + max(60, int(ttl_s))
    affected_ips: list[str] = []
    with db() as conn:
        conn.execute(
            "INSERT INTO bypass_kicks (mac, kicked_at, kicked_until, reason) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(mac) DO UPDATE SET "
            "  kicked_at=excluded.kicked_at, "
            "  kicked_until=excluded.kicked_until, "
            "  reason=excluded.reason",
            (mac, now, until, reason),
        )
        # Snapshot any active mac_bypass sessions for this MAC
        rows = conn.execute(
            "SELECT id, ip FROM sessions "
            "WHERE mac = ? AND auth_backend = 'mac_bypass' "
            "AND revoked_at IS NULL",
            (mac,),
        ).fetchall()
        affected_ips = [r["ip"] for r in rows]
        # Revoke the sessions
        conn.execute(
            "UPDATE sessions SET revoked_at = ?, revoke_reason = ? "
            "WHERE mac = ? AND auth_backend = 'mac_bypass' "
            "AND revoked_at IS NULL",
            (now, reason, mac),
        )
        conn.commit()
    # Remove from nft immediately
    for ip in affected_ips:
        nft_remove_authenticated(ip)
    return {
        "mac": mac,
        "kicked_until": until,
        "ttl_s": until - now,
        "affected_ips": affected_ips,
    }


def clear_bypass_kick(mac: str) -> bool:
    mac = (mac or "").strip().upper()
    if not mac:
        return False
    with db() as conn:
        cur = conn.execute("DELETE FROM bypass_kicks WHERE mac = ?", (mac,))
        conn.commit()
        return cur.rowcount > 0


def _prune_expired_kicks() -> int:
    now = int(time.time())
    with db() as conn:
        cur = conn.execute(
            "DELETE FROM bypass_kicks WHERE kicked_until <= ?", (now,)
        )
        conn.commit()
        return cur.rowcount


def materialize_bypass_sessions(mac_ip_map: dict[str, str]) -> dict:
    """Sync sessions table with current MAC→IP bypass resolution.

    For each MAC in mac_ip_map: create or update a mac_bypass session.
    Any previously-active mac_bypass session whose MAC is no longer
    present gets revoked with reason 'disconnected'.
    """
    now = int(time.time())
    far = now + BYPASS_SESSION_EXPIRY_S
    created = updated = revoked = 0

    active = {(m or "").upper(): ip for m, ip in (mac_ip_map or {}).items()}

    with db() as conn:
        rows = conn.execute(
            "SELECT id, ip, mac FROM sessions "
            "WHERE auth_backend = 'mac_bypass' AND revoked_at IS NULL"
        ).fetchall()
        current = {r["mac"].upper(): dict(r) for r in rows if r["mac"]}

        for mac, ip in active.items():
            if mac in current:
                r = current[mac]
                if r["ip"] != ip:
                    conn.execute(
                        "UPDATE sessions SET ip = ?, last_seen_at = ?, "
                        "expires_at = ? WHERE id = ?",
                        (ip, now, far, r["id"]),
                    )
                    updated += 1
                else:
                    conn.execute(
                        "UPDATE sessions SET last_seen_at = ?, expires_at = ? "
                        "WHERE id = ?",
                        (now, far, r["id"]),
                    )
            else:
                conn.execute(
                    "INSERT INTO sessions "
                    "(ip, mac, username, auth_backend, user_agent, "
                    " started_at, last_seen_at, expires_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (ip, mac, mac, "mac_bypass", "bypass",
                     now, now, far),
                )
                created += 1

        for mac, r in current.items():
            if mac not in active:
                conn.execute(
                    "UPDATE sessions SET revoked_at = ?, "
                    "revoke_reason = 'disconnected' WHERE id = ?",
                    (now, r["id"]),
                )
                revoked += 1
        conn.commit()

    return {"created": created, "updated": updated, "revoked": revoked}


def _lan_iface_from_listen_ip() -> str:
    """Return the interface that owns the portal listen_ip (i.e. the LAN)."""
    try:
        cfg = json.loads((CP_DIR / "portal.json").read_text())
        listen_ip = cfg.get("listen_ip") or ""
    except Exception:
        listen_ip = ""
    if not listen_ip:
        return ""
    try:
        import subprocess as _sp
        r = _sp.run(["ip", "-o", "addr", "show"],
                    capture_output=True, text=True, timeout=5)
        prefix = listen_ip + "/"
        for line in r.stdout.splitlines():
            parts = line.split()
            # "2: enp2s0    inet 192.168.10.1/24 ..."
            if len(parts) >= 4 and parts[2] == "inet" and parts[3].startswith(prefix):
                return parts[1]
    except Exception:
        pass
    return ""


def _list_unauthenticated(now: int, q: str, limit: int) -> list[dict]:
    """Return ARP-known LAN clients with no active captive portal session.

    Used to surface "has an IP but hasn't logged in yet" clients in the GUI.
    Session DB is the source of truth for auth; ARP is the source of truth
    for presence.
    """
    # Only consider neighbours on the LAN interface. Without this filter
    # we pick up WAN-side ARP entries (e.g. the upstream ISP router at
    # 192.168.1.1) and mislabel them as unauthenticated clients.
    lan = _lan_iface_from_listen_ip()
    arp: dict[str, str] = {}
    if lan:
        try:
            import subprocess as _sp
            r = _sp.run(["ip", "-4", "neigh", "show", "dev", lan],
                        capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                if "lladdr" not in line:
                    continue
                parts = line.split()
                ip = parts[0]
                idx = parts.index("lladdr")
                if idx + 1 < len(parts):
                    arp[parts[idx + 1].upper()] = ip
        except Exception as e:
            LOG.warning("_list_unauthenticated: ip neigh failed: %s", e)
    else:
        LOG.warning("_list_unauthenticated: cannot determine LAN iface")
    try:
        with db() as conn:
            rows = conn.execute(
                "SELECT ip FROM sessions "
                "WHERE revoked_at IS NULL AND expires_at > ?",
                (now,),
            ).fetchall()
        active_ips = {r["ip"] for r in rows}
    except Exception as e:
        LOG.warning("_list_unauthenticated: db read failed: %s", e)
        active_ips = set()

    # Exclude the firewall's own LAN IP(s) — the kernel knows its own
    # address, so it appears in the ARP table and would otherwise show
    # up as an "unauthenticated client".
    own_ips: set[str] = set()
    try:
        import subprocess as _sp
        r = _sp.run(["ip", "-4", "-o", "addr", "show", "scope", "global"],
                    capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            parts = line.split()
            # format: "N: iface    inet 192.168.10.1/24 ..."
            if len(parts) >= 4 and parts[2] == "inet":
                own_ips.add(parts[3].split("/")[0])
    except Exception:
        pass

    ql = q.lower() if q else ""
    out: list[dict] = []
    for mac, ip in arp.items():
        if ip in active_ips:
            continue
        if ip in own_ips:
            continue
        if ql and ql not in ip.lower() and ql not in mac.lower():
            continue
        out.append({
            "ip": ip,
            "mac": mac,
            "username": "",
            "auth_backend": "",
            "user_agent": "",
            "started_at": 0,
            "last_seen_at": now,
            "expires_at": 0,
            "bytes_in": 0,
            "bytes_out": 0,
            "bw_in_bps": 0,
            "bw_out_bps": 0,
            "kind": "unauthenticated",
            "status": "pending",
        })
    out.sort(key=lambda x: x["ip"])
    return out[:limit]


def list_sessions_filtered(kind: str = "all", q: str = "",
                           include_revoked: bool = False,
                           limit: int = 500) -> list[dict]:
    """Return sessions filtered by kind.

    kind values: 'all' | 'auth' | 'voucher' | 'splash' | 'bypass' |
                 'unauthenticated'.

    When kind == 'unauthenticated': return ARP-known clients with no active
    session. When kind == 'all': merge unauthenticated clients in alongside
    authenticated sessions (unauth rows appended after sessions).
    """
    now = int(time.time())

    # Special case: unauthenticated only
    if kind == "unauthenticated":
        return _list_unauthenticated(now, q, limit)

    clauses = []
    params: list = []
    if not include_revoked:
        clauses.append("revoked_at IS NULL AND expires_at > ?")
        params.append(now)
    if kind == "auth":
        clauses.append("auth_backend IN ('local','ldap','radius')")
    elif kind == "voucher":
        clauses.append("auth_backend = 'voucher'")
    elif kind == "splash":
        clauses.append("auth_backend = 'splash'")
    elif kind == "bypass":
        clauses.append("auth_backend = 'mac_bypass'")
    if q:
        clauses.append("(ip LIKE ? OR username LIKE ? OR mac LIKE ?)")
        like = f"%{q}%"
        params.extend([like, like, like])
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"SELECT * FROM sessions{where} ORDER BY last_seen_at DESC LIMIT ?"
    params.append(int(limit))
    with db() as conn:
        rows = conn.execute(sql, params).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["kind"] = _classify_backend(d.get("auth_backend", ""))
        # status: distinguishes active vs revoked vs bypass
        if d.get("revoked_at"):
            d["status"] = "revoked"
        else:
            d["status"] = "authenticated"
        out.append(d)
    out = augment_sessions_with_rates(out)

    # When 'all' — append unauth clients not already represented
    if kind == "all":
        existing_ips = {s["ip"] for s in out}
        extra = [u for u in _list_unauthenticated(now, q, limit)
                 if u["ip"] not in existing_ips]
        out.extend(extra)

    return out

# ---------------------------------------------------------------------------
# Phase 9.18b4 — Custom portal templates
# ---------------------------------------------------------------------------
import re as _re
import uuid as _uuid

_TPL_VAR_RE = _re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}")


def _tpl_ensure_dirs() -> None:
    TPL_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(TPL_DIR, 0o770)
        os.chown(TPL_DIR, 0, _gid_nfw())
    except OSError:
        pass


def _read_registry() -> list[dict]:
    try:
        return json.loads(TPL_REGISTRY.read_text())
    except Exception:
        return []


def _write_registry(items: list[dict]) -> None:
    _tpl_ensure_dirs()
    tmp = TPL_REGISTRY.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(items, indent=2, sort_keys=True))
    try:
        os.chmod(tmp, 0o660)
        os.chown(tmp, 0, _gid_nfw())
    except OSError:
        pass
    os.replace(tmp, TPL_REGISTRY)


def _tpl_dir(tid: str) -> Path:
    return TPL_DIR / tid


def _safe_rel_path(name: str) -> str | None:
    """Reject absolute paths, '..' segments, null bytes, weird chars."""
    if not name or "\x00" in name:
        return None
    name = name.replace("\\", "/").lstrip("/")
    parts = []
    for seg in name.split("/"):
        if seg in ("", ".", ".."):
            return None
        # Conservative: allow only alphanumerics, dashes, underscores, dots, slashes
        if not _re.match(r"^[A-Za-z0-9._\-]+$", seg):
            return None
        parts.append(seg)
    return "/".join(parts)


def list_templates() -> list[dict]:
    _tpl_ensure_dirs()
    return _read_registry()


def get_template(tid: str) -> dict | None:
    for t in _read_registry():
        if t.get("id") == tid:
            return t
    return None


def delete_template(tid: str) -> bool:
    items = _read_registry()
    new_items = [t for t in items if t.get("id") != tid]
    if len(new_items) == len(items):
        return False
    _write_registry(new_items)
    # Best-effort remove the directory
    import shutil
    try:
        shutil.rmtree(_tpl_dir(tid))
    except Exception:
        pass
    return True


def read_template_file(tid: str, relpath: str) -> dict | None:
    """Return {'path': ..., 'content': str, 'size': N, 'is_text': bool}."""
    sp = _safe_rel_path(relpath)
    if not sp:
        return None
    root = _tpl_dir(tid)
    full = root / sp
    if not full.exists() or not full.is_file():
        return None
    try:
        data = full.read_bytes()
    except OSError:
        return None
    ext = Path(sp).suffix.lower()
    is_text = ext in {".html", ".htm", ".css", ".js", ".txt", ".md", ".json", ".svg"}
    if is_text:
        try:
            content = data.decode("utf-8")
        except UnicodeDecodeError:
            content = ""
            is_text = False
    else:
        content = ""
    return {"path": sp, "content": content, "size": len(data), "is_text": is_text}


def write_template_file(tid: str, relpath: str, content: str) -> bool:
    sp = _safe_rel_path(relpath)
    if not sp:
        return False
    t = get_template(tid)
    if not t:
        return False
    root = _tpl_dir(tid)
    root.mkdir(parents=True, exist_ok=True)
    full = root / sp
    full.parent.mkdir(parents=True, exist_ok=True)
    tmp = full.with_suffix(full.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    try:
        os.chmod(tmp, 0o660)
        os.chown(tmp, 0, _gid_nfw())
    except OSError:
        pass
    os.replace(tmp, full)
    _tpl_refresh_stats(tid)
    return True


def delete_template_file(tid: str, relpath: str) -> bool:
    sp = _safe_rel_path(relpath)
    if not sp:
        return False
    full = _tpl_dir(tid) / sp
    if not full.exists() or not full.is_file():
        return False
    try:
        full.unlink()
    except OSError:
        return False
    _tpl_refresh_stats(tid)
    return True


def _tpl_refresh_stats(tid: str) -> None:
    items = _read_registry()
    for t in items:
        if t.get("id") == tid:
            root = _tpl_dir(tid)
            n = 0
            total = 0
            files = []
            if root.exists():
                for f in sorted(root.rglob("*")):
                    if f.is_file():
                        n += 1
                        try:
                            total += f.stat().st_size
                        except OSError:
                            pass
                        try:
                            files.append(str(f.relative_to(root)))
                        except ValueError:
                            pass
            t["files"] = n
            t["size"] = total
            t["file_list"] = files
            break
    _write_registry(items)


def list_template_files(tid: str) -> list[dict]:
    root = _tpl_dir(tid)
    if not root.exists():
        return []
    out = []
    for f in sorted(root.rglob("*")):
        if not f.is_file():
            continue
        try:
            rel = str(f.relative_to(root))
            st = f.stat()
            out.append({"path": rel, "size": st.st_size, "mtime": st.st_mtime})
        except OSError:
            continue
    return out


def extract_template_zip(zip_bytes: bytes, name: str) -> dict:
    """Validate + extract a ZIP into a new template directory."""
    import io as _io
    import zipfile

    if len(zip_bytes) > TPL_MAX_BYTES:
        raise ValueError(f"ZIP exceeds {TPL_MAX_BYTES} bytes")
    try:
        zf = zipfile.ZipFile(_io.BytesIO(zip_bytes))
    except zipfile.BadZipFile as e:
        raise ValueError(f"not a valid ZIP: {e}")

    members = [m for m in zf.infolist() if not m.is_dir()]
    if len(members) > TPL_MAX_FILES:
        raise ValueError(f"too many files ({len(members)} > {TPL_MAX_FILES})")

    total = sum(m.file_size for m in members)
    if total > TPL_MAX_BYTES:
        raise ValueError(f"uncompressed size {total} exceeds {TPL_MAX_BYTES}")

    tid = _uuid.uuid4().hex[:16]
    staging = TPL_DIR / f".staging-{tid}"
    final = _tpl_dir(tid)

    _tpl_ensure_dirs()
    staging.mkdir(parents=True, exist_ok=False)

    seen_paths: set[str] = set()
    extracted = 0
    for m in members:
        raw = m.filename
        sp = _safe_rel_path(raw)
        if not sp:
            raise ValueError(f"unsafe path: {raw}")
        ext = Path(sp).suffix.lower()
        if ext and ext not in TPL_ALLOWED_EXTS:
            raise ValueError(f"disallowed extension: {ext} ({sp})")
        if sp in seen_paths:
            continue
        seen_paths.add(sp)
        dest = staging / sp
        dest.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(m) as src, open(dest, "wb") as dst:
            # Copy with a size cap
            copied = 0
            while True:
                chunk = src.read(65536)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > TPL_MAX_BYTES:
                    raise ValueError(f"file too large during extract: {sp}")
                dst.write(chunk)
        extracted += 1

    if "login.html" not in seen_paths:
        raise ValueError("ZIP must contain login.html at the root")

    # Reject Jinja2 markup — we don't support it, and its presence
    # almost always means the user tried to reuse the built-in template.
    login_path = staging / "login.html"
    try:
        login_text = login_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        login_text = ""
    if "{%" in login_text or "{#" in login_text:
        import shutil as _sh
        _sh.rmtree(staging, ignore_errors=True)
        raise ValueError(
            "login.html contains Jinja2 markup ({% ... %} or {# ... #}). "
            "Custom templates must be plain HTML — use {{variable}} tokens "
            "and JavaScript for logic. Download the starter ZIP for a "
            "working example."
        )

    # Move into place
    try:
        os.rename(str(staging), str(final))
    except OSError:
        import shutil
        shutil.rmtree(staging, ignore_errors=True)
        raise

    # Set perms
    for f in final.rglob("*"):
        try:
            os.chmod(f, 0o660 if f.is_file() else 0o770)
            os.chown(f, 0, _gid_nfw())
        except OSError:
            pass

    total_size = sum(f.stat().st_size for f in final.rglob("*") if f.is_file())
    entry = {
        "id": tid,
        "name": (name or "").strip()[:64] or f"template-{tid[:8]}",
        "uploaded_at": int(time.time()),
        "files": extracted,
        "size": total_size,
        "file_list": sorted(seen_paths),
    }
    items = _read_registry()
    items.append(entry)
    _write_registry(items)
    LOG.info("template uploaded id=%s name=%r files=%d size=%d",
             tid, entry["name"], extracted, total_size)
    return entry


PLAIN_HTML_STARTER = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{gateway_name}}</title>
<style>
  :root { --primary: {{primary_color}}; }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #0d1117; color: #c9d1d9;
    min-height: 100vh;
    display: flex; align-items: center; justify-content: center;
    padding: 20px;
  }
  .card {
    background: #161b22; border: 1px solid #30363d; border-radius: 12px;
    padding: 32px 28px; max-width: 420px; width: 100%;
    box-shadow: 0 8px 32px rgba(0,0,0,0.4);
  }
  h1 { margin: 0 0 8px; font-size: 20px; text-align: center; color: #f0f6fc; }
  .welcome { text-align: center; color: #8b949e; font-size: 14px; margin: 0 0 20px; }
  .error { background: rgba(248,81,73,0.1); border: 1px solid #f85149;
           color: #f85149; padding: 10px 12px; border-radius: 8px;
           font-size: 13px; margin-bottom: 16px; }
  label { display: block; margin-bottom: 14px; }
  label span { display: block; font-size: 12px; color: #8b949e; margin-bottom: 5px; }
  input[type=text], input[type=password] {
    width: 100%; padding: 11px 13px;
    background: #0d1117; border: 1px solid #30363d; border-radius: 8px;
    color: #c9d1d9; font-size: 15px; outline: none;
  }
  input:focus { border-color: var(--primary); }
  button { width: 100%; padding: 12px; background: var(--primary); color: #fff;
           border: 0; border-radius: 8px; font-size: 15px; font-weight: 600;
           cursor: pointer; }
  .tabs { display: flex; margin-bottom: 20px; background: #0d1117; border-radius: 8px;
          padding: 4px; border: 1px solid #30363d; }
  .tab { flex: 1; padding: 9px 12px; text-align: center; font-size: 13px;
         color: #8b949e; cursor: pointer; border-radius: 6px; user-select: none; }
  .tab.active { background: var(--primary); color: #fff; }
  .panel { display: none; }
  .panel.active { display: block; }
  .footer { text-align: center; color: #6e7681; font-size: 11px; margin-top: 24px; }
</style>
</head>
<body>
  <div class="card">
    <h1>{{gateway_name}}</h1>
    <p class="welcome">{{welcome_text}}</p>

    <div id="err" class="error" style="display:none"></div>

    <div id="tabs" class="tabs" style="display:none">
      <div class="tab active" data-tab="password">Username &amp; password</div>
      <div class="tab" data-tab="voucher">Voucher code</div>
    </div>

    <form id="form-password" method="post" action="/login">
      <input type="hidden" name="next" value="{{next_url}}">
      <input type="hidden" name="auth_method" value="password">
      <label><span>Username</span>
        <input type="text" name="username" autocomplete="username" required>
      </label>
      <label><span>Password</span>
        <input type="password" name="password" autocomplete="current-password" required>
      </label>
      <button type="submit">Sign in</button>
    </form>

    <form id="form-voucher" method="post" action="/login" style="display:none">
      <input type="hidden" name="next" value="{{next_url}}">
      <input type="hidden" name="auth_method" value="voucher">
      <label><span>Voucher code</span>
        <input type="text" name="voucher_code" autocomplete="off" required
               style="text-transform:uppercase;letter-spacing:0.15em;
                      font-family:ui-monospace,monospace;text-align:center">
      </label>
      <button type="submit">Redeem voucher</button>
    </form>

    <form id="form-splash" method="post" action="/splash" style="display:none">
      <input type="hidden" name="next" value="{{next_url}}">
      <button type="submit">{{splash_label}}</button>
    </form>

    <div class="footer">Powered by NFW</div>
  </div>

  <script>
    // Read the substituted values from the server, set up the right form
    var mode = "{{auth_mode}}";
    var showPw = "{{show_password_form}}" === "yes";
    var showV = "{{show_voucher_form}}" === "yes";
    var errText = "{{error}}";

    var errEl = document.getElementById('err');
    if (errText) { errEl.textContent = errText; errEl.style.display = 'block'; }

    var tabs = document.getElementById('tabs');
    var formPw = document.getElementById('form-password');
    var formV  = document.getElementById('form-voucher');
    var formS  = document.getElementById('form-splash');

    if (mode === 'splash') {
      formPw.style.display = 'none';
      formV.style.display = 'none';
      formS.style.display = 'block';
    } else if (showPw && showV) {
      tabs.style.display = 'flex';
      formPw.style.display = 'block';
      formV.style.display = 'none';
      document.querySelectorAll('.tab').forEach(function(t) {
        t.addEventListener('click', function() {
          document.querySelectorAll('.tab').forEach(function(x) { x.classList.remove('active'); });
          t.classList.add('active');
          var tab = t.getAttribute('data-tab');
          formPw.style.display = (tab === 'password') ? 'block' : 'none';
          formV.style.display  = (tab === 'voucher')  ? 'block' : 'none';
        });
      });
    } else if (showV) {
      formPw.style.display = 'none';
      formV.style.display = 'block';
    } else {
      formPw.style.display = 'block';
      formV.style.display = 'none';
    }
  </script>
</body>
</html>
"""


README_STARTER = """NFW Captive Portal Template

This is a plain-HTML template. It ships no Jinja2 logic and no template
inheritance. Server-side substitution is limited to {{variable}} tokens;
everything else (conditionals, loops, interactivity) is plain JavaScript.

Available variables:

  {{gateway_name}}          Portal heading
  {{welcome_text}}          Welcome message
  {{primary_color}}         Theme accent color (hex)
  {{logo_url}}              Logo URL (empty if unset)
  {{error}}                 Error message (empty if none)
  {{next_url}}              Original URL to return to after login
  {{portal_url}}            Absolute URL of this portal
  {{auth_mode}}             multi | credentials | voucher | splash
  {{tos_required}}          yes | no
  {{tos_text}}              Terms of service body
  {{splash_label}}          Splash button label
  {{splash_extra_text}}     Splash extra paragraph
  {{show_password_form}}    yes | no
  {{show_voucher_form}}     yes | no

IMPORTANT: This renderer does NOT understand Jinja2. If you use
{% if %}...{% endif %} or {# comments #}, they will be served as
literal text to the browser. Branch on {{auth_mode}} etc. in JavaScript.

Form endpoints (all POST):
  /login   — password or voucher
              fields: username, password, auth_method=password|voucher,
                      voucher_code (when auth_method=voucher), next
  /splash  — splash-only connect (auth_method=splash, accept_tos=1 optional)
  /logout  — clear session

Assets: put CSS / JS / PNG in the ZIP alongside login.html. They will be
served from /portal/template/<template_id>/<path>. Reference them with
absolute paths like:
    <link rel="stylesheet" href="/portal/template/<id>/style.css">
or relative paths (they resolve against the portal root when the template
is served inline — but absolute is safer).

ZIP layout:
  login.html          <- required, at the root
  style.css           <- optional
  logo.png            <- optional
  js/script.js        <- optional (subdirs OK)
"""


def build_starter_zip() -> bytes:
    """Return a ZIP containing a plain-HTML starter template (no Jinja2)."""
    import io as _io
    import zipfile
    buf = _io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("login.html", PLAIN_HTML_STARTER)
        zf.writestr("README.txt", README_STARTER)
    return buf.getvalue()

def substitute_template_vars(text: str, vars_: dict) -> str:
    """Replace {{var}} with values. Unknown vars become empty string."""
    def _repl(m):
        return str(vars_.get(m.group(1), ""))
    return _TPL_VAR_RE.sub(_repl, text)

# ---------------------------------------------------------------------------
# Phase 9.18b5 — Per-session shaping (integrated with authorize/revoke)
# ---------------------------------------------------------------------------
def _shaping_ifaces(cfg: dict) -> tuple[str, str]:
    """Return (lan_iface, wan_iface) from config; empty strings if unset."""
    resolved = cfg.get("_resolved_interfaces") or {}
    net = cfg.get("network", {}) or {}
    lan = resolved.get("lan") or net.get("lan") or ""
    wan = resolved.get("wan") or net.get("wan") or ""
    return (str(lan), str(wan))


def shaping_install(cfg: dict) -> dict:
    """Install HTB roots on WAN + LAN. Idempotent.

    Also reapplies per-client filters for all active sessions — otherwise
    a prior cp_clear_all (during uninstall) leaves sessions with no
    shaping and no byte counters.
    """
    from modules.shaper import tc as _tc
    lan, wan = _shaping_ifaces(cfg)
    out = {}
    if wan:
        out["wan"] = {"iface": wan,
                      "result": _tc.cp_ensure_root(wan, _tc.CP_HANDLE_UPLOAD)}
    if lan:
        out["lan"] = {"iface": lan,
                      "result": _tc.cp_ensure_root(lan, _tc.CP_HANDLE_DOWNLOAD)}

    reapplied = _reapply_active_filters(cfg)
    out["reapplied"] = reapplied
    LOG.info("shaping install: %s", out)
    return out


def _reapply_active_filters(cfg: dict) -> int:
    """Restore nft set membership + tc filters for all active sessions.

    Called after captiveportal.apply rebuilds the ruleset. The compiler
    emits an empty cp_authenticated_v4 set, so every nft -f drops
    authorization for everyone still in the DB. Without this reapply,
    any config change kicks every client off until they re-login.
    """
    now = int(time.time())
    svc = cfg.get("services", {}).get("captiveportal_config", {}) or {}
    default_up = int(svc.get("default_bandwidth_up_kbps", 0) or 0)
    default_down = int(svc.get("default_bandwidth_down_kbps", 0) or 0)
    count = 0
    try:
        with db() as conn:
            rows = conn.execute(
                "SELECT ip, username, auth_backend, expires_at FROM sessions "
                "WHERE revoked_at IS NULL AND expires_at > ?",
                (now,),
            ).fetchall()
    except Exception as e:
        LOG.warning("reapply filters: db read failed: %s", e)
        return 0
    for r in rows:
        # Restore nft authorization with the remaining TTL
        try:
            ttl = max(1, int(r["expires_at"]) - now)
            nft_add_authenticated(r["ip"], ttl)
        except Exception as e:
            LOG.warning("reapply nft for %s failed: %s", r["ip"], e)
            continue
        ip = r["ip"]
        up = default_up
        down = default_down
        if r["auth_backend"] == "voucher":
            try:
                with db() as conn:
                    v = conn.execute(
                        "SELECT bandwidth_up_kbps, bandwidth_down_kbps "
                        "FROM vouchers WHERE code = ?",
                        (r["username"],),
                    ).fetchone()
                if v:
                    if v["bandwidth_up_kbps"]:
                        up = int(v["bandwidth_up_kbps"])
                    if v["bandwidth_down_kbps"]:
                        down = int(v["bandwidth_down_kbps"])
            except Exception:
                pass
        eff_up = up or 1_000_000
        eff_down = down or 1_000_000
        try:
            shaping_apply_client(ip, eff_up, eff_down, cfg)
            count += 1
        except Exception as e:
            LOG.warning("reapply filter for %s failed: %s", ip, e)
    return count


def shaping_uninstall(cfg: dict) -> dict:
    """Remove HTB roots + all client filters from WAN + LAN."""
    from modules.shaper import tc as _tc
    lan, wan = _shaping_ifaces(cfg)
    r = _tc.cp_clear_all(lan, wan)
    LOG.info("shaping uninstall: %s", r)
    return r


def shaping_apply_client(ip: str, up_kbps: int, down_kbps: int,
                         cfg: dict) -> dict:
    """Add or update tc filters for one client IP. Never raises."""
    from modules.shaper import tc as _tc
    lan, wan = _shaping_ifaces(cfg)
    out = {}
    try:
        if wan:
            out["upload"] = _tc.cp_add_client(
                wan, ip, int(up_kbps or 0), _tc.CP_HANDLE_UPLOAD, "egress")
        if lan:
            out["download"] = _tc.cp_add_client(
                lan, ip, int(down_kbps or 0), _tc.CP_HANDLE_DOWNLOAD, "ingress")
    except Exception as e:
        LOG.warning("shaping_apply_client(%s) failed: %s", ip, e)
        out["error"] = str(e)
    return out


def shaping_remove_client(ip: str, cfg: dict) -> dict:
    """Remove tc filters for one client IP. Never raises."""
    from modules.shaper import tc as _tc
    lan, wan = _shaping_ifaces(cfg)
    out = {}
    try:
        if wan:
            out["upload"] = _tc.cp_remove_client(wan, ip, _tc.CP_HANDLE_UPLOAD)
        if lan:
            out["download"] = _tc.cp_remove_client(lan, ip, _tc.CP_HANDLE_DOWNLOAD)
    except Exception as e:
        LOG.warning("shaping_remove_client(%s) failed: %s", ip, e)
        out["error"] = str(e)
    return out


def full_authorize(cfg: dict, ip: str, mac: str, username: str,
                   backend: str, ua: str, timeout_s: int,
                   hard_timeout_s: int = 0,
                   up_kbps: int = 0, down_kbps: int = 0) -> int:
    """Add client to nft sets, install tc filters, insert session row.

    Returns the new session id (0 if DB write failed).
    Never raises for shaping / DB failures — only for nft failure.
    """
    nft_add_authenticated(ip, timeout_s)
    # Always install tc filters — even without a bandwidth limit — so byte
    # accounting works. When no limit is configured, use the top bucket
    # (1 Gbps): enforces nothing meaningful, but keeps counters alive.
    eff_up = up_kbps or 1_000_000
    eff_down = down_kbps or 1_000_000
    try:
        shaping_apply_client(ip, eff_up, eff_down, cfg)
    except Exception as e:
        LOG.warning("shaping_apply_client failed for %s: %s", ip, e)
    try:
        return add_session(ip, mac, username, backend, ua, timeout_s,
                           hard_timeout_s=hard_timeout_s)
    except Exception as e:
        LOG.warning("add_session failed for %s: %s", ip, e)
        return 0


def full_deauthorize(cfg: dict, ip: str) -> dict:
    """Remove client from nft sets, remove tc filters, delete session row."""
    r = {}
    try:
        r["nft"] = nft_remove_authenticated(ip)
    except Exception as e:
        LOG.warning("nft_remove failed for %s: %s", ip, e)
        r["nft_error"] = str(e)
    try:
        r["shaping"] = shaping_remove_client(ip, cfg)
    except Exception as e:
        LOG.warning("shaping remove failed for %s: %s", ip, e)
        r["shaping_error"] = str(e)
    try:
        r["had_session"] = end_session(ip)
    except Exception as e:
        LOG.warning("end_session failed for %s: %s", ip, e)
        r["session_error"] = str(e)
    return r

# ---------------------------------------------------------------------------
# Phase 9.18b5 — live rate enrichment (reads tc_snapshot.json)
# ---------------------------------------------------------------------------
TC_SNAPSHOT = CP_DIR / "tc_snapshot.json"


def _load_tc_snapshot() -> dict:
    try:
        return json.loads(TC_SNAPSHOT.read_text())
    except Exception:
        return {}


def augment_sessions_with_rates(sessions: list[dict]) -> list[dict]:
    """Add bw_in_bps / bw_out_bps to each session by joining the tc snapshot.

    A session maps to two tc filters: one on the WAN iface (upload = bytes_out
    direction) and one on the LAN iface (download = bytes_in direction).
    """
    snap = _load_tc_snapshot().get("ifaces") or {}
    # Build {ip: {"in": rate, "out": rate}} from snapshot
    rates_by_ip: dict[str, dict] = {}
    for iface, prio_map in snap.items():
        for prio_str, entry in (prio_map or {}).items():
            ip = entry.get("ip")
            if not ip:
                continue
            r = int(entry.get("rate_bps") or 0)
            bucket = rates_by_ip.setdefault(ip, {"in": 0, "out": 0})
            dir_ = str(entry.get("dir") or "").lower()
            if not dir_:
                # Fallback: derive from flowid class prefix
                flowid = str(entry.get("flowid") or "")
                if flowid.startswith("3:"):
                    dir_ = "ingress"
                elif flowid.startswith("2:"):
                    dir_ = "egress"
            if dir_ == "ingress":
                bucket["in"] = r
            elif dir_ == "egress":
                bucket["out"] = r
    for s in sessions:
        ip = s.get("ip")
        if ip and ip in rates_by_ip:
            s["bw_in_bps"] = rates_by_ip[ip]["in"]
            s["bw_out_bps"] = rates_by_ip[ip]["out"]
        else:
            s["bw_in_bps"] = 0
            s["bw_out_bps"] = 0
    return sessions

