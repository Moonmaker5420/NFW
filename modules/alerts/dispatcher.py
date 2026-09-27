"""Alert dispatcher — event throttling, SMTP delivery, history.

Usage from configd (direct call):
    from modules.alerts import dispatcher as alerts
    alerts.notify(cfg, "firewall_apply_failed", context={"revision": rev},
                  subject="...", body="...")

Usage from API (via configd action `alerts.notify`):
    POST {"event": "login_failed", "context": {"username": "admin"}, ...}

Design:
  - Events table records every occurrence (for threshold counting).
  - Alerts table records every send attempt (for history + display).
  - Throttle: at most one alert per (event, context_key) per window,
    where window comes from the event config; user config sets threshold
    (N events within window → 1 alert).

  - SMTP send is synchronous with a 15s timeout. Failures are recorded;
    no auto-retry (user sees failed entries in history and can retry by
    re-triggering, or fix SMTP config).
"""
from __future__ import annotations

import json
import logging
import os
import smtplib
import ssl
import sqlite3
import time
from email.message import EmailMessage
from typing import Any

LOG = logging.getLogger("alerts.dispatcher")

DB_PATH = "/var/lib/nfw/alerts.db"
SMTP_TIMEOUT = 15


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH, timeout=5)
    c.row_factory = sqlite3.Row
    return c


def _ensure_schema() -> None:
    try:
        with _conn() as c:
            c.executescript("""
                CREATE TABLE IF NOT EXISTS events (
                    id      INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts      REAL NOT NULL,
                    event   TEXT NOT NULL,
                    context TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS ix_events_lookup
                    ON events(event, context, ts);

                CREATE TABLE IF NOT EXISTS alerts (
                    id       INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts       REAL NOT NULL,
                    event    TEXT NOT NULL,
                    context  TEXT NOT NULL DEFAULT '',
                    subject  TEXT NOT NULL DEFAULT '',
                    body     TEXT NOT NULL DEFAULT '',
                    status   TEXT NOT NULL,        -- sent | failed | throttled
                    error    TEXT
                );
                CREATE INDEX IF NOT EXISTS ix_alerts_ts
                    ON alerts(ts DESC);
                CREATE INDEX IF NOT EXISTS ix_alerts_lookup
                    ON alerts(event, context, ts, status);
            """)
    except Exception as e:
        LOG.warning("_ensure_schema failed: %s", e)


def _ctx_key(ctx: dict | None) -> str:
    """Serialize a context dict into a stable string for throttling."""
    if not ctx:
        return ""
    try:
        return json.dumps(ctx, sort_keys=True, separators=(",", ":"))[:200]
    except Exception:
        return str(ctx)[:200]


def _cfg_section(cfg: dict) -> dict:
    return ((cfg.get("services") or {}).get("notifications") or {})


def _event_cfg(cfg: dict, event: str) -> dict:
    ev = (_cfg_section(cfg).get("events") or {}).get(event) or {}
    return ev


def _threshold(cfg: dict, event: str) -> tuple[int, int]:
    """Return (threshold, window_seconds) for an event.

    Defaults:
      login_failed: 5 within 15 minutes
      firewall_apply_failed: 1 immediately (window 60s)
      cert_expiring: 1 per day
    """
    ev = _event_cfg(cfg, event)
    defaults = {
        "login_failed":          (5, 15 * 60),
        "firewall_apply_failed": (1, 60),
        "cert_expiring":         (1, 24 * 3600),
    }
    d_thr, d_win = defaults.get(event, (1, 60))
    thr = int(ev.get("threshold", d_thr))
    win_min = int(ev.get("window_minutes", d_win // 60))
    if win_min <= 0:
        win_min = max(1, d_win // 60)
    return max(1, thr), win_min * 60


def _send_email(smtp: dict, subject: str, body: str) -> tuple[bool, str]:
    """Send an email. Returns (ok, error_message)."""
    host = (smtp.get("host") or "").strip()
    if not host:
        return False, "smtp.host not configured"
    port = int(smtp.get("port") or 587)
    use_tls = bool(smtp.get("use_tls", True))
    use_ssl = bool(smtp.get("use_ssl", False))
    username = (smtp.get("username") or "").strip()
    password = smtp.get("password") or ""
    from_addr = (smtp.get("from_addr") or "").strip()
    to_addrs = smtp.get("to_addrs") or []

    if not to_addrs:
        return False, "smtp.to_addrs is empty"
    if not from_addr:
        # Fall back to username or a generic
        from_addr = username or "nfw@localhost"

    msg = EmailMessage()
    msg["Subject"] = f"[NFW] {subject}"
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)
    msg.set_content(body)

    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, timeout=SMTP_TIMEOUT,
                                  context=ctx) as s:
                if username:
                    s.login(username, password)
                s.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=SMTP_TIMEOUT) as s:
                s.ehlo()
                if use_tls:
                    s.starttls(context=ssl.create_default_context())
                    s.ehlo()
                if username:
                    s.login(username, password)
                s.send_message(msg)
        return True, ""
    except Exception as e:
        LOG.warning("SMTP send failed: %s", e)
        return False, str(e)[:300]


def _record_alert(event: str, ctx_key: str, subject: str, body: str,
                  status: str, error: str = "") -> None:
    try:
        with _conn() as c:
            c.execute(
                "INSERT INTO alerts(ts, event, context, subject, body, status, error) "
                "VALUES (?,?,?,?,?,?,?)",
                (time.time(), event, ctx_key, subject, body, status, error),
            )
    except Exception as e:
        LOG.warning("_record_alert failed: %s", e)


def notify(cfg: dict, event: str, *, context: dict | None = None,
           subject: str, body: str, force: bool = False) -> dict[str, Any]:
    """Public entry point. Records the event, applies throttling, sends.

    Returns {sent: bool, throttled: bool, status: 'sent'|'failed'|'throttled',
             reason: str}.
    """
    _ensure_schema()

    notif = _cfg_section(cfg)
    if not notif.get("enabled"):
        return {"sent": False, "throttled": False,
                "status": "disabled", "reason": "notifications disabled"}

    ev_cfg = _event_cfg(cfg, event)
    if not ev_cfg.get("enabled", True):
        return {"sent": False, "throttled": False,
                "status": "disabled", "reason": f"event {event} disabled"}

    ctx_key = _ctx_key(context)

    # Record this occurrence
    try:
        with _conn() as c:
            c.execute("INSERT INTO events(ts, event, context) VALUES (?,?,?)",
                      (time.time(), event, ctx_key))
    except Exception as e:
        LOG.warning("event record failed: %s", e)

    threshold, window = _threshold(cfg, event)
    now = time.time()

    if not force:
        # Count events in window
        try:
            with _conn() as c:
                row = c.execute(
                    "SELECT COUNT(*) AS n FROM events "
                    "WHERE event=? AND context=? AND ts > ?",
                    (event, ctx_key, now - window),
                ).fetchone()
                n = row["n"] if row else 0
        except Exception as e:
            LOG.warning("event count failed: %s", e)
            n = threshold  # fail open

        if n < threshold:
            return {"sent": False, "throttled": False,
                    "status": "below_threshold",
                    "reason": f"{n}/{threshold} events in window"}

        # Already alerted for this (event, context) in window?
        try:
            with _conn() as c:
                row = c.execute(
                    "SELECT COUNT(*) AS n FROM alerts "
                    "WHERE event=? AND context=? AND ts > ? AND status='sent'",
                    (event, ctx_key, now - window),
                ).fetchone()
                already = row["n"] if row else 0
        except Exception:
            already = 0

        if already > 0:
            _record_alert(event, ctx_key, subject, body, "throttled")
            return {"sent": False, "throttled": True,
                    "status": "throttled",
                    "reason": f"alert already sent within {window}s"}

    # Send
    smtp = notif.get("smtp") or {}
    ok, err = _send_email(smtp, subject, body)
    status = "sent" if ok else "failed"
    _record_alert(event, ctx_key, subject, body, status, err)
    if ok:
        LOG.info("alert sent: %s", event)
    else:
        LOG.warning("alert failed: %s — %s", event, err)
    return {"sent": ok, "throttled": False, "status": status,
            "reason": err or "ok"}


def test_smtp(cfg: dict, to_override: list[str] | None = None) -> dict[str, Any]:
    """Send a test email. Bypasses threshold, uses config as-is."""
    notif = _cfg_section(cfg)
    smtp = dict(notif.get("smtp") or {})
    if to_override:
        smtp["to_addrs"] = to_override

    subject = "Test alert from NFW"
    body = ("This is a test alert from your NFW firewall.\n\n"
            "If you received this, the notification system is working.\n"
            "You can now enable specific events in System → Alerts.\n")
    ok, err = _send_email(smtp, subject, body)
    _record_alert("test", "", subject, body, "sent" if ok else "failed", err)
    return {"ok": ok, "error": err}


def history(limit: int = 50) -> dict[str, Any]:
    """Return the most recent alerts + a small stats summary."""
    _ensure_schema()
    try:
        with _conn() as c:
            rows = c.execute(
                "SELECT ts, event, context, subject, status, error "
                "FROM alerts ORDER BY ts DESC LIMIT ?",
                (max(1, min(limit, 500)),),
            ).fetchall()
        stats = {"sent": 0, "failed": 0, "throttled": 0}
        for r in rows:
            s = r["status"]
            if s in stats:
                stats[s] += 1
        return {"alerts": [dict(r) for r in rows], "stats": stats}
    except Exception as e:
        return {"alerts": [], "stats": {}, "error": str(e)}
