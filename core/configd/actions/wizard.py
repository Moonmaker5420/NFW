"""First-run setup wizard actions."""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
from typing import Any

from configd.registry import action

sys.path.insert(0, "/opt/nfw")
sys.path.insert(0, "/opt/nfw/core")

from config import store as cfg_store  # noqa: E402
from config.schema import validate  # noqa: E402

LOG = logging.getLogger("configd.wizard")

USERS_FILE = "/etc/nfw/users.json"
MARKER = "/var/lib/nfw/config/setup_pending"


def _read_users() -> dict:
    try:
        with open(USERS_FILE) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def _write_users(users: dict) -> None:
    tmp = USERS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(users, f, indent=2, sort_keys=True)
    os.chmod(tmp, 0o640)
    try:
        import grp
        os.chown(tmp, 0, grp.getgrnam("nfw").gr_gid)
    except Exception:
        pass
    os.replace(tmp, USERS_FILE)


@action("wizard.status")
def wizard_status(_data: dict[str, Any]) -> dict[str, Any]:
    return {"pending": os.path.exists(MARKER)}


@action("wizard.complete")
def _update_etc_hosts(hostname: str) -> None:
    """Ensure /etc/hosts has a 127.0.1.1 entry for the new hostname.

    Without this, sudo prints 'unable to resolve host <name>' on every
    invocation after the wizard changes the hostname.
    """
    import re as _re
    path = "/etc/hosts"
    try:
        with open(path) as f:
            lines = f.readlines()
    except OSError:
        return
    kept = [ln for ln in lines
            if not _re.match(r'^127\.0\.1\.1\s', ln)]
    kept.append(f"127.0.1.1\t{hostname}\n")
    try:
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            f.writelines(kept)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except OSError as e:
        LOG.warning("wizard: /etc/hosts update failed: %s", e)


def wizard_complete(data: dict[str, Any]) -> dict[str, Any]:
    """Finalize first-run setup.

    Input:
      hostname:       str (required, alnum + hyphen + dot)
      timezone:       str (optional, default UTC)
      admin_password: str (required, >= 6 chars)

    Side effects:
      - updates config system.hostname + system.timezone
      - rewrites /etc/nfw/users.json with bcrypt hash of new password
      - sets hostname live
      - removes /var/lib/nfw/config/setup_pending
      - commits a new config revision
    """
    # Refuse if setup is already complete — otherwise a logged-in admin
    # could accidentally re-run the wizard and reset their password.
    if not os.path.exists(MARKER):
        return {"ok": False, "error": "setup already complete"}

    hostname = (data.get("hostname") or "").strip()
    timezone = (data.get("timezone") or "UTC").strip() or "UTC"
    new_pw = data.get("admin_password") or ""

    if not hostname:
        return {"ok": False, "error": "hostname required"}
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9.\-]{0,62}$", hostname):
        return {"ok": False, "error": "invalid hostname"}
    if len(new_pw) < 6:
        return {"ok": False, "error": "password must be at least 6 characters"}

    # 1. Rewrite users.json
    try:
        import bcrypt
        users = _read_users()
        rec = users.get("admin") or {}
        rec["hash"] = bcrypt.hashpw(new_pw.encode("utf-8"),
                                     bcrypt.gensalt()).decode("utf-8")
        rec.setdefault("role", "admin")
        rec["totp_enabled"] = bool(rec.get("totp_enabled", False))
        users["admin"] = rec
        _write_users(users)
    except Exception as e:
        LOG.error("wizard: password update failed: %s", e)
        return {"ok": False, "error": f"password update failed: {e}"}

    # 2. Update config
    try:
        staged = cfg_store.get_staging()
        cfg = dict(staged if staged is not None else cfg_store.read())
        sys_cfg = cfg.setdefault("system", {})
        sys_cfg["hostname"] = hostname
        sys_cfg["timezone"] = timezone
        validate(cfg)
        cfg_store.stage(cfg, author="wizard")
        info = cfg_store.commit(author="wizard", message="first-run setup")
    except Exception as e:
        LOG.error("wizard: config commit failed: %s", e)
        return {"ok": False, "error": f"config commit failed: {e}"}

    # 3. Apply hostname live (best-effort)
    try:
        subprocess.run(["hostnamectl", "set-hostname", hostname],
                       capture_output=True, timeout=5)
    except Exception as e:
        LOG.warning("wizard: hostnamectl failed: %s", e)

    _update_etc_hosts(hostname)

    # 4. Remove marker
    try:
        os.unlink(MARKER)
    except FileNotFoundError:
        pass
    except OSError as e:
        LOG.warning("wizard: marker removal failed: %s", e)

    LOG.info("wizard complete: hostname=%s rev=%s", hostname, info.revision)
    return {"ok": True, "revision": info.revision,
            "hostname": hostname, "timezone": timezone}
