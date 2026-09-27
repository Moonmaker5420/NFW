"""LDAP / Active Directory authentication (Phase 9.9b)."""
from __future__ import annotations
import logging
import ssl
from typing import Any

LOG = logging.getLogger("auth.ldap")

_RANK = {"readonly": 1, "operator": 2, "admin": 3}


def _role_from_groups(groups: list, mapping: dict, default: str) -> str:
    """Return the highest role matched by any of the user's group DNs."""
    best = None
    for g in groups:
        gs = str(g).strip().lower()
        for dn, role in (mapping or {}).items():
            if str(dn).strip().lower() == gs and role in _RANK:
                if best is None or _RANK[role] > _RANK[best]:
                    best = role
    return best or (default if default in _RANK else "readonly")


def authenticate(cfg: dict, username: str, password: str) -> dict[str, Any]:
    try:
        from ldap3 import Server, Connection, Tls, SUBTREE
        from ldap3.core.exceptions import LDAPException
        from ldap3.utils.conv import escape_filter_chars
    except ImportError as e:
        return {"ok": False, "reason": f"ldap3 not installed: {e}"}

    lc = (cfg.get("auth") or {}).get("ldap") or {}
    server_addr = (lc.get("server") or "").strip()
    if not server_addr:
        return {"ok": False, "reason": "no ldap server configured"}

    port = int(lc.get("port", 389))
    use_ssl = bool(lc.get("use_ssl", False))
    use_starttls = bool(lc.get("use_starttls", False))
    timeout_f = float(lc.get("timeout", 5))
    timeout = int(max(1, timeout_f))

    tls = None
    if use_ssl or use_starttls:
        ca = (lc.get("ca_cert") or "").strip()
        validate = ssl.CERT_REQUIRED if ca else ssl.CERT_NONE
        if ca:
            tls = Tls(validate=validate, ca_certs_file=ca)
        else:
            tls = Tls(validate=validate)

    try:
        server = Server(server_addr, port=port, use_ssl=use_ssl, tls=tls,
                        connect_timeout=timeout)
    except Exception as e:
        return {"ok": False, "reason": f"server init failed: {e}"}

    # 1. Service bind
    bind_dn = (lc.get("bind_dn") or "").strip()
    bind_pw = lc.get("bind_password") or ""
    try:
        if bind_dn:
            conn = Connection(server, user=bind_dn, password=bind_pw,
                              auto_bind=True, raise_exceptions=True,
                              receive_timeout=int(timeout))
        else:
            conn = Connection(server, auto_bind=True, raise_exceptions=True,
                              receive_timeout=int(timeout))
    except LDAPException as e:
        return {"ok": False, "reason": f"service bind failed: {e}"}
    except Exception as e:
        return {"ok": False, "reason": f"service bind error: {e}"}

    # 2. Search for the user
    base_dn = (lc.get("base_dn") or "").strip()
    if not base_dn:
        conn.unbind()
        return {"ok": False, "reason": "base_dn required"}
    ufilter = (lc.get("user_filter") or "(uid={username})").replace(
        "{username}", escape_filter_chars(username))

    try:
        # Request all user attributes with "*". ldap3 validates the names
        # against the server schema, so naming AD-only attributes
        # (sAMAccountName, memberOf, ...) breaks on plain OpenLDAP.
        conn.search(base_dn, ufilter, search_scope=SUBTREE,
                    attributes=["*"])
    except LDAPException as e:
        conn.unbind()
        return {"ok": False, "reason": f"search failed: {e}"}
    except Exception as e:
        conn.unbind()
        return {"ok": False, "reason": f"search error: {e}"}

    if not conn.entries:
        conn.unbind()
        return {"ok": False, "reason": "user not found"}

    user_dn = conn.entries[0].entry_dn
    groups: list[str] = []
    # memberOf only exists on Active Directory and OpenLDAP with the
    # memberof overlay. Access it defensively.
    try:
        entry = conn.entries[0]
        # ldap3 Entry attribute access is via __getattr__, which raises
        # LDAPCursorAttributeError if the attribute isn't present.
        if "memberOf" in entry:
            mo = entry.memberOf
            vals = getattr(mo, "values", None)
            if vals is not None:
                groups = [str(g) for g in vals]
            else:
                groups = [str(g) for g in mo]
    except Exception as _e:
        LOG.debug("memberOf not available: %s", _e)
    conn.unbind()

    # 3. Bind as the user to verify the password
    try:
        uc = Connection(server, user=user_dn, password=password,
                        auto_bind=True, raise_exceptions=True,
                        receive_timeout=int(timeout))
        uc.unbind()
    except LDAPException:
        return {"ok": False, "reason": "invalid credentials"}
    except Exception as e:
        return {"ok": False, "reason": f"user bind error: {e}"}

    role = _role_from_groups(groups, lc.get("group_role_map") or {},
                             lc.get("default_role", "readonly"))
    return {"ok": True, "method": "ldap", "user_dn": user_dn,
            "role": role, "groups": groups}


def test_bind(cfg: dict) -> dict[str, Any]:
    """Test the service-account bind without touching a user."""
    try:
        from ldap3 import Server, Connection, Tls
        from ldap3.core.exceptions import LDAPException
    except ImportError as e:
        return {"ok": False, "reason": f"ldap3 not installed: {e}"}

    lc = (cfg.get("auth") or {}).get("ldap") or {}
    server_addr = (lc.get("server") or "").strip()
    if not server_addr:
        return {"ok": False, "reason": "no server configured"}
    port = int(lc.get("port", 389))
    use_ssl = bool(lc.get("use_ssl", False))
    timeout_f = float(lc.get("timeout", 5))
    timeout = int(max(1, timeout_f))

    ca = (lc.get("ca_cert") or "").strip()
    tls = None
    if use_ssl or lc.get("use_starttls"):
        validate = ssl.CERT_REQUIRED if ca else ssl.CERT_NONE
        if ca:
            tls = Tls(validate=validate, ca_certs_file=ca)
        else:
            tls = Tls(validate=validate)

    try:
        s = Server(server_addr, port=port, use_ssl=use_ssl, tls=tls,
                   connect_timeout=timeout)
        c = Connection(s, user=(lc.get("bind_dn") or "") or None,
                       password=(lc.get("bind_password") or "") or None,
                       auto_bind=True, raise_exceptions=True,
                       receive_timeout=timeout)
        server_info = ""
        try:
            if s.info and s.info.naming_contexts:
                server_info = "naming_contexts: " + ", ".join(s.info.naming_contexts)
        except Exception:
            pass
        c.unbind()
        return {"ok": True, "info": server_info}
    except LDAPException as e:
        return {"ok": False, "reason": str(e)}
    except Exception as e:
        return {"ok": False, "reason": f"{type(e).__name__}: {e}"}
