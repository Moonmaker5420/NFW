"""FreeRADIUS config compiler (Phase 9.13a).

Generates:
  - /etc/freeradius/3.0/clients.conf
  - /etc/freeradius/3.0/mods-config/files/authorize
  - /etc/freeradius/3.0/mods-config/nfw/eap
  - /etc/freeradius/3.0/mods-config/nfw/ldap
  - /etc/freeradius/3.0/sites-enabled/nfw
  - /etc/freeradius/3.0/sites-enabled/nfw-inner-tunnel

Exposes:
  - generate_clients_conf(cfg)
  - generate_authorize(cfg)
  - generate_eap_conf(cfg)
  - generate_ldap_conf(cfg)
  - generate_site_conf(cfg)
  - generate_inner_tunnel(cfg)
  - nt_hash(password) -> uppercase hex
"""
from __future__ import annotations


# ---------------------------------------------------------------------------
# Pure-Python MD4 — needed for NT-Password (MSCHAPv2)
# ---------------------------------------------------------------------------
def _md4(data: bytes) -> bytes:
    def _lrot(x, n): return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    def _f(x, y, z): return (x & y) | (~x & z)
    def _g(x, y, z): return (x & y) | (x & z) | (y & z)
    def _h(x, y, z): return x ^ y ^ z

    msg = bytearray(data)
    orig_len = len(msg)
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += (orig_len * 8).to_bytes(8, "little")

    A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    for off in range(0, len(msg), 64):
        X = [int.from_bytes(msg[off + 4 * i: off + 4 * i + 4], "little") for i in range(16)]
        AA, BB, CC, DD = A, B, C, D

        for i, s in zip(range(16), [3, 7, 11, 19] * 4):
            A = _lrot((A + _f(B, C, D) + X[i]) & 0xFFFFFFFF, s)
            A, B, C, D = D, A, B, C

        for i, s in zip(range(16), [3, 5, 9, 13] * 4):
            k = (i % 4) * 4 + (i // 4)
            A = _lrot((A + _g(B, C, D) + X[k] + 0x5A827999) & 0xFFFFFFFF, s)
            A, B, C, D = D, A, B, C

        for i, s in zip(range(16), [3, 9, 11, 15] * 4):
            k = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15][i]
            A = _lrot((A + _h(B, C, D) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)
            A, B, C, D = D, A, B, C

        A = (A + AA) & 0xFFFFFFFF
        B = (B + BB) & 0xFFFFFFFF
        C = (C + CC) & 0xFFFFFFFF
        D = (D + DD) & 0xFFFFFFFF

    return A.to_bytes(4, "little") + B.to_bytes(4, "little") + \
           C.to_bytes(4, "little") + D.to_bytes(4, "little")


def nt_hash(password: str) -> str:
    """NT hash of password (uppercase hex). Per MS-NLMP."""
    return _md4(password.encode("utf-16-le")).hex().upper()


# ---------------------------------------------------------------------------
# Config generators
# ---------------------------------------------------------------------------
def generate_clients_conf(cfg: dict) -> str:
    rc = cfg.get("services", {}).get("radius_config", {}) or {}
    listen_ip = rc.get("listen_ip") or "127.0.0.1"
    secret = rc.get("localhost_secret") or "testing123"
    clients = rc.get("clients") or []

    L = ["# NFW — GENERATED clients.conf. Do not edit by hand.", ""]
    L += [
        "client localhost {",
        "    ipaddr = 127.0.0.1",
        f"    secret = {secret}",
        "    shortname = localhost",
        "    nas_type = other",
        "    require_message_authenticator = true",
        "}",
        "",
    ]
    if listen_ip and listen_ip != "127.0.0.1":
        L += [
            "client localhost_listen {",
            f"    ipaddr = {listen_ip}",
            f"    secret = {secret}",
            "    shortname = localhost_listen",
            "    nas_type = other",
            "    require_message_authenticator = true",
            "}",
            "",
        ]
    for c in clients:
        name = c.get("name") or "client"
        ip = c.get("ip") or ""
        sec = c.get("secret") or ""
        if not ip or not sec:
            continue
        L += [
            f"client {name} {{",
            f"    ipaddr = {ip}",
            f"    secret = {sec}",
            f"    shortname = {name}",
            "    nas_type = other",
            "    require_message_authenticator = true",
            "}",
            "",
        ]
    return "\n".join(L)


def generate_authorize(cfg: dict) -> str:
    rc = cfg.get("services", {}).get("radius_config", {}) or {}
    users = rc.get("local_users") or []
    L = [
        "# NFW — GENERATED users file. Do not edit by hand.",
        "# Format: username  NT-Password := <hex>",
        "",
    ]
    for u in users:
        if not u.get("enabled", True):
            continue
        username = (u.get("username") or "").strip()
        if not username:
            continue
        nt = (u.get("nt_hash") or "").strip()
        if not nt:
            continue
        L.append(f"{username}  NT-Password := {nt}")
    L.append("")
    L.append("DEFAULT  Auth-Type := Reject")
    L.append("")
    return "\n".join(L)


def _eap_block(rc: dict) -> str:
    methods = rc.get("eap_methods") or ["peap", "ttls"]
    default = rc.get("default_eap_type") or "peap"

    L = [
        "eap {",
        f"    default_eap_type = {default}",
        "    timer_expire     = 60",
        "    ignore_unknown_eap_types = no",
        "    cisco_accounting_username_bug = no",
        "    max_sessions = 4096",
        "",
        "    md5 {",
        '        auth_type = "EAP"',
        "    }",
        "",
        "    tls-config tls-common {",
        "        private_key_file = ${certdir}/server.key",
        "        certificate_file = ${certdir}/server.crt",
        "        ca_file = ${certdir}/ca.pem",
        "        random_file = /dev/urandom",
        "        fragment_size = 1024",
        "        include_length = yes",
        "        check_crl = no",
        '        cipher_list = "DEFAULT"',
        '        ecdh_curve = "prime256v1"',
        "        cache {",
        "            enable = yes",
        "            lifetime = 24",
        "            max_entries = 255",
        "        }",
        "    }",
        "",
    ]
    if "peap" in methods:
        L += [
            "    peap {",
            "        tls = tls-common",
            "        default_eap_type = mschapv2",
            "        copy_request_to_tunnel = no",
            "        use_tunneled_reply = no",
            '        virtual_server = "inner-tunnel"',
            "    }",
            "",
        ]
    if "ttls" in methods:
        L += [
            "    ttls {",
            "        tls = tls-common",
            "        default_eap_type = md5",
            "        copy_request_to_tunnel = no",
            "        use_tunneled_reply = no",
            '        virtual_server = "inner-tunnel"',
            "    }",
            "",
        ]
    if "tls" in methods:
        L += [
            "    tls {",
            "        tls = tls-common",
            "    }",
            "",
        ]
    L.append("}")
    return "\n".join(L)


def generate_eap_conf(cfg: dict) -> str:
    rc = cfg.get("services", {}).get("radius_config", {}) or {}
    return "# NFW — GENERATED eap module. Do not edit by hand.\n\n" + _eap_block(rc)


def generate_ldap_conf(cfg: dict) -> str:
    ldap = cfg.get("auth", {}).get("ldap", {}) or {}
    server = ldap.get("server") or "ldap.forumsys.com"
    port = ldap.get("port") or 389
    bd = ldap.get("bind_dn") or ""
    bp = ldap.get("bind_password") or ""
    basedn = ldap.get("base_dn") or ""
    filt = ldap.get("user_filter") or "(uid=%{%{Stripped-User-Name}:-%{User-Name}})"

    L = [
        "# NFW — GENERATED ldap module. Do not edit by hand.",
        "ldap {",
        f'    server = "{server}"',
        f"    port = {port}",
        f'    identity = "{bd}"',
        f'    password = "{bp}"',
        f'    base_dn = "{basedn}"',
        "    user {",
        f'        base_dn = "{basedn}"',
        f'        filter = "{filt}"',
        "    }",
        "    update {",
        "        control:Password-With-Header += 'userPassword'",
        "    }",
        "    tls {",
        "        start_tls = no",
        "    }",
        "    pool {",
        "        start = 0",
        "        min = 0",
        "        max = 10",
        "        spare = 3",
        "        uses = 0",
        "        lifetime = 0",
        "        idle_timeout = 60",
        "    }",
        "}",
        "",
    ]
    return "\n".join(L)


def generate_site_conf(cfg: dict) -> str:
    rc = cfg.get("services", {}).get("radius_config", {}) or {}
    listen_ip = rc.get("listen_ip") or "127.0.0.1"
    auth_port = rc.get("auth_port") or 1812
    acct_port = rc.get("acct_port") or 1813
    acct_on = (rc.get("accounting") or {}).get("enabled", True)

    L = [
        "# NFW — GENERATED virtual server. Do not edit by hand.",
        "",
        "server nfw {",
        "    # LAN listener — for real NAS devices",
        "    listen {",
        f"        ipaddr = {listen_ip}",
        f"        port = {auth_port}",
        "        type = auth",
        "    }",
        "    # Loopback listener — for local testing (radtest)",
        "    listen {",
        "        ipaddr = 127.0.0.1",
        f"        port = {auth_port}",
        "        type = auth",
        "    }",
    ]
    if acct_on:
        L += [
            "    listen {",
            f"        ipaddr = {listen_ip}",
            f"        port = {acct_port}",
            "        type = acct",
            "    }",
            "    listen {",
            "        ipaddr = 127.0.0.1",
            f"        port = {acct_port}",
            "        type = acct",
            "    }",
        ]
    L += [
        "",
        "    authorize {",
        "        preprocess",
        "        chap",
        "        mschap",
        "        suffix",
        "        eap {",
        "            ok = return",
        "        }",
        "        files",
        "        expiration",
        "        logintime",
        "        pap",
        "    }",
        "",
        "    authenticate {",
        "        pap",
        "        chap",
        "        mschap",
        "        eap",
        "    }",
        "",
        "    preacct {",
        "        preprocess",
        "        acct_unique",
        "        suffix",
        "        files",
        "    }",
        "",
        "    accounting {",
        "        detail",
        "        unix",
        "        radutmp",
        "        exec",
        "    }",
        "",
        "    post-auth {",
        "        update {",
        "            &reply: += &session-state:",
        "        }",
        "        exec",
        "        Post-Auth-Type REJECT {",
        "            attr_filter.access_reject",
        "        }",
        "    }",
        "",
        "    pre-proxy {",
        "    }",
        "",
        "    post-proxy {",
        "        eap",
        "    }",
        "}",
        "",
    ]
    return "\n".join(L)

def generate_inner_tunnel(cfg: dict) -> str:
    rc = cfg.get("services", {}).get("radius_config", {}) or {}
    use_ldap = rc.get("use_ldap", False)

    L = [
        "# NFW — GENERATED inner-tunnel. Do not edit by hand.",
        "",
        "server inner-tunnel {",
        "    listen {",
        "        ipaddr = 127.0.0.1",
        "        port = 18120",
        "        type = auth",
        "    }",
        "",
        "    authorize {",
        "        filter_username",
        "        chap",
        "        mschap",
        "        suffix",
        "        update control {",
        "            &Proxy-To-Realm := LOCAL",
        "        }",
        "        eap {",
        "            ok = return",
        "        }",
        "        files",
    ]
    if use_ldap:
        L.append("        ldap")
    L += [
        "        expiration",
        "        logintime",
        "        pap",
        "    }",
        "",
        "    authenticate {",
        "        pap",
        "        chap",
        "        mschap",
        "        eap",
        "    }",
        "",
        "    post-auth {",
        "        update {",
        "            &reply: += &session-state:",
        "        }",
        "        Post-Auth-Type REJECT {",
        "            attr_filter.access_reject",
        "        }",
        "    }",
        "}",
        "",
    ]
    return "\n".join(L)

