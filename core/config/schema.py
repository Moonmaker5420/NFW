"""
Default config + validation (Phase 4 — adds firewall rules/aliases/NAT).
"""
from __future__ import annotations
import re

import copy
from typing import Any

DEFAULT_CONFIG: dict[str, Any] = {
    "version": 1,
    "system": {
        "hostname": "nfw",
        "domain": "lan",
        "timezone": "UTC",
        "admin_email": "",
    },
    "network": {
        "wan": "auto",
        "lan": "auto",
        "opt": [],
        "interfaces": {},
        "advanced_interfaces": [],
        "gateways": {"gateways": [], "groups": [], "static_routes": []},
    },
    "firewall": {
        "ruleset_file": "/etc/nftables.conf",
        "wan_ssh_enabled": True,
        "log_drops": True,
        "rules": [],
        "aliases": [],
        "nat": {
            "port_forwards": [],
            "outbound": [],
            "one_to_one": [],
            "npt": [],
            "reflection": {
                "enabled": False,
            },
            "upnp": {
                "enabled": False,
                "external_iface": "wan",
                "internal_iface": "lan",
                "allow": [],
                "deny": [],
                "secure_mode": True,
                "http_port": 5000,
                "presentation_url": "http://192.168.10.1:8080/",
            },
        },
        "schedules": [],
        "normalization": {
            "mss_clamp": False,
            "mss_clamp_size": 1452,
            "frag_policy": "pass",
            "drop_invalid": True,
            "icmp_drop_redirects": True,
            "icmp_drop_source_quench": True,
            "syn_flood_protect": False,
            "log_martians": False,
        },
    },
    "auth": {
        "providers": [
            {"type": "local", "enabled": True},
            {"type": "ldap", "enabled": False},
            {"type": "radius", "enabled": False},
            {"type": "oauth", "enabled": False},
        ],
        "acls": {
            "enabled": False,
            "roles": {
                "readonly": {"allow": ["GET **"], "deny": []},
                "operator": {
                    "allow": [
                        "GET **",
                        "POST /api/config/stage",
                        "POST /api/config/validate",
                        "POST /api/firewall/rules**",
                        "PUT /api/firewall/rules/**",
                        "DELETE /api/firewall/rules/**",
                        "POST /api/firewall/aliases**",
                        "PUT /api/firewall/aliases/**",
                        "DELETE /api/firewall/aliases/**",
                        "POST /api/firewall/nat/**",
                        "PUT /api/firewall/nat/**",
                        "DELETE /api/firewall/nat/**",
                        "PUT /api/firewall/normalization",
                        "POST /api/firewall/schedules**",
                        "PUT /api/firewall/schedules/**",
                        "DELETE /api/firewall/schedules/**",
                        "PUT /api/services/**",
                        "POST /api/services/**",
                        "POST /api/gateways",
                        "PUT /api/gateways/**",
                        "DELETE /api/gateways/**",
                        "POST /api/gateways/groups**",
                        "POST /api/gateways/routes**",
                        "POST /api/vpn/**",
                        "PUT /api/vpn/**",
                        "DELETE /api/vpn/**",
                        "POST /api/ids",
                        "PUT /api/ids",
                        "POST /api/ids/update-rules",
                        "PUT /api/shaper",
                        "POST /api/users/*/password",
                        "POST /api/users/*/2fa/setup",
                        "POST /api/users/*/2fa/enable",
                        "POST /api/users/*/2fa/disable",
                        "PUT /api/network/ifaces/**",
                        "POST /api/network/ifaces**",
                        "POST /api/interfaces/advanced",
                        "PUT /api/interfaces/advanced/**",
                        "DELETE /api/interfaces/advanced/**",
                    ],
                    "deny": [
                        "POST **/apply",
                        "POST **/commit",
                        "POST **/rollback",
                        "POST **/reload",
                        "POST **/sync",
                    ],
                },
                "admin": {"allow": ["*"], "deny": []},
            },
            "users": {},
        },
        "ldap": {
            "enabled": False,
            "server": "",
            "port": 389,
            "use_ssl": False,
            "use_starttls": False,
            "ca_cert": "",
            "bind_dn": "",
            "bind_password": "",
            "base_dn": "",
            "user_filter": "(uid={username})",
            "group_role_map": {},
            "default_role": "readonly",
            "auto_create": True,
            "timeout": 5,
        },
        "radius": {
            "enabled": False,
            "server": "",
            "port": 1812,
            "secret": "",
            "nas_id": "nfw",
            "timeout": 5,
            "attribute_role_map": {},
            "default_role": "readonly",
            "auto_create": True,
        },
    },
    "ca": {
        "enabled": False,
        "root_cn": "NFW Root CA",
        "intermediate_cn": "NFW Intermediate CA",
        "org": "NFW",
        "ou": "Firewall",
        "country": "US",
        "root_key_bits": 4096,
        "root_lifetime_days": 3650,
        "intermediate_lifetime_days": 1825,
        "default_server_lifetime_days": 825,
        "default_client_lifetime_days": 825,
        "default_key_bits": 2048,
        "crl_lifetime_days": 180,
    },
    "reporting": {
        "enabled": True,
        "retention_days": 365,
        "graph_default_range": "day",
        "netflow": {
            "enabled": False,
            "target": "",
            "port": 2055,
            "protocol": "v9",
            "interfaces": [],
            "max_flows": 8192,
        },
    },
    "services": {
        "dhcp": False,
        "dns": False,
        "ids": False,
        "ntp": True,
        "dhcp_config": {
            "enabled": False,
            "interface": "lan",
            "authoritative": True,
            "default_lease_time": 3600,
            "max_lease_time": 86400,
            "subnets": [],
            "static_reservations": [],
        },
        "dns_config": {
            "enabled": False,
            "listen": ["0.0.0.0"],
            "port": 53,
            "recursive": True,
            "dnssec": True,
            "qname_minimisation": True,
            "hide_identity": True,
            "hide_version": True,
            "prefetch": True,
            "so_reuseport": True,
            "num_threads": 2,
            "do_tls": False,
            "forwarders_tls": [
                {"address": "1.1.1.1@853", "tls_name": "cloudflare-dns.com"},
                {"address": "9.9.9.9@853", "tls_name": "dns.quad9.net"},
            ],
            "forward_zones": [],
            "host_overrides": [],
            "local_zone": "lan",
            "blocklists": {
                "enabled": False,
                "domains": [],
                "sources": [],
            },
            "access_control": ["127.0.0.0/8 allow",
                               "192.168.0.0/16 allow",
                               "10.0.0.0/8 allow"],
        },
        "ntp_config": {
            "enabled": True,
            "mode": "client",
            "servers": [
                "0.pool.ntp.org", "1.pool.ntp.org", "2.pool.ntp.org",
                "3.pool.ntp.org",
            ],
            "allow_clients": ["192.168.0.0/16", "10.0.0.0/8"],
        },
        "radius": False,
        "radius_config": {
            "enabled": False,
            "listen_ip": "",
            "auth_port": 1812,
            "acct_port": 1813,
            "default_eap_type": "peap",
            "eap_methods": ["peap", "ttls"],
            "clients": [],
            "local_users": [],
            "use_ldap": False,
            "accounting": {"enabled": True},
            "server_cert_serial": "",
            "localhost_secret": "testing123",
        },

        "captiveportal": False,
        "captiveportal_config": {
            "enabled": False,
            "interface": "lan",
            "portal_port": 8081,
            "gateway_name": "NFW Captive Portal",
            "session_timeout": 3600,
            "idle_timeout": 600,
            "auth_backends": ["local", "ldap"],
            "tos_required": False,
            "tos_text": "",
            "walled_garden": [],
            "branding": {
                "logo_url": "",
                "primary_color": "#58a6ff",
                "welcome_text": "Welcome to the network. Please sign in."
            },
            "auth_mode": "multi",
            "splash_label": "Connect",
            "splash_extra_text": "",
            "concurrent_logins": 0,
            "concurrent_mode": "deny_new",
            "hard_timeout": 0,
            "welcome_back": 0,
            "bypass_macs": [],
            "bypass_hostnames": [],
            "bypass_refresh_seconds": 120,
            "template_id": "",
            "redirect_after_login": "",
            "disable_auto_rules": False,
            "dhcp_option_114": True,
            "default_bandwidth_up_kbps": 0,
            "default_bandwidth_down_kbps": 0,
            "voucher_defaults": {
                "code_length": 8,
                "code_alphabet": "ABCDEFGHJKLMNPQRSTUVWXYZ23456789",
                "validity_minutes": 1440,
                "session_timeout": 3600,
                "max_sessions": 1,
                "batch_prefix": ""
            }
        },
    },
    "ui": {"theme": "dark", "language": "en", "page_size": 25},
    "api": {
        "listen_host": "127.0.0.1",
        "listen_port": 8080,
        "session_lifetime_s": 3600,
        "tls": {
            "enabled": False,
            "cert_serial": "",
            "listen_port": 8443,
        },
    },
    "ids_config": {
        "enabled": False,
        "mode": "ids",
        "interfaces": ["wan"],
        "home_nets": [],
        "external_net": "!$HOME_NET",
        "rule_paths": ["/var/lib/suricata/rules/suricata.rules"],
    },
    "shaper_config": {
        "enabled": False,
        "interfaces": [],
    },
    "haproxy_config": {
        "enabled": False, "frontends": [], "backends": [],
        "stats_enabled": True, "stats_port": 8404,
    },
    "squid_config": {
        "enabled": False, "port": 3128, "transparent": False,
        "cache_size_mb": 1000, "allowed_nets": [], "blocked_domains": [],
    },
    "ddns_config": {"entries": []},
    "snmp_config": {
        "enabled": False, "location": "Unknown", "contact": "admin@localhost",
        "communities": [{"name": "public", "access": "ro"}],
        "allowed_nets": ["127.0.0.1"],
    },
    "vpn": {
        "wireguard": {"instances": []},
        "openvpn": {"servers": []},
        "ipsec": {"tunnels": []},
    },
}


def default_config() -> dict[str, Any]:
    return copy.deepcopy(DEFAULT_CONFIG)


import re as _re_global

# Template IDs are lowercase hex-ish safe slugs generated by our own code.
_TEMPLATE_ID_RE = _re_global.compile(r"^[a-z0-9]{8,32}$")


class SchemaError(ValueError):
    pass


def _require_keys(obj: dict, required: list[str], path: str) -> None:
    for k in required:
        if k not in obj:
            raise SchemaError(f"{path}: missing required key '{k}'")



def _validate_radius(svc: dict) -> None:
    rc = svc.get("radius_config") or {}
    if not isinstance(rc, dict):
        raise SchemaError("services.radius_config must be an object")
    if "enabled" in rc and not isinstance(rc["enabled"], bool):
        raise SchemaError("services.radius_config.enabled must be bool")
    if "auth_port" in rc:
        p = rc["auth_port"]
        if not isinstance(p, int) or not (1 <= p <= 65535):
            raise SchemaError("services.radius_config.auth_port invalid")
    if "acct_port" in rc:
        p = rc["acct_port"]
        if not isinstance(p, int) or not (1 <= p <= 65535):
            raise SchemaError("services.radius_config.acct_port invalid")
    if "default_eap_type" in rc:
        if rc["default_eap_type"] not in ("peap", "ttls", "tls"):
            raise SchemaError("services.radius_config.default_eap_type invalid")
    if "eap_methods" in rc:
        if not isinstance(rc["eap_methods"], list):
            raise SchemaError("services.radius_config.eap_methods must be a list")
        for m in rc["eap_methods"]:
            if m not in ("peap", "ttls", "tls"):
                raise SchemaError(f"services.radius_config.eap_methods invalid: {m}")
    if "clients" in rc:
        if not isinstance(rc["clients"], list):
            raise SchemaError("services.radius_config.clients must be a list")
        for i, c in enumerate(rc["clients"]):
            if not isinstance(c, dict): raise SchemaError(f"radius_config.clients[{i}] must be object")
            if not c.get("name"): raise SchemaError(f"radius_config.clients[{i}].name required")
            ip = c.get("ip", "")
            if not ip: raise SchemaError(f"radius_config.clients[{i}].ip required")
            try:
                import ipaddress
                ipaddress.ip_network(ip, strict=False)
            except Exception:
                raise SchemaError(f"radius_config.clients[{i}].ip invalid")
            sec = c.get("secret", "")
            if not sec or len(sec) < 6:
                raise SchemaError(f"radius_config.clients[{i}].secret must be >=6 chars")
    if "local_users" in rc:
        if not isinstance(rc["local_users"], list):
            raise SchemaError("services.radius_config.local_users must be a list")
        for i, u in enumerate(rc["local_users"]):
            if not isinstance(u, dict): raise SchemaError(f"radius_config.local_users[{i}] must be object")
            if not u.get("username"): raise SchemaError(f"radius_config.local_users[{i}].username required")



def _validate_captiveportal(svc: dict) -> None:
    cp = svc.get("captiveportal_config") or {}
    if not isinstance(cp, dict):
        raise SchemaError("services.captiveportal_config must be an object")
    if "enabled" in cp and not isinstance(cp["enabled"], bool):
        raise SchemaError("services.captiveportal_config.enabled must be bool")
    if "interface" in cp and cp["interface"] not in ("lan", "opt1", "opt2", "opt3"):
        raise SchemaError("services.captiveportal_config.interface invalid")
    p = cp.get("portal_port", 8081)
    if not isinstance(p, int) or not (1024 <= p <= 65535):
        raise SchemaError("services.captiveportal_config.portal_port must be 1024-65535")
    for k in ("session_timeout", "idle_timeout"):
        v = cp.get(k)
        if v is not None:
            if not isinstance(v, int) or v < 60:
                raise SchemaError(f"services.captiveportal_config.{k} must be int >= 60")
    ab = cp.get("auth_backends") or []
    if not isinstance(ab, list) or not ab:
        raise SchemaError("services.captiveportal_config.auth_backends must be non-empty list")
    for b in ab:
        if b not in ("local", "ldap", "radius"):
            raise SchemaError(f"services.captiveportal_config.auth_backends invalid: {b}")
    wg = cp.get("walled_garden") or []
    if not isinstance(wg, list):
        raise SchemaError("services.captiveportal_config.walled_garden must be a list")
    for entry in wg:
        if not isinstance(entry, str) or not entry:
            raise SchemaError("walled_garden entries must be non-empty strings")
    br = cp.get("branding") or {}
    if not isinstance(br, dict):
        raise SchemaError("services.captiveportal_config.branding must be an object")



def _validate_captiveportal_b2(svc: dict) -> None:
    cp = svc.get("captiveportal_config") or {}
    if "auth_mode" in cp:
        if cp["auth_mode"] not in ("multi", "splash", "credentials", "voucher"):
            raise SchemaError("services.captiveportal_config.auth_mode invalid")
    if "splash_label" in cp and not isinstance(cp["splash_label"], str):
        raise SchemaError("services.captiveportal_config.splash_label must be string")
    if "splash_extra_text" in cp and not isinstance(cp["splash_extra_text"], str):
        raise SchemaError("services.captiveportal_config.splash_extra_text must be string")
    if "concurrent_logins" in cp:
        v = cp["concurrent_logins"]
        if not isinstance(v, int) or v < 0 or v > 100:
            raise SchemaError("services.captiveportal_config.concurrent_logins must be 0..100")
    if "concurrent_mode" in cp:
        if cp["concurrent_mode"] not in ("deny_new", "kick_oldest"):
            raise SchemaError("services.captiveportal_config.concurrent_mode invalid")


def _validate_captiveportal_b3(svc: dict) -> None:
    cp = svc.get("captiveportal_config") or {}
    bm = cp.get("bypass_macs")
    if bm is not None:
        if not isinstance(bm, list):
            raise SchemaError("services.captiveportal_config.bypass_macs must be a list")
        import re as _r
        mac_re = _r.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")
        for i, m in enumerate(bm):
            if not isinstance(m, str) or not mac_re.match(m):
                raise SchemaError(f"services.captiveportal_config.bypass_macs[{i}] invalid (AA:BB:CC:DD:EE:FF)")
    bh = cp.get("bypass_hostnames")
    if bh is not None:
        if not isinstance(bh, list):
            raise SchemaError("services.captiveportal_config.bypass_hostnames must be a list")
        import re as _r
        fqdn_re = _r.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$")
        for i, h in enumerate(bh):
            if not isinstance(h, str) or not h:
                raise SchemaError(f"services.captiveportal_config.bypass_hostnames[{i}] must be non-empty string")
            stripped = h[2:] if h.startswith("*.") else h
            if "*" in stripped or not fqdn_re.match(stripped):
                raise SchemaError(
                    f"services.captiveportal_config.bypass_hostnames[{i}] invalid "
                    "(FQDN or *.wildcard only, no IPs)")
    r = cp.get("bypass_refresh_seconds")
    if r is not None:
        if not isinstance(r, int) or r < 30 or r > 3600:
            raise SchemaError("services.captiveportal_config.bypass_refresh_seconds must be 30..3600")


def _validate_captiveportal_b4(svc: dict) -> None:
    cp = svc.get("captiveportal_config") or {}
    tid = cp.get("template_id")
    if tid is not None:
        if not isinstance(tid, str):
            raise SchemaError("services.captiveportal_config.template_id must be a string")
        if tid and not _TEMPLATE_ID_RE.match(tid):
            raise SchemaError("services.captiveportal_config.template_id invalid format")
    redir = cp.get("redirect_after_login")
    if redir is not None:
        if not isinstance(redir, str):
            raise SchemaError("services.captiveportal_config.redirect_after_login must be a string")
        if redir:
            if not (redir.startswith("http://") or redir.startswith("https://")):
                raise SchemaError("services.captiveportal_config.redirect_after_login must be http(s)://")
            if len(redir) > 500:
                raise SchemaError("services.captiveportal_config.redirect_after_login too long")

def _validate_captiveportal_b5(svc: dict) -> None:
    cp = svc.get("captiveportal_config") or {}
    for k in ("default_bandwidth_up_kbps", "default_bandwidth_down_kbps"):
        v = cp.get(k)
        if v is None:
            continue
        if not isinstance(v, int) or v < 0 or v > 10_000_000:
            raise SchemaError(f"services.captiveportal_config.{k} must be 0..10000000")


def _validate_captiveportal_9_18_polish(svc: dict) -> None:
    cp = svc.get("captiveportal_config") or {}
    v = cp.get("disable_auto_rules")
    if v is not None and not isinstance(v, bool):
        raise SchemaError("services.captiveportal_config.disable_auto_rules must be bool")
    v = cp.get("dhcp_option_114")
    if v is not None and not isinstance(v, bool):
        raise SchemaError("services.captiveportal_config.dhcp_option_114 must be bool")



def validate(cfg: dict[str, Any]) -> None:
    if not isinstance(cfg, dict):
        raise SchemaError("config must be a JSON object")
    _require_keys(cfg, ["version", "system", "network", "firewall",
                        "services", "ui", "api"], "root")
    if not isinstance(cfg["version"], int) or cfg["version"] < 1:
        raise SchemaError("version must be a positive int")

    sysc = cfg["system"]
    _require_keys(sysc, ["hostname", "domain", "timezone"], "system")
    for k in ("hostname", "domain", "timezone"):
        if not isinstance(sysc[k], str) or not sysc[k]:
            raise SchemaError(f"system.{k} must be a non-empty string")

    net = cfg["network"]
    _require_keys(net, ["wan", "lan", "opt"], "network")
    for k in ("wan", "lan"):
        if not isinstance(net[k], str) or not net[k]:
            raise SchemaError(f"network.{k} must be a non-empty string")
    if not isinstance(net["opt"], list):
        raise SchemaError("network.opt must be a list")
    # interfaces is an optional dict: {device: {role, ipv4: {...}, ipv6: {...}}}
    ifs = net.get("interfaces")
    gws = net.get("gateways")
    if gws is not None:
        if not isinstance(gws, dict):
            raise SchemaError("network.gateways must be an object")
        for k in ("gateways", "groups", "static_routes"):
            if k not in gws:
                raise SchemaError(f"network.gateways.{k} missing")
            if not isinstance(gws[k], list):
                raise SchemaError(f"network.gateways.{k} must be a list")
    if ifs is not None:
        if not isinstance(ifs, dict):
            raise SchemaError("network.interfaces must be an object")
        for dev, cfg_iface in ifs.items():
            if not isinstance(cfg_iface, dict):
                raise SchemaError(f"network.interfaces.{dev} must be an object")
            ipv4 = cfg_iface.get("ipv4", {})
            if isinstance(ipv4, dict):
                mode = ipv4.get("mode", "dhcp")
                if mode not in ("dhcp", "static", "none"):
                    raise SchemaError(f"{dev}.ipv4.mode must be dhcp|static|none")
                if mode == "static":
                    if not ipv4.get("address"):
                        raise SchemaError(f"{dev}.ipv4.address required when mode=static")
                    if not ipv4.get("prefixlen"):
                        raise SchemaError(f"{dev}.ipv4.prefixlen required when mode=static")

    fw = cfg["firewall"]
    _require_keys(fw, ["ruleset_file", "wan_ssh_enabled", "log_drops"], "firewall")
    if not isinstance(fw["ruleset_file"], str) or not fw["ruleset_file"]:
        raise SchemaError("firewall.ruleset_file must be a non-empty string")
    if not isinstance(fw["wan_ssh_enabled"], bool):
        raise SchemaError("firewall.wan_ssh_enabled must be bool")
    if not isinstance(fw["log_drops"], bool):
        raise SchemaError("firewall.log_drops must be bool")

    _VALID_STATETYPES = {"", "new", "established", "related", "invalid"}
    _VALID_ICMP_TYPES = {
        "", "echo-request", "echo-reply", "destination-unreachable",
        "redirect", "time-exceeded", "parameter-problem",
        "router-advertisement", "router-solicitation",
        "neighbor-solicitation", "neighbor-advertisement",
    }
    _VALID_DSCP = {"", "cs0","cs1","cs2","cs3","cs4","cs5","cs6","cs7",
                   "af11","af12","af13","af21","af22","af23",
                   "af31","af32","af33","af41","af42","af43",
                   "ef"}

    rules = fw.get("rules", [])
    if not isinstance(rules, list):
        raise SchemaError("firewall.rules must be a list")
    for i, r in enumerate(rules):
        if not isinstance(r, dict):
            raise SchemaError(f"firewall.rules[{i}] must be an object")
        for k in ("id", "action", "interface", "direction", "proto"):
            if k not in r:
                raise SchemaError(f"firewall.rules[{i}] missing '{k}'")

        # Phase 9.7a: advanced rule fields
        st = r.get("statetype", "")
        if st not in _VALID_STATETYPES:
            raise SchemaError(f"firewall.rules[{i}].statetype invalid: {st}")
        it = r.get("icmp_type", "")
        if it and it not in _VALID_ICMP_TYPES:
            raise SchemaError(f"firewall.rules[{i}].icmp_type invalid: {it}")
        dscp = r.get("dscp", "")
        if dscp and dscp not in _VALID_DSCP:
            raise SchemaError(f"firewall.rules[{i}].dscp invalid: {dscp}")
        for k in ("tcpflags1", "tcpflags2"):
            v = r.get(k, "")
            if v and not re.match(r"^(FIN|SYN|RST|PSH|ACK|URG|ECE|CWR)(,(FIN|SYN|RST|PSH|ACK|URG|ECE|CWR))*$", v):
                raise SchemaError(f"firewall.rules[{i}].{k} invalid: {v}")
        for k in ("schedule", "tag", "tagged", "log_limit"):
            v = r.get(k, "")
            if v and not isinstance(v, str):
                raise SchemaError(f"firewall.rules[{i}].{k} must be string")

    aliases = fw.get("aliases", [])
    if not isinstance(aliases, list):
        raise SchemaError("firewall.aliases must be a list")
    for i, a in enumerate(aliases):
        if not isinstance(a, dict):
            raise SchemaError(f"firewall.aliases[{i}] must be an object")
        if "name" not in a or "type" not in a:
            raise SchemaError(f"firewall.aliases[{i}] missing name/type")
        t = a.get("type")
        if t not in ("host", "network", "port", "port_range", "url", "geoip"):
            raise SchemaError(f"firewall.aliases[{i}].type invalid: {t!r}")
        if t in ("host", "network", "port", "port_range"):
            if not isinstance(a.get("values"), list):
                raise SchemaError(f"firewall.aliases[{i}].values must be a list")
        elif t == "url":
            url = a.get("url", "")
            if not isinstance(url, str) or not url:
                raise SchemaError(f"firewall.aliases[{i}].url required")
            if not (url.startswith("https://") or url.startswith("http://")):
                raise SchemaError(f"firewall.aliases[{i}].url must be http(s)")
            if a.get("refresh", "daily") not in ("hourly","daily","weekly","monthly","manual"):
                raise SchemaError(f"firewall.aliases[{i}].refresh invalid")
            if a.get("format", "both") not in ("ipv4","ipv6","both"):
                raise SchemaError(f"firewall.aliases[{i}].format invalid")
        elif t == "geoip":
            cc = a.get("countries")
            if not isinstance(cc, list) or not cc:
                raise SchemaError(f"firewall.aliases[{i}].countries must be non-empty list")
            for c in cc:
                if not isinstance(c, str) or len(c) != 2:
                    raise SchemaError(f"firewall.aliases[{i}].countries entries must be ISO-2 codes")
            if a.get("refresh", "monthly") not in ("hourly","daily","weekly","monthly","manual"):
                raise SchemaError(f"firewall.aliases[{i}].refresh invalid")
            if a.get("format", "ipv4") not in ("ipv4","ipv6","both"):
                raise SchemaError(f"firewall.aliases[{i}].geoip format invalid")

    nat = fw.get("nat", {})
    if not isinstance(nat, dict):
        raise SchemaError("firewall.nat must be an object")
    for k in ("port_forwards", "outbound", "one_to_one", "npt"):
        if k not in nat:
            raise SchemaError(f"firewall.nat.{k} missing")
        if not isinstance(nat[k], list):
            raise SchemaError(f"firewall.nat.{k} must be a list")

    reflection = nat.get("reflection")
    if reflection is not None:
        if not isinstance(reflection, dict):
            raise SchemaError("firewall.nat.reflection must be an object")
        if "enabled" in reflection and not isinstance(reflection["enabled"], bool):
            raise SchemaError("firewall.nat.reflection.enabled must be bool")

    upnp = nat.get("upnp")
    if upnp is not None:
        if not isinstance(upnp, dict):
            raise SchemaError("firewall.nat.upnp must be an object")
        if "enabled" in upnp and not isinstance(upnp["enabled"], bool):
            raise SchemaError("firewall.nat.upnp.enabled must be bool")
        if "http_port" in upnp and upnp["http_port"] is not None:
            try:
                _hp = int(upnp["http_port"])
            except (TypeError, ValueError):
                raise SchemaError("firewall.nat.upnp.http_port must be int")
            if not (1 <= _hp <= 65535):
                raise SchemaError("firewall.nat.upnp.http_port out of range")

    # Phase 9.7a: schedules
    schedules = fw.get("schedules", [])
    if not isinstance(schedules, list):
        raise SchemaError("firewall.schedules must be a list")
    _VALID_DAYS = {"mon","tue","wed","thu","fri","sat","sun"}
    for _i, _s in enumerate(schedules):
        if not isinstance(_s, dict):
            raise SchemaError(f"firewall.schedules[{_i}] must be an object")
        for _k in ("id", "name", "ranges"):
            if _k not in _s:
                raise SchemaError(f"firewall.schedules[{_i}] missing '{_k}'")
        if not isinstance(_s["name"], str) or not _s["name"]:
            raise SchemaError(f"firewall.schedules[{_i}].name must be non-empty string")
        if not isinstance(_s["ranges"], list):
            raise SchemaError(f"firewall.schedules[{_i}].ranges must be a list")
        for _j, _r in enumerate(_s["ranges"]):
            if not isinstance(_r, dict):
                raise SchemaError(f"firewall.schedules[{_i}].ranges[{_j}] must be an object")
            for _d in _r.get("days", []):
                if _d not in _VALID_DAYS:
                    raise SchemaError(f"invalid day '{_d}'")
            for _k in ("start", "end"):
                _v = _r.get(_k, "")
                if not re.match(r"^\d{1,2}:\d{2}$", str(_v)):
                    raise SchemaError(f"firewall.schedules[{_i}].ranges[{_j}].{_k} must be HH:MM")
            # OPNsense parity: same-day only (start < end)
            _sv = _r.get("start", "00:00")
            _ev = _r.get("end", "23:59")
            try:
                _sh, _sm = (int(x) for x in _sv.split(":"))
                _eh, _em = (int(x) for x in _ev.split(":"))
            except (ValueError, TypeError):
                continue
            if (_sh, _sm) >= (_eh, _em):
                raise SchemaError(
                    f"firewall.schedules[{_i}].ranges[{_j}]: range {_sv}-{_ev} "
                    f"crosses midnight (start >= end). Split into two ranges, "
                    f"e.g. {_sv}-23:59 and 00:00-{_ev}"
                )

    # Phase 9.7a: normalization
    _norm = fw.get("normalization", {})
    if _norm and not isinstance(_norm, dict):
        raise SchemaError("firewall.normalization must be an object")
    if isinstance(_norm, dict):
        if "mss_clamp" in _norm and not isinstance(_norm["mss_clamp"], bool):
            raise SchemaError("firewall.normalization.mss_clamp must be bool")
        if "mss_clamp_size" in _norm:
            try:
                _sz = int(_norm["mss_clamp_size"])
            except (TypeError, ValueError):
                raise SchemaError("firewall.normalization.mss_clamp_size must be int")
            if not (536 <= _sz <= 65535):
                raise SchemaError("firewall.normalization.mss_clamp_size out of range")

    # Phase 9.9b: auth block
    auth = cfg.get("auth", {})
    if auth and not isinstance(auth, dict):
        raise SchemaError("auth must be an object")
    if isinstance(auth, dict):
        provs = auth.get("providers", [])
        if not isinstance(provs, list):
            raise SchemaError("auth.providers must be a list")
        for _i, _p in enumerate(provs):
            if not isinstance(_p, dict):
                raise SchemaError(f"auth.providers[{_i}] must be an object")
            if _p.get("type") not in ("local", "ldap", "radius", "oauth"):
                raise SchemaError(f"auth.providers[{_i}].type invalid")
        _ldap = auth.get("ldap", {})
        if _ldap and not isinstance(_ldap, dict):
            raise SchemaError("auth.ldap must be an object")
        if isinstance(_ldap, dict):
            for _k in ("use_ssl", "use_starttls", "auto_create"):
                if _k in _ldap and not isinstance(_ldap[_k], bool):
                    raise SchemaError(f"auth.ldap.{_k} must be bool")
            if "port" in _ldap:
                try: _p = int(_ldap["port"])
                except (TypeError, ValueError):
                    raise SchemaError("auth.ldap.port must be int")
                if not (1 <= _p <= 65535):
                    raise SchemaError("auth.ldap.port out of range")
        _rad = auth.get("radius", {})
        if _rad and not isinstance(_rad, dict):
            raise SchemaError("auth.radius must be an object")
        if isinstance(_rad, dict) and "port" in _rad:
            try: _p = int(_rad["port"])
            except (TypeError, ValueError):
                raise SchemaError("auth.radius.port must be int")
            if not (1 <= _p <= 65535):
                raise SchemaError("auth.radius.port out of range")


    _auth = cfg.get("auth", {})
    if isinstance(_auth, dict):
        _acls = _auth.get("acls", {})
        if _acls and not isinstance(_acls, dict):
            raise SchemaError("auth.acls must be an object")
        if isinstance(_acls, dict):
            if "enabled" in _acls and not isinstance(_acls["enabled"], bool):
                raise SchemaError("auth.acls.enabled must be bool")
            def _validate_pattern_list(plist, path):
                if not isinstance(plist, list):
                    raise SchemaError(f"{path} must be a list")
                for _p in plist:
                    if not isinstance(_p, str) or not _p:
                        raise SchemaError(f"{path}: patterns must be strings")

            for _k in ("roles", "users"):
                if _k in _acls and not isinstance(_acls[_k], dict):
                    raise SchemaError(f"auth.acls.{_k} must be an object")
                if not isinstance(_acls.get(_k), dict):
                    continue
                for _key, _val in _acls[_k].items():
                    if _k == "roles":
                        # Accept the legacy flat-list shape and the current
                        # dict-with-allow/deny shape.
                        if isinstance(_val, list):
                            _validate_pattern_list(_val, f"auth.acls.roles.{_key}")
                        elif isinstance(_val, dict):
                            _validate_pattern_list(_val.get("allow") or [],
                                                   f"auth.acls.roles.{_key}.allow")
                            _validate_pattern_list(_val.get("deny") or [],
                                                   f"auth.acls.roles.{_key}.deny")
                        else:
                            raise SchemaError(f"auth.acls.roles.{_key} has invalid shape")
                    else:  # users
                        if not isinstance(_val, dict):
                            raise SchemaError(f"auth.acls.users.{_key} must be an object")
                        _validate_pattern_list(_val.get("allow") or [],
                                               f"auth.acls.users.{_key}.allow")
                        _validate_pattern_list(_val.get("deny") or [],
                                               f"auth.acls.users.{_key}.deny")
        _oauth = _auth.get("oauth", {})
        if _oauth and not isinstance(_oauth, dict):
            raise SchemaError("auth.oauth must be an object")
        if isinstance(_oauth, dict):
            if "enabled" in _oauth and not isinstance(_oauth["enabled"], bool):
                raise SchemaError("auth.oauth.enabled must be bool")
            _provs = _oauth.get("providers", [])
            if not isinstance(_provs, list):
                raise SchemaError("auth.oauth.providers must be a list")
            for _i, _p in enumerate(_provs):
                if not isinstance(_p, dict):
                    raise SchemaError(f"auth.oauth.providers[{_i}] must be an object")
                for _req in ("id", "type", "name", "issuer", "client_id"):
                    if not _p.get(_req):
                        raise SchemaError(f"auth.oauth.providers[{_i}].{_req} required")
                if _p["type"] not in ("oidc", "google", "github"):
                    raise SchemaError(f"auth.oauth.providers[{_i}].type must be oidc|google|github")


    ca = cfg.get("ca", {})
    if ca and not isinstance(ca, dict):
        raise SchemaError("ca must be an object")
    if isinstance(ca, dict):
        for _k in ("root_cn", "intermediate_cn", "org", "country"):
            if _k in ca and (not isinstance(ca[_k], str) or not ca[_k]):
                raise SchemaError(f"ca.{_k} must be a non-empty string")
        for _k in ("root_key_bits", "root_lifetime_days", "intermediate_lifetime_days",
                   "default_server_lifetime_days", "default_client_lifetime_days",
                   "default_key_bits", "crl_lifetime_days"):
            if _k in ca:
                try:
                    _n = int(ca[_k])
                except (TypeError, ValueError):
                    raise SchemaError(f"ca.{_k} must be int")
                if _n < 1:
                    raise SchemaError(f"ca.{_k} must be positive")


    _api = cfg.get("api", {})
    if isinstance(_api, dict):
        _tls = _api.get("tls", {})
        if _tls and not isinstance(_tls, dict):
            raise SchemaError("api.tls must be an object")
        if isinstance(_tls, dict):
            if "enabled" in _tls and not isinstance(_tls["enabled"], bool):
                raise SchemaError("api.tls.enabled must be bool")
            if "cert_serial" in _tls and not isinstance(_tls["cert_serial"], str):
                raise SchemaError("api.tls.cert_serial must be string")
            if "listen_port" in _tls:
                try: _p = int(_tls["listen_port"])
                except (TypeError, ValueError):
                    raise SchemaError("api.tls.listen_port must be int")
                if not (1 <= _p <= 65535):
                    raise SchemaError("api.tls.listen_port out of range")


    rep = cfg.get("reporting", {})
    if rep and not isinstance(rep, dict):
        raise SchemaError("reporting must be an object")
    if isinstance(rep, dict):
        if "enabled" in rep and not isinstance(rep["enabled"], bool):
            raise SchemaError("reporting.enabled must be bool")
        if "retention_days" in rep:
            try: _d = int(rep["retention_days"])
            except (TypeError, ValueError):
                raise SchemaError("reporting.retention_days must be int")
            if not (1 <= _d <= 3650):
                raise SchemaError("reporting.retention_days must be 1..3650")
        nf = rep.get("netflow", {})
        if nf and not isinstance(nf, dict):
            raise SchemaError("reporting.netflow must be an object")
        if isinstance(nf, dict):
            if "enabled" in nf and not isinstance(nf["enabled"], bool):
                raise SchemaError("reporting.netflow.enabled must be bool")
            if "port" in nf:
                try: _p = int(nf["port"])
                except (TypeError, ValueError):
                    raise SchemaError("reporting.netflow.port must be int")
                if not (1 <= _p <= 65535):
                    raise SchemaError("reporting.netflow.port out of range")
            if "protocol" in nf and nf["protocol"] not in ("v5", "v9", "ipfix"):
                raise SchemaError("reporting.netflow.protocol must be v5|v9|ipfix")


def merge_defaults(cfg: dict[str, Any]) -> dict[str, Any]:
    def _merge(base: dict, over: dict) -> dict:
        out = copy.deepcopy(base)
        for k, v in over.items():
            if k in out and isinstance(out[k], dict) and isinstance(v, dict):
                out[k] = _merge(out[k], v)
            else:
                out[k] = copy.deepcopy(v)
        return out
    return _merge(DEFAULT_CONFIG, cfg)
