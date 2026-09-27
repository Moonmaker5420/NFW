"""ISC DHCP compiler: config → /etc/dhcp/dhcpd.conf."""
from __future__ import annotations
import ipaddress
from typing import Any


class CompileError(ValueError):
    pass


def _iface(config: dict, key: str) -> str:
    resolved = config.get("_resolved_interfaces") or {}
    if key in resolved:
        return resolved[key]
    net = config.get("network", {})
    return net.get(key, key)


def _cp_listen_ip(config: dict, fallback: str = "") -> str:
    """Return the IP where the captive portal actually listens.

    Prefers the CP config's listen_ip (if set), then the LAN interface's
    configured IPv4 address. Falls back to `fallback` (usually the subnet
    gateway) if neither is available.
    """
    cp = config.get("services", {}).get("captiveportal_config", {}) or {}
    explicit = (cp.get("listen_ip") or "").strip()
    if explicit:
        return explicit

    net = config.get("network", {}) or {}
    lan_iface = net.get("lan") or ""
    for name, icfg in (net.get("interfaces", {}) or {}).items():
        if name == lan_iface:
            addr = (icfg.get("ipv4", {}) or {}).get("address", "")
            if addr:
                return addr
            break
    return fallback


def compile_dhcpd(config: dict) -> str:
    svc = config.get("services", {}).get("dhcp_config", {}) or {}
    subnets = svc.get("subnets", []) or []
    reservations = svc.get("static_reservations", []) or []

    L: list[str] = []
    L.append("# NFW — GENERATED dhcpd.conf. Do not edit by hand.")
    L.append("")
    L.append(f'default-lease-time {int(svc.get("default_lease_time", 3600))};')
    L.append(f'max-lease-time {int(svc.get("max_lease_time", 86400))};')
    L.append(f'authoritative;')
    L.append("")
    L.append("ddns-update-style none;")

    # --- RFC 8910: captive portal URL via DHCP option 114 ---
    cp = config.get("services", {}).get("captiveportal_config", {}) or {}
    cp_on = bool(cp.get("enabled", False))
    emit_114 = cp_on and bool(cp.get("dhcp_option_114", True))
    if emit_114:
        L.append("option captive-portal-url code 114 = text;")
    L.append("")
    L.append("option domain-name-servers " +
             ", ".join(config.get("network", {}).get("dns_servers", []) or []) +
             ";" if False else "")
    L.append("")

    for sn in subnets:
        net = sn.get("network")           # e.g. "192.168.10.0/24"
        if not net:
            continue
        try:
            network = ipaddress.ip_network(net, strict=False)
        except ValueError as e:
            raise CompileError(f"invalid subnet {net}: {e}")

        gateway = sn.get("gateway") or str(network.network_address + 1)
        dns = sn.get("dns") or []
        domain = sn.get("domain") or config.get("system", {}).get("domain", "lan")
        lease_default = int(sn.get("default_lease_time", svc.get("default_lease_time", 3600)))
        lease_max = int(sn.get("max_lease_time", svc.get("max_lease_time", 86400)))

        L.append(f"subnet {network.network_address} netmask {network.netmask} {{")
        if sn.get("range_start") and sn.get("range_end"):
            L.append(f"  range {sn['range_start']} {sn['range_end']};")
        L.append(f"  option routers {gateway};")
        if dns:
            L.append(f"  option domain-name-servers {', '.join(dns)};")
        L.append(f'  option domain-name "{domain}";')
        L.append(f"  default-lease-time {lease_default};")
        L.append(f"  max-lease-time {lease_max};")

        if emit_114:
            # RFC 8910: point clients at the portal URL.
            # Use the portal's actual listen IP, not this subnet's gateway —
            # multi-subnet setups may have a different local gateway.
            # Fall back to the subnet gateway when the LAN address is unset.
            portal_port = int(cp.get("portal_port", 8081))
            portal_ip = _cp_listen_ip(config, fallback=gateway)
            url = f"http://{portal_ip}:{portal_port}/"
            L.append(f'  option captive-portal-url "{url}";')

        # Inline reservations for this subnet
        for r in reservations:
            ip = r.get("ip")
            mac = r.get("mac")
            if not ip or not mac:
                continue
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if addr not in network:
                continue
            hostname = r.get("hostname") or ""
            L.append(f"  host {hostname or mac.replace(':', '_')} {{")
            L.append(f"    hardware ethernet {mac};")
            L.append(f"    fixed-address {ip};")
            L.append(f"  }}")
        L.append("}")
        L.append("")

    return "\n".join(L)


def dhcp_service_unit_interface(config: dict) -> str:
    """Return the interface name dhcpd should listen on (from services.dhcp_config.interface)."""
    svc = config.get("services", {}).get("dhcp_config", {}) or {}
    role = svc.get("interface", "lan")
    return _iface(config, role)
