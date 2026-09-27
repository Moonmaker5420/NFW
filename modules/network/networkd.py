"""
systemd-networkd compiler.

Generates /etc/systemd/network/*.network files from the NFW config.
The files are named 10-nfw-<device>.network so they take priority over
any auto-generated config (e.g. from cloud-init).

Handles:
  ipv4: dhcp | static <addr/prefix> [gateway] | none
  ipv6: auto | dhcp6 | static <addr/prefix> | none

Dynamic: works with any device name, any count of NICs.
"""
from __future__ import annotations

import ipaddress
from typing import Any


class CompileError(ValueError):
    pass


def _render_iface(dev: str, ifcfg: dict) -> str:
    ipv4 = ifcfg.get("ipv4") or {"mode": "dhcp"}
    ipv6 = ifcfg.get("ipv6") or {"mode": "auto"}

    v4_mode = ipv4.get("mode", "dhcp")
    v6_mode = ipv6.get("mode", "auto")

    L: list[str] = []
    L.append(f"# NFW — GENERATED for {dev}. Do not edit by hand.")
    L.append("[Match]")
    L.append(f"Name={dev}")
    L.append("")
    L.append("[Network]")

    # --- IPv4 ---------------------------------------------------------
    if v4_mode == "dhcp":
        L.append("DHCP=ipv4")
    elif v4_mode == "static":
        addr = ipv4.get("address", "").strip()
        plen = ipv4.get("prefixlen")
        if not addr or plen is None:
            raise CompileError(f"{dev}: static ipv4 requires address and prefixlen")
        # validate
        try:
            ipaddress.ip_address(addr)
        except ValueError as e:
            raise CompileError(f"{dev}: invalid address {addr}: {e}")
        L.append(f"Address={addr}/{int(plen)}")
        gw = ipv4.get("gateway")
        if gw:
            try:
                ipaddress.ip_address(gw)
            except ValueError as e:
                raise CompileError(f"{dev}: invalid gateway {gw}: {e}")
            L.append(f"Gateway={gw}")
        L.append("DHCP=no")
    elif v4_mode == "none":
        L.append("DHCP=no")
    else:
        raise CompileError(f"{dev}: unknown ipv4 mode {v4_mode}")

    # --- IPv6 ---------------------------------------------------------
    if v6_mode == "auto":
        L.append("IPv6AcceptRA=yes")
    elif v6_mode == "dhcp6":
        L.append("IPv6AcceptRA=yes")
        # dhcp6 handled by DHCP= setting; adjust below
    elif v6_mode == "static":
        addr6 = (ipv6.get("address") or "").strip()
        plen6 = ipv6.get("prefixlen")
        if addr6 and plen6 is not None:
            L.append(f"Address={addr6}/{int(plen6)}")
    # "none" → do nothing

    # --- DHCP line correction ----------------------------------------
    # If both ipv4=dhcp and ipv6=dhcp6, emit DHCP=yes
    if v4_mode == "dhcp" and v6_mode == "dhcp6":
        # Replace the DHPC=ipv4 line with DHCP=yes
        L = [("DHCP=yes" if line == "DHCP=ipv4" else line) for line in L]

    L.append("")
    return "\n".join(L)


def compile_networkd(config: dict) -> dict[str, str]:
    """
    Return {device: file_content} for all explicitly configured
    interfaces. Devices not in config.network.interfaces are not written
    (so they keep whatever the OS did by default — usually DHCP from
    netplan/cloud-init).
    """
    net = config.get("network", {}) or {}
    ifaces = net.get("interfaces") or {}
    out: dict[str, str] = {}
    for dev, ifcfg in ifaces.items():
        if not isinstance(ifcfg, dict):
            continue
        out[dev] = _render_iface(dev, ifcfg)
    return out


def file_path(dev: str) -> str:
    return f"/etc/systemd/network/10-nfw-{dev}.network"
