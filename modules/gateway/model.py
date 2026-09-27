"""Gateway model.

A gateway has:
  id            - "gw-" + hex
  name          - human name (e.g. "WAN_Primary")
  interface     - role name ("wan", "opt1", ...) or explicit device
  address       - gateway IP (e.g. "192.168.1.1")
  monitor_ips   - list of IPs to ping for liveness
  weight        - for load balancing (1-5)
  enabled       - bool
  description   - free text

A gateway group has:
  id            - "gwg-" + hex
  name          - e.g. "WAN_Group"
  type          - "failover" | "loadbalance"
  members       - [{gateway_id, tier}] (tier for failover, weight for LB)
"""
from __future__ import annotations
import secrets
import re
from dataclasses import dataclass, field, asdict
from typing import Any


VALID_TYPES = {"failover", "loadbalance"}


def new_gw_id() -> str: return "gw-" + secrets.token_hex(4)
def new_gwg_id() -> str: return "gwg-" + secrets.token_hex(4)


class GatewayError(ValueError):
    pass


@dataclass
class Gateway:
    id: str = field(default_factory=new_gw_id)
    name: str = ""
    interface: str = "wan"
    address: str = ""
    monitor_ips: list = field(default_factory=list)
    weight: int = 1
    enabled: bool = True
    description: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Gateway":
        return cls(
            id=d.get("id") or new_gw_id(),
            name=d.get("name", ""),
            interface=d.get("interface", "wan"),
            address=d.get("address", ""),
            monitor_ips=list(d.get("monitor_ips") or []),
            weight=int(d.get("weight", 1)),
            enabled=bool(d.get("enabled", True)),
            description=d.get("description", ""),
        )

    def validate(self) -> None:
        if not self.name or not re.match(r"^[A-Za-z0-9_]+$", self.name):
            raise GatewayError("name must be alphanumeric + underscore")
        if not self.interface:
            raise GatewayError("interface required")
        try:
            import ipaddress
            ipaddress.ip_address(self.address)
        except Exception:
            raise GatewayError(f"invalid address: {self.address}")
        for ip in self.monitor_ips:
            try:
                import ipaddress
                ipaddress.ip_address(ip)
            except Exception:
                raise GatewayError(f"invalid monitor_ip: {ip}")
        if not (1 <= self.weight <= 5):
            raise GatewayError("weight must be 1-5")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class GatewayGroup:
    id: str = field(default_factory=new_gwg_id)
    name: str = ""
    type: str = "failover"
    members: list = field(default_factory=list)
    description: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "GatewayGroup":
        return cls(
            id=d.get("id") or new_gwg_id(),
            name=d.get("name", ""),
            type=d.get("type", "failover"),
            members=list(d.get("members") or []),
            description=d.get("description", ""),
        )

    def validate(self, gateway_ids: set) -> None:
        if not self.name or not re.match(r"^[A-Za-z0-9_]+$", self.name):
            raise GatewayError("name must be alphanumeric + underscore")
        if self.type not in VALID_TYPES:
            raise GatewayError(f"type must be one of {VALID_TYPES}")
        if not self.members:
            raise GatewayError("group must have at least one member")
        for m in self.members:
            if not isinstance(m, dict):
                raise GatewayError("member must be object")
            if m.get("gateway_id") not in gateway_ids:
                raise GatewayError(f"member refers to unknown gateway {m.get('gateway_id')}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
