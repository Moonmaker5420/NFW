"""Firewall rule model + validation.

Rules are stored logically (not as nft syntax) so the GUI can edit them.
The compiler turns them into an nftables ruleset.

Rule fields:
  id            - "r-" + 8 hex chars, immutable
  order         - integer, lower = higher priority
  enabled       - bool
  action        - "pass" | "block" | "reject"
  interface     - "wan" | "lan" | "opt1" ... (matches config.network.*)
  direction     - "in" | "out"
  proto         - "any" | "tcp" | "udp" | "icmp" | "icmpv6"
  source        - "any" | "lan_net" | "192.168.1.5" | "@alias_name"
  dest          - same
  dport         - "" | "80" | "80,443" | "1000-2000" | "@port_alias"
  log           - bool
  description   - free text
"""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field, asdict
from typing import Any

VALID_ACTIONS = {"pass", "block", "reject"}
VALID_DIRECTIONS = {"in", "out"}
VALID_PROTOS = {"any", "tcp", "udp", "icmp", "icmpv6"}


class RuleError(ValueError):
    pass


def new_id() -> str:
    return "r-" + secrets.token_hex(4)


def _is_alias_ref(s: str) -> bool:
    return s.startswith("@")


def _is_port_spec(s: str) -> bool:
    """Accepts: '', '80', '80,443', '1000-2000', '@alias', combinations."""
    if not s:
        return True
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if _is_alias_ref(part):
            continue
        if re.fullmatch(r"\d+(?:-\d+)?", part):
            continue
        return False
    return True


@dataclass
class Rule:
    id: str = field(default_factory=new_id)
    order: int = 100
    enabled: bool = True
    action: str = "pass"
    interface: str = "lan"
    direction: str = "in"
    proto: str = "any"
    source: str = "any"
    dest: str = "any"
    dport: str = ""
    log: bool = False
    description: str = ""
    # --- Phase 9.7a: advanced rule fields ---
    schedule: str = ""
    icmp_type: str = ""
    tcpflags1: str = ""
    tcpflags2: str = ""
    statetype: str = ""
    tag: str = ""
    tagged: str = ""
    dscp: str = ""
    log_limit: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Rule":
        return cls(
            id=d.get("id") or new_id(),
            order=int(d.get("order", 100)),
            enabled=bool(d.get("enabled", True)),
            action=d.get("action", "pass"),
            interface=d.get("interface", "lan"),
            direction=d.get("direction", "in"),
            proto=d.get("proto", "any"),
            source=d.get("source", "any"),
            dest=d.get("dest", "any"),
            dport=d.get("dport", ""),
            log=bool(d.get("log", False)),
            description=d.get("description", ""),
            schedule=d.get("schedule", ""),
            icmp_type=d.get("icmp_type", ""),
            tcpflags1=d.get("tcpflags1", ""),
            tcpflags2=d.get("tcpflags2", ""),
            statetype=d.get("statetype", ""),
            tag=d.get("tag", ""),
            tagged=d.get("tagged", ""),
            dscp=d.get("dscp", ""),
            log_limit=d.get("log_limit", "")
        )

    def validate(self) -> None:
        if self.action not in VALID_ACTIONS:
            raise RuleError(f"invalid action: {self.action}")
        if self.direction not in VALID_DIRECTIONS:
            raise RuleError(f"invalid direction: {self.direction}")
        if self.proto not in VALID_PROTOS:
            raise RuleError(f"invalid proto: {self.proto}")
        if not self.interface:
            raise RuleError("interface required")
        if self.dport and self.proto not in ("tcp", "udp"):
            raise RuleError(f"dport only valid for tcp/udp (proto={self.proto})")
        if not _is_port_spec(self.dport):
            raise RuleError(f"invalid dport spec: {self.dport}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def validate_rule_dict(d: dict[str, Any]) -> Rule:
    r = Rule.from_dict(d)
    r.validate()
    return r


def validate_rules_list(rules: list[dict[str, Any]]) -> list[Rule]:
    out: list[Rule] = []
    seen = set()
    for d in rules:
        r = validate_rule_dict(d)
        if r.id in seen:
            raise RuleError(f"duplicate rule id: {r.id}")
        seen.add(r.id)
        out.append(r)
    return out


# =============================================================================
# Phase 9.7a: Schedules
# =============================================================================
@dataclass
class Schedule:
    """A named set of day/time ranges. Rules reference it by name.

    Example:
        {
            "id": "sch-a1b2c3d4",
            "name": "work-hours",
            "description": "Mon-Fri 09:00-17:00",
            "ranges": [
                {"days": ["mon","tue","wed","thu","fri"],
                 "start": "09:00", "end": "17:00"}
            ],
            "enabled": True,
        }
    """
    id: str = field(default_factory=lambda: "sch-" + __import__("secrets").token_hex(4))
    name: str = ""
    description: str = ""
    ranges: list = field(default_factory=list)
    enabled: bool = True

    @classmethod
    def from_dict(cls, d: dict) -> "Schedule":
        return cls(
            id=d.get("id") or ("sch-" + __import__("secrets").token_hex(4)),
            name=d.get("name", ""),
            description=d.get("description", ""),
            ranges=list(d.get("ranges") or []),
            enabled=bool(d.get("enabled", True)),
        )

    def validate(self) -> None:
        import re as _re
        if not self.name or not _re.match(r"^[A-Za-z0-9_-]+$", self.name):
            raise RuleError("schedule name must be alphanumeric/dash/underscore")
        valid_days = {"mon","tue","wed","thu","fri","sat","sun"}
        for i, r in enumerate(self.ranges):
            if not isinstance(r, dict):
                raise RuleError(f"range[{i}] must be an object")
            days = r.get("days", [])
            for d in days:
                if d not in valid_days:
                    raise RuleError(f"range[{i}] invalid day: {d}")
            for k in ("start", "end"):
                v = r.get(k, "")
                if not _re.match(r"^\d{1,2}:\d{2}$", v):
                    raise RuleError(f"range[{i}].{k} must be HH:MM")

    def to_dict(self) -> dict:
        return asdict(self)

