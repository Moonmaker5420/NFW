"""Per-rule byte / packet counters.

Parses `nft -j list table inet nfw_filter` and maps each user rule's
`comment "NFW-RULE-<id>"` to its live counter. Also supports resetting
counters for a specific rule (or all).

Rule IDs come in two flavors:
  - numeric strings from user rules (e.g. "1001")
  - descriptive strings from auto-generated rules (e.g. "sys-radius-lan")
Both are handled transparently — the map is keyed by whatever's after
the NFW-RULE- prefix.
"""
from __future__ import annotations

import json
import logging
import subprocess
from typing import Any

LOG = logging.getLogger("firewall.counters")

NFT = "/usr/sbin/nft"
PREFIX = "NFW-RULE-"
TABLE = ("inet", "nfw_filter")


def _run_nft(args: list[str], timeout: int = 10) -> tuple[int, str, str]:
    try:
        p = subprocess.run([NFT] + args, capture_output=True, text=True,
                           timeout=timeout, check=False)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 1, "", "timeout"
    except FileNotFoundError:
        return 1, "", "nft not found"


def read_counters() -> dict[str, dict[str, int]]:
    """Return {rule_id: {"bytes": N, "packets": N, "handle": N}}.

    rule_id is the string after NFW-RULE- in the rule's comment.
    """
    rc, out, err = _run_nft(["-j", "list", "table", *TABLE])
    if rc != 0:
        LOG.warning("nft list table failed: %s", err[:200])
        return {}

    try:
        data = json.loads(out)
    except json.JSONDecodeError as e:
        LOG.warning("nft JSON parse failed: %s", e)
        return {}

    result: dict[str, dict[str, int]] = {}

    for item in data.get("nftables", []):
        rule = item.get("rule")
        if not rule:
            continue
        comment = rule.get("comment", "")
        if not comment.startswith(PREFIX):
            continue
        rule_id = comment[len(PREFIX):]
        handle = rule.get("handle", 0)

        # Walk the expression list and pick out the `counter` entry.
        # Shape: {"counter": {"packets": N, "bytes": N}}
        bytes_ = 0
        packets = 0
        for expr in rule.get("expr", []):
            c = expr.get("counter")
            if isinstance(c, dict):
                bytes_ = int(c.get("bytes", 0))
                packets = int(c.get("packets", 0))
                break

        result[rule_id] = {
            "bytes": bytes_,
            "packets": packets,
            "handle": handle,
        }

    return result


def reset_counters(rule_id: str | None = None) -> dict[str, Any]:
    """Reset counters.

    If rule_id is None, resets every NFW-managed rule in nfw_filter.
    Otherwise resets just that rule. Uses `nft reset` which zeroes
    counters atomically.
    """
    if rule_id is None:
        # nft has no `reset table` — only `reset ruleset`, `reset rules`,
        # `reset set`, `reset element`. Safest portable approach: enumerate
        # every NFW-managed rule and reset each by (chain, handle).
        rc, out, err = _run_nft(["-j", "list", "table", *TABLE])
        if rc != 0:
            return {"ok": False, "error": err[:200]}
        try:
            data = json.loads(out)
        except json.JSONDecodeError as e:
            return {"ok": False, "error": f"json: {e}"}

        reset = 0
        failed: list[str] = []
        for item in data.get("nftables", []):
            rule = item.get("rule")
            if not rule:
                continue
            comment = rule.get("comment", "")
            if not comment.startswith(PREFIX):
                continue
            handle = rule.get("handle")
            chain = rule.get("chain")
            if not handle or not chain:
                continue
            rc, _, err = _run_nft([
                "reset", "rule", *TABLE, chain,
                "handle", str(handle),
            ])
            if rc == 0:
                reset += 1
            else:
                failed.append(f"{comment}: {err.strip()[:80]}")

        return {
            "ok": not failed,
            "scope": "all",
            "reset": reset,
            "failed": failed,
        }

    # Reset a specific rule by walking the list to find its handle.
    rc, out, err = _run_nft(["-j", "list", "table", *TABLE])
    if rc != 0:
        return {"ok": False, "error": err[:200]}
    try:
        data = json.loads(out)
    except json.JSONDecodeError as e:
        return {"ok": False, "error": f"json: {e}"}

    target_comment = f"{PREFIX}{rule_id}"
    for item in data.get("nftables", []):
        rule = item.get("rule")
        if not rule:
            continue
        if rule.get("comment") != target_comment:
            continue
        handle = rule.get("handle")
        chain = rule.get("chain")
        if not handle or not chain:
            continue
        rc, _, err = _run_nft([
            "reset", "rule", *TABLE, chain,
            "handle", str(handle),
        ])
        if rc != 0:
            return {"ok": False, "error": err[:200]}
        return {"ok": True, "scope": "rule", "rule_id": rule_id,
                "handle": handle, "chain": chain}

    return {"ok": False, "error": f"rule {rule_id} not found in nfw_filter"}
