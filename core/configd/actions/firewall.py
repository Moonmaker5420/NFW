"""Firewall actions — wrap nft."""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from configd.registry import action

NFT = "/usr/sbin/nft"
NFT_CONF = Path("/etc/nftables.conf")


def _run(cmd: list[str], timeout: int = 15) -> dict[str, Any]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return {"rc": 124, "stdout": "", "stderr": f"timeout after {timeout}s"}
    except FileNotFoundError as e:
        return {"rc": 127, "stdout": "", "stderr": str(e)}
    return {"rc": p.returncode, "stdout": p.stdout, "stderr": p.stderr}


@action("firewall.reload")
def firewall_reload(_data: dict[str, Any]) -> dict[str, Any]:
    if not NFT_CONF.exists():
        return {"rc": 1, "stdout": "", "stderr": f"{NFT_CONF} not found"}
    r = _run([NFT, "-f", str(NFT_CONF)])
    return {"ok": r["rc"] == 0, **r}


@action("firewall.status")
def firewall_status(_data: dict[str, Any]) -> dict[str, Any]:
    r = _run([NFT, "list", "ruleset"])
    return {"ok": r["rc"] == 0, "ruleset": r["stdout"], "stderr": r["stderr"]}


@action("firewall.tables")
def firewall_tables(_data: dict[str, Any]) -> dict[str, Any]:
    r = _run([NFT, "-j", "list", "tables"])
    return {"ok": r["rc"] == 0, "json": r["stdout"], "stderr": r["stderr"]}


@action("firewall.counters")
def firewall_counters(_data: dict[str, Any]) -> dict[str, Any]:
    r = _run([NFT, "-j", "list", "ruleset"])
    return {"ok": r["rc"] == 0, "json": r["stdout"], "stderr": r["stderr"]}


@action("firewall.validate")
def firewall_validate(data: dict[str, Any]) -> dict[str, Any]:
    ruleset = data.get("ruleset")
    if not isinstance(ruleset, str) or not ruleset.strip():
        return {"ok": False, "stderr": "missing 'ruleset' string"}
    import tempfile, os
    fd, path = tempfile.mkstemp(prefix="nfw-validate-", suffix=".nft")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(ruleset)
        r = _run([NFT, "-c", "-f", path])
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    return {"ok": r["rc"] == 0, "stdout": r["stdout"], "stderr": r["stderr"]}
