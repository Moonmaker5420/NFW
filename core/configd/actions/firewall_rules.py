"""Firewall rule + alias configd actions."""
from __future__ import annotations

import logging
import sys
from typing import Any

from configd.registry import action

sys.path.insert(0, "/opt/nfw")
sys.path.insert(0, "/opt/nfw/core")

from config import store as cfg_store  # noqa: E402
from config.schema import validate  # noqa: E402

LOG = logging.getLogger("configd.firewall")


def _get_rules(cfg: dict) -> list[dict]:
    return list(cfg.get("firewall", {}).get("rules", []) or [])


def _set_rules(cfg: dict, rules: list[dict]) -> None:
    cfg.setdefault("firewall", {})["rules"] = rules


def _get_aliases(cfg: dict) -> list[dict]:
    return list(cfg.get("firewall", {}).get("aliases", []) or [])


def _set_aliases(cfg: dict, aliases: list[dict]) -> None:
    cfg.setdefault("firewall", {})["aliases"] = aliases


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------
@action("firewall.rules.list")
def fw_rules_list(_data: dict[str, Any]) -> dict[str, Any]:
    cfg = _effective_config()
    return {"rules": _get_rules(cfg)}


@action("firewall.rules.get")
def fw_rules_get(data: dict[str, Any]) -> dict[str, Any]:
    rid = data.get("id")
    cfg = _effective_config()
    for r in _get_rules(cfg):
        if r.get("id") == rid:
            return {"rule": r}
    raise FileNotFoundError(f"rule {rid} not found")


@action("firewall.rules.add")
def fw_rules_add(data: dict[str, Any]) -> dict[str, Any]:
    from modules.firewall.model import Rule, RuleError
    rule = data.get("rule")
    if not isinstance(rule, dict):
        raise ValueError("missing 'rule'")
    try:
        r = Rule.from_dict(rule)
        r.validate()
    except RuleError as e:
        raise ValueError(str(e))

    cfg = _effective_config()
    rules = _get_rules(cfg)
    if any(x.get("id") == r.id for x in rules):
        raise ValueError(f"rule {r.id} already exists")
    rules.append(r.to_dict())
    # sort by order for display
    rules.sort(key=lambda x: x.get("order", 100))
    _set_rules(cfg, rules)
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"rule": r.to_dict()}


@action("firewall.rules.update")
def fw_rules_update(data: dict[str, Any]) -> dict[str, Any]:
    from modules.firewall.model import Rule, RuleError
    rid = data.get("id")
    rule = data.get("rule")
    if not isinstance(rule, dict):
        raise ValueError("missing 'rule'")
    try:
        r = Rule.from_dict({**rule, "id": rid})
        r.validate()
    except RuleError as e:
        raise ValueError(str(e))

    cfg = _effective_config()
    rules = _get_rules(cfg)
    for i, x in enumerate(rules):
        if x.get("id") == rid:
            rules[i] = r.to_dict()
            break
    else:
        raise FileNotFoundError(f"rule {rid} not found")
    rules.sort(key=lambda x: x.get("order", 100))
    _set_rules(cfg, rules)
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"rule": r.to_dict()}


@action("firewall.rules.delete")
def fw_rules_delete(data: dict[str, Any]) -> dict[str, Any]:
    rid = data.get("id")
    cfg = _effective_config()
    rules = _get_rules(cfg)
    new_rules = [r for r in rules if r.get("id") != rid]
    if len(new_rules) == len(rules):
        raise FileNotFoundError(f"rule {rid} not found")
    _set_rules(cfg, new_rules)
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"deleted": rid}


@action("firewall.rules.reorder")
def fw_rules_reorder(data: dict[str, Any]) -> dict[str, Any]:
    """data = {"ids": ["r-xxxx", "r-yyyy", ...]}"""
    ids = data.get("ids")
    if not isinstance(ids, list) or not ids:
        raise ValueError("missing 'ids' list")
    cfg = _effective_config()
    rules = _get_rules(cfg)
    by_id = {r.get("id"): r for r in rules}
    if set(ids) != set(by_id.keys()):
        raise ValueError("reorder list must include all rule ids")
    new_rules = []
    for i, rid in enumerate(ids):
        r = dict(by_id[rid])
        r["order"] = (i + 1) * 10
        new_rules.append(r)
    _set_rules(cfg, new_rules)
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"rules": new_rules}


@action("firewall.rules.toggle")
def fw_rules_toggle(data: dict[str, Any]) -> dict[str, Any]:
    rid = data.get("id")
    cfg = _effective_config()
    rules = _get_rules(cfg)
    for r in rules:
        if r.get("id") == rid:
            r["enabled"] = not r.get("enabled", True)
            _set_rules(cfg, rules)
            validate(cfg)
            cfg_store.stage(cfg, author=data.get("author") or "unknown")
            return {"rule": r}
    raise FileNotFoundError(f"rule {rid} not found")


# ---------------------------------------------------------------------------
# Aliases
# ---------------------------------------------------------------------------
@action("firewall.aliases.list")
def fw_aliases_list(_data: dict[str, Any]) -> dict[str, Any]:
    cfg = _effective_config()
    return {"aliases": _get_aliases(cfg)}


@action("firewall.aliases.add")
def fw_aliases_add(data: dict[str, Any]) -> dict[str, Any]:
    alias = data.get("alias")
    if not isinstance(alias, dict):
        raise ValueError("missing 'alias'")
    name = alias.get("name")
    if not name or not isinstance(name, str):
        raise ValueError("alias name required")
    cfg = _effective_config()
    aliases = _get_aliases(cfg)
    if any(a.get("name") == name for a in aliases):
        raise ValueError(f"alias {name} exists")
    aliases.append(alias)
    _set_aliases(cfg, aliases)
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"alias": alias}


@action("firewall.aliases.update")
def fw_aliases_update(data: dict[str, Any]) -> dict[str, Any]:
    name = data.get("name")
    alias = data.get("alias")
    if not name or not isinstance(alias, dict):
        raise ValueError("missing name or alias")
    cfg = _effective_config()
    aliases = _get_aliases(cfg)
    for i, a in enumerate(aliases):
        if a.get("name") == name:
            alias["name"] = name
            aliases[i] = alias
            break
    else:
        raise FileNotFoundError(f"alias {name} not found")
    _set_aliases(cfg, aliases)
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"alias": alias}


@action("firewall.aliases.delete")
def fw_aliases_delete(data: dict[str, Any]) -> dict[str, Any]:
    name = data.get("name")
    cfg = _effective_config()
    aliases = _get_aliases(cfg)
    new_aliases = [a for a in aliases if a.get("name") != name]
    if len(new_aliases) == len(aliases):
        raise FileNotFoundError(f"alias {name} not found")
    _set_aliases(cfg, new_aliases)
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"deleted": name}


# ---------------------------------------------------------------------------
# Phase 9.11 — URL / GeoIP alias refresh
# ---------------------------------------------------------------------------
@action("firewall.aliases.refresh")
def fw_aliases_refresh(data: dict[str, Any]) -> dict[str, Any]:
    from modules.firewall import aliases as alias_mod
    cfg = _effective_config()
    name = data.get("name")
    if name:
        target = next((a for a in _get_aliases(cfg) if a.get("name") == name), None)
        if not target:
            raise FileNotFoundError(f"alias {name} not found")
        results = [alias_mod.refresh_one(target, cfg)]
    else:
        results = alias_mod.refresh_all(cfg)
    return {"refreshed": results, "count": len(results)}


@action("firewall.aliases.refresh_due")
def fw_aliases_refresh_due(_data: dict[str, Any]) -> dict[str, Any]:
    from modules.firewall import aliases as alias_mod
    cfg = _effective_config()
    results = alias_mod.refresh_due(cfg)
    return {"refreshed": results, "count": len(results)}


@action("firewall.aliases.status")
def fw_aliases_status(data: dict[str, Any]) -> dict[str, Any]:
    from modules.firewall import aliases as alias_mod
    name = data.get("name")
    if name:
        return {"status": alias_mod.read_meta(name)}
    cfg = _effective_config()
    out: dict[str, dict] = {}
    for a in _get_aliases(cfg):
        if a.get("type") in ("url", "geoip"):
            out[a["name"]] = alias_mod.read_meta(a["name"])
    return {"status": out}


# ---------------------------------------------------------------------------
# Compile / apply
# ---------------------------------------------------------------------------
def _effective_config() -> dict:
    """Staged config if present, else the active revision.

    Also injects _resolved_interfaces mapping logical roles
    (wan/lan/opt1) to physical devices, so the compiler emits correct
    interface names in the nftables ruleset.
    """
    staged = cfg_store.get_staging()
    cfg = staged if staged is not None else cfg_store.read()
    try:
        import sys
        if "/opt/nfw" not in sys.path:
            sys.path.insert(0, "/opt/nfw")
        from modules.network.interfaces import resolve_roles
        cfg = dict(cfg)
        cfg["_resolved_interfaces"] = resolve_roles(cfg.get("network", {}))
    except Exception as e:
        import logging
        logging.getLogger("configd.firewall").warning(
            "could not resolve interfaces: %s", e
        )
    return cfg


@action("firewall.preview")
def fw_preview(_data: dict[str, Any]) -> dict[str, Any]:
    from modules.firewall.compiler import compile_ruleset, validate_ruleset
    cfg = _effective_config()
    text = compile_ruleset(cfg)
    ok, err = validate_ruleset(text)
    staged = cfg_store.get_staging()
    return {
        "ruleset": text,
        "valid": ok,
        "error": err,
        "source": "staging" if staged is not None else "active",
    }


def _alert_apply_failed(err: str, rev: str = "") -> None:
    """Fire-and-forget alert on firewall apply failure.

    Best-effort — must never raise into the caller.
    """
    try:
        import sys as _sys
        _sys.path.insert(0, "/opt/nfw")
        _sys.path.insert(0, "/opt/nfw/core")
        from config import store as _st
        from modules.alerts import dispatcher as _d
        cfg = _st.read()
        _d.notify(cfg, "firewall_apply_failed",
                  context={"revision": rev} if rev else {},
                  subject="Firewall apply failed",
                  body=(f"The firewall ruleset failed to apply.\n\n"
                        f"Revision: {rev or '(unknown)'}\n"
                        f"Error: {err[:500]}\n\n"
                        f"Check the firewall preview and validator output."))
    except Exception:
        pass


def _alert_on_failure(fn):
    """Decorator: fire firewall_apply_failed alert on any exception."""
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            try:
                _alert_apply_failed(str(e))
            except Exception:
                pass
            raise
    wrapper.__name__ = fn.__name__
    return wrapper


@action("firewall.apply_staged")
@_alert_on_failure
def fw_apply_staged(data: dict[str, Any]) -> dict[str, Any]:
    """
    Compile the CURRENT config (including any staging), validate, and
    write it to /etc/nftables.conf + reload nft.
    """
    from modules.firewall.compiler import compile_ruleset, validate_ruleset
    cfg = _effective_config()

    try:
        text = compile_ruleset(cfg)
    except Exception as e:
        raise ValueError(f"compile failed: {e}")

    ok, err = validate_ruleset(text)
    if not ok:
        raise ValueError(f"nft validation failed: {err}")

    import os, shutil, subprocess, time
    path = "/etc/nftables.conf"
    backup_dir = "/etc/nfw/backups"
    os.makedirs(backup_dir, exist_ok=True)

    # Keep a rolling set of backups (max 20)
    if os.path.exists(path):
        ts = int(time.time())
        shutil.copy2(path, os.path.join(backup_dir, f"nftables.conf.{ts}"))
        # prune old backups
        files = sorted(
            (f for f in os.listdir(backup_dir) if f.startswith("nftables.conf.")),
            key=lambda x: os.path.getmtime(os.path.join(backup_dir, x)),
        )
        for old in files[:-20]:
            try:
                os.unlink(os.path.join(backup_dir, old))
            except OSError:
                pass

    with open(path, "w") as f:
        f.write(text)

    p = subprocess.run(["/usr/sbin/nft", "-f", path],
                       capture_output=True, text=True, timeout=15)
    if p.returncode != 0:
        raise RuntimeError(f"nft apply failed: {p.stderr}")

    # Persist the exact staged configuration that was successfully applied.
    # Commit only after nft has accepted the generated ruleset so the active
    # revision matches the live firewall state.
    try:
        info = cfg_store.commit(
            author=data.get("author") or "unknown",
            message="firewall apply",
        )
    except Exception as e:
        raise RuntimeError(
            f"firewall applied but configuration commit failed: {e}"
        ) from e

    return {
        "applied": True,
        "bytes": len(text),
        "revision": info.revision,
    }

# =========================================================================
# Per-rule counters (Phase 10e)
# =========================================================================
import sys as _sys
_sys.path.insert(0, "/opt/nfw")
from modules.firewall.counters import (  # noqa: E402
    read_counters as _read_counters,
    reset_counters as _reset_counters,
)


@action("firewall.rules.stats")
def fw_rules_stats(_data: dict[str, Any]) -> dict[str, Any]:
    """Return {rule_id: {bytes, packets, handle}} for every NFW-managed
    rule currently loaded in the kernel. Rules without counters (e.g.
    auto rules that don't pass through `_rule_to_nft`) are omitted."""
    counters = _read_counters()
    total_bytes = sum(v.get("bytes", 0) for v in counters.values())
    total_packets = sum(v.get("packets", 0) for v in counters.values())
    return {
        "stats": counters,
        "count": len(counters),
        "total_bytes": total_bytes,
        "total_packets": total_packets,
    }


@action("firewall.rules.reset_counters")
def fw_rules_reset_counters(data: dict[str, Any]) -> dict[str, Any]:
    """Reset counters for a single rule (data={'rule_id': '1001'}) or
    for every NFW rule (data={} or data={'rule_id': None})."""
    rule_id = data.get("rule_id")
    if rule_id == "" or rule_id == "all":
        rule_id = None
    return _reset_counters(rule_id)
