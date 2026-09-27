"""
Post-commit / post-rollback hooks.
"""
from __future__ import annotations

import logging
from typing import Any, Callable

Hook = Callable[[dict[str, Any], dict[str, Any]], None]

_HOOKS: list[tuple[str, Hook]] = []


def register(name: str, fn: Hook) -> None:
    _HOOKS.append((name, fn))


def run_all(old: dict[str, Any], new: dict[str, Any]) -> dict[str, str]:
    results: dict[str, str] = {}
    log = logging.getLogger("config.hooks")
    for name, fn in _HOOKS:
        try:
            fn(old, new)
            results[name] = "ok"
        except Exception as e:
            log.exception("hook %s failed", name)
            results[name] = f"error: {type(e).__name__}: {e}"
    return results


def _log_change(old: dict[str, Any], new: dict[str, Any]) -> None:
    log = logging.getLogger("config.hooks.log")
    keys_old = set(old.keys()) if isinstance(old, dict) else set()
    keys_new = set(new.keys()) if isinstance(new, dict) else set()
    log.info("config change: top-level keys added=%s removed=%s",
             keys_new - keys_old, keys_old - keys_new)


register("log", _log_change)
