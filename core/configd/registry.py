"""
Action registry.
"""
from __future__ import annotations

from typing import Any, Callable

ActionFn = Callable[[dict[str, Any]], Any]

_REGISTRY: dict[str, ActionFn] = {}


class DuplicateAction(Exception):
    pass


class UnknownAction(Exception):
    pass


def action(name: str) -> Callable[[ActionFn], ActionFn]:
    def deco(fn: ActionFn) -> ActionFn:
        if name in _REGISTRY:
            raise DuplicateAction(name)
        _REGISTRY[name] = fn
        return fn
    return deco


def get(name: str) -> ActionFn:
    if name not in _REGISTRY:
        raise UnknownAction(name)
    return _REGISTRY[name]


def names() -> list[str]:
    return sorted(_REGISTRY.keys())
