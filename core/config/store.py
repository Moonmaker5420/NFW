"""
Revisioned config store.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

from .schema import SchemaError, merge_defaults, validate

BASE = Path("/var/lib/nfw/config")
REVISIONS = BASE / "revisions"
ACTIVE = BASE / "active.json"
STAGING = BASE / "staging.json"
STAGING_META = BASE / "staging.meta"


class ConfigError(Exception):
    pass


@dataclass
class RevisionInfo:
    revision: str
    ts: float
    author: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _ensure_dirs() -> None:
    BASE.mkdir(parents=True, exist_ok=True)
    REVISIONS.mkdir(parents=True, exist_ok=True)


def _new_revision_id() -> str:
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    salt = secrets.token_hex(4)
    return f"{ts}-{salt}"


def _atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    finally:
        pass
    os.replace(tmp, path)


def _read_json(path: Path) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _write_json(path: Path, obj: dict[str, Any], mode: int = 0o600) -> None:
    _atomic_write(path, json.dumps(obj, indent=2, sort_keys=True).encode("utf-8"), mode)


def read() -> dict[str, Any]:
    """Return the active config, or defaults if none exists yet.

    Always deep-merges the current DEFAULT_CONFIG so that keys introduced
    by later schema versions (e.g. firewall.rules, firewall.nat) are
    present even when the stored revision predates them.
    """
    _ensure_dirs()
    if not ACTIVE.exists():
        cfg = merge_defaults({})
        rev = _new_revision_id()
        ts = time.time()
        _write_json(REVISIONS / f"{rev}.json", cfg)
        _write_json(REVISIONS / f"{rev}.meta", {
            "revision": rev,
            "ts": ts,
            "author": "installer",
            "message": "initial config",
        })
        _write_json(ACTIVE, {"revision": rev, "ts": ts})
        return cfg
    meta = _read_json(ACTIVE)
    rev = meta["revision"]
    stored = _read_json(REVISIONS / f"{rev}.json")
    # Merge current defaults under the stored values so new schema keys exist
    return merge_defaults(stored)


def _active_revision() -> str | None:
    if not ACTIVE.exists():
        return None
    return _read_json(ACTIVE)["revision"]


def stage(cfg: dict[str, Any], author: str) -> str:
    _ensure_dirs()

    # Normalize older configurations with the current schema defaults
    # before validation/staging. This allows newly introduced keys
    # (for example firewall.nat.npt) to be inherited automatically.
    cfg = merge_defaults(cfg)

    try:
        validate(cfg)
    except SchemaError as e:
        raise ConfigError(f"validation failed: {e}") from e

    base_rev = _active_revision()
    _write_json(STAGING, cfg)
    _write_json(STAGING_META, {
        "author": author,
        "base_revision": base_rev,
        "staged_at": time.time(),
    })
    blob = json.dumps(cfg, sort_keys=True).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]


def get_staging() -> dict[str, Any] | None:
    if not STAGING.exists():
        return None
    return _read_json(STAGING)


def get_staging_meta() -> dict[str, Any] | None:
    if not STAGING_META.exists():
        return None
    return _read_json(STAGING_META)


def discard_staging() -> bool:
    removed = False
    for p in (STAGING, STAGING_META):
        try:
            p.unlink()
            removed = True
        except FileNotFoundError:
            pass
    return removed


def commit(author: str, message: str = "") -> RevisionInfo:
    _ensure_dirs()
    staged = get_staging()
    if staged is None:
        staged = read()
    try:
        validate(staged)
    except SchemaError as e:
        raise ConfigError(f"validation failed: {e}") from e

    rev = _new_revision_id()
    ts = time.time()
    _write_json(REVISIONS / f"{rev}.json", staged)
    _write_json(REVISIONS / f"{rev}.meta", {
        "revision": rev,
        "ts": ts,
        "author": author,
        "message": message,
    })
    _write_json(ACTIVE, {"revision": rev, "ts": ts})
    discard_staging()
    return RevisionInfo(revision=rev, ts=ts, author=author, message=message)


def rollback(revision: str, author: str, reason: str = "") -> RevisionInfo:
    _ensure_dirs()
    rev_file = REVISIONS / f"{revision}.json"
    if not rev_file.exists():
        raise ConfigError(f"revision '{revision}' not found")

    cfg = _read_json(rev_file)
    try:
        validate(cfg)
    except SchemaError as e:
        raise ConfigError(f"revision invalid: {e}") from e

    new_rev = _new_revision_id()
    ts = time.time()
    _write_json(REVISIONS / f"{new_rev}.json", cfg)
    _write_json(REVISIONS / f"{new_rev}.meta", {
        "revision": new_rev,
        "ts": ts,
        "author": author,
        "message": f"rollback to {revision}: {reason}".strip(": "),
    })
    _write_json(ACTIVE, {"revision": new_rev, "ts": ts})
    discard_staging()
    return RevisionInfo(revision=new_rev, ts=ts, author=author,
                        message=f"rollback to {revision}")


def revisions(limit: int = 100) -> list[RevisionInfo]:
    _ensure_dirs()
    out: list[RevisionInfo] = []
    for meta in sorted(REVISIONS.glob("*.meta"), reverse=True):
        try:
            m = _read_json(meta)
            out.append(RevisionInfo(**m))
        except (OSError, KeyError, json.JSONDecodeError):
            continue
        if len(out) >= limit:
            break
    return out


def active_revision() -> RevisionInfo | None:
    rev = _active_revision()
    if rev is None:
        return None
    meta_file = REVISIONS / f"{rev}.meta"
    if not meta_file.exists():
        return None
    return RevisionInfo(**_read_json(meta_file))
