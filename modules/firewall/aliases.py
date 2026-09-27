"""Alias refresh + cache: URL tables and GeoIP (Phase 9.11)."""
from __future__ import annotations

import gzip
import io
import ipaddress
import json
import logging
import os
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LOG = logging.getLogger("firewall.aliases")

CACHE_DIR = Path("/var/lib/nfw/aliases")
GEOIP_DIR = Path("/var/lib/nfw/geoip")
GEOIP_CSV = GEOIP_DIR / "dbip-country-lite.csv"

FETCH_TIMEOUT  = 30
MAX_BYTES      = 10 * 1024 * 1024
MAX_ENTRIES    = 100_000
USER_AGENT     = "NFW/1.0 (alias-refresh)"

REFRESH_INTERVALS = {
    "hourly":  3600,
    "daily":   86400,
    "weekly":  604800,
    "monthly": 2592000,
    "manual":  0,
}


def ensure_dirs() -> None:
    for d in (CACHE_DIR, GEOIP_DIR):
        d.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(d, 0o755); os.chown(d, 0, 0)
        except OSError:
            pass


def _validate_element(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith("#") or line.startswith(";"):
        return None
    if "#" in line:
        line = line.split("#", 1)[0].strip()
    if not line:
        return None
    if "-" in line:
        a, _, b = line.partition("-")
        try:
            ipaddress.ip_address(a.strip()); ipaddress.ip_address(b.strip())
            return f"{a.strip()}-{b.strip()}"
        except ValueError:
            return None
    try:
        if "/" in line:
            return str(ipaddress.ip_network(line, strict=False))
        return str(ipaddress.ip_address(line))
    except ValueError:
        return None


def parse_url_content(content: str, fmt: str = "both") -> list[str]:
    want_v4 = fmt in ("ipv4", "both")
    want_v6 = fmt in ("ipv6", "both")
    out: list[str] = []; seen: set[str] = set()
    for raw in content.splitlines():
        elem = _validate_element(raw)
        if not elem:
            continue
        is_v6 = ":" in elem
        if is_v6 and not want_v6: continue
        if not is_v6 and not want_v4: continue
        if elem in seen: continue
        seen.add(elem); out.append(elem)
        if len(out) >= MAX_ENTRIES:
            LOG.warning("alias element cap hit (%d)", MAX_ENTRIES); break
    return out


def _fetch(url: str, allow_http: bool = False) -> bytes:
    if not url.startswith("https://") and not (allow_http and url.startswith("http://")):
        raise ValueError(f"only https:// URLs allowed (got {url[:60]})")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as r:
        data = r.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f"response exceeds {MAX_BYTES} bytes")
    return data


def parse_geoip_countries(csv_content: str, countries: list[str],
                         fmt: str = "ipv4") -> list[str]:
    """Parse DB-IP Lite Country CSV. Handles quoted fields.

    DB-IP includes both IPv4 and IPv6 ranges; filter by fmt so that the
    result matches the alias set's declared address family in nftables.
    """
    want_v4 = fmt in ("ipv4", "both")
    want_v6 = fmt in ("ipv6", "both")
    want = {c.upper() for c in countries if c}
    out: list[str] = []
    seen: set[str] = set()
    for line in csv_content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip().strip('"') for p in line.split(",")]
        if len(parts) < 3:
            continue
        start, end, cc = parts[0], parts[1], parts[2].upper()
        if cc not in want: continue
        try:
            a = ipaddress.ip_address(start)
            b = ipaddress.ip_address(end)
        except ValueError:
            continue
        is_v6 = a.version == 6
        if is_v6 and not want_v6: continue
        if (not is_v6) and not want_v4: continue
        elem = f"{start}-{end}"
        if elem in seen: continue
        seen.add(elem)
        out.append(elem)
        if len(out) >= MAX_ENTRIES:
            LOG.warning("geoip element cap hit (%d)", MAX_ENTRIES); break
    return out


def _cache_path(name: str) -> Path:  return CACHE_DIR / f"{name}.txt"
def _meta_path(name: str) -> Path:   return CACHE_DIR / f"{name}.meta.json"


def load_cached(name: str) -> list[str]:
    p = _cache_path(name)
    if not p.exists(): return []
    return [ln.strip() for ln in p.read_text().splitlines() if ln.strip()]


def read_meta(name: str) -> dict:
    p = _meta_path(name)
    if not p.exists(): return {}
    try: return json.loads(p.read_text())
    except Exception: return {}


def _write_meta(name: str, meta: dict) -> None:
    ensure_dirs()
    p = _meta_path(name); tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(meta, indent=2, sort_keys=True))
    os.chmod(tmp, 0o600); os.chown(tmp, 0, 0)
    os.replace(tmp, p)


def _write_cache(name: str, elements: list[str], meta: dict) -> None:
    ensure_dirs()
    p = _cache_path(name); tmp = p.with_suffix(".txt.tmp")
    tmp.write_text("\n".join(elements) + ("\n" if elements else ""))
    os.chmod(tmp, 0o644); os.chown(tmp, 0, 0)
    os.replace(tmp, p)
    _write_meta(name, meta)


def refresh_one(alias: dict, cfg: dict | None = None) -> dict:
    name = alias.get("name")
    if not name: raise ValueError("alias name required")
    t = alias.get("type", "")
    now = time.time()
    base = {"name": name, "type": t, "fetched_at": now,
            "url": alias.get("url", ""), "countries": alias.get("countries", [])}
    try:
        if t == "url":
            url = (alias.get("url") or "").strip()
            if not url: raise ValueError("url required for url alias")
            allow_http = bool((cfg or {}).get("firewall", {}).get("aliases_allow_http", False))
            data = _fetch(url, allow_http=allow_http).decode("utf-8", errors="replace")
            elements = parse_url_content(data, fmt=alias.get("format", "both"))
        elif t == "geoip":
            countries = alias.get("countries") or []
            if not countries: raise ValueError("countries required for geoip alias")
            if not GEOIP_CSV.exists():
                raise FileNotFoundError(
                    f"GeoIP database missing: {GEOIP_CSV} "
                    f"(run /usr/local/sbin/nfw-geoip-update.py)")
            elements = parse_geoip_countries(
                GEOIP_CSV.read_text(), countries,
                fmt=alias.get("format", "ipv4"))
        else:
            raise ValueError(f"unsupported alias type for refresh: {t}")
    except Exception as e:
        LOG.warning("refresh failed %s: %s", name, e)
        prior = read_meta(name)
        meta = dict(base); meta["error"] = str(e)
        meta["count"] = prior.get("count", len(load_cached(name)))
        meta["last_success"] = prior.get("last_success")
        _write_meta(name, meta)
        return meta
    meta = dict(base); meta["count"] = len(elements); meta["last_success"] = now
    _write_cache(name, elements, meta)
    LOG.info("refreshed %s (%s): %d elements", name, t, len(elements))
    return meta


def is_due(alias: dict) -> bool:
    t = alias.get("type", "")
    if t not in ("url", "geoip"): return False
    if not alias.get("enabled", True): return False
    interval = REFRESH_INTERVALS.get(alias.get("refresh", "daily"), 86400)
    if interval == 0: return False
    meta = read_meta(alias.get("name", ""))
    last = meta.get("fetched_at") or meta.get("last_success") or 0
    return (time.time() - last) >= interval


def _iter_aliases(cfg: dict):
    return cfg.get("firewall", {}).get("aliases", []) or []


def refresh_due(cfg: dict) -> list[dict]:
    return [refresh_one(a, cfg) for a in _iter_aliases(cfg) if is_due(a)]


def refresh_all(cfg: dict) -> list[dict]:
    return [refresh_one(a, cfg) for a in _iter_aliases(cfg)
            if a.get("type") in ("url", "geoip")]
