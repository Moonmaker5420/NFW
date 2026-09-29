"""DNS blocklist manager: download, parse, dedupe, emit unbound include.

The main unbound config (see modules/services/dns.py) includes
/var/lib/nfw/dns/blocklist.conf when blocklists are enabled. This module
regenerates that file from (manual ∪ downloaded) − whitelist.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Any

LOG = logging.getLogger("nfw.dnsblock")

DNS_DIR = Path("/var/lib/nfw/dns")
SOURCES_DIR = DNS_DIR / "sources"
STATE_FILE = DNS_DIR / "state.json"
# Include file lives in unbound's config dir so the unbound user
# can read it without granting group access to /var/lib/nfw/dns.
INCLUDE_FILE = Path("/etc/unbound/nfw-blocklist.conf")

_RE_ADBLOCK = re.compile(r"^\|\|([\w.-]+)\^?(?:\$.*)?$")
_RE_HOSTS = re.compile(r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1|::1?|::0)\s+(\S+)")
_RE_PLAIN = re.compile(r"^([a-z0-9](?:[a-z0-9\-_]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-_]*[a-z0-9])?)+)\s*$", re.I)

_LOCAL_NAMES = {
    "localhost", "localhost.localdomain", "local", "broadcasthost",
    "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
    "ip6-allnodes", "ip6-allrouters", "ip6-allhosts",
}

# Some public hosts lists (StevenBlack et al.) contain malformed entries
# where a sink IP is glued to the domain with a dot instead of whitespace:
#   "0.0.0.0.creative.hpyrdr.com"  instead of  "0.0.0.0 creative.hpyrdr.com"
# Strip those prefixes so the underlying domain ends up in the blocklist.
_SINK_PREFIXES = ("0.0.0.0.", "127.0.0.1.", "::1.", "::0.", "::.")
_RE_IPV4_ONLY = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _normalize(domain: str) -> str | None:
    domain = domain.strip().rstrip(".").lower()
    # Peel sink-IP prefixes (repeatable — some lists double-prefix)
    changed = True
    while changed:
        changed = False
        for pref in _SINK_PREFIXES:
            if domain.startswith(pref):
                domain = domain[len(pref):]
                changed = True
                break
    if not domain or domain in _LOCAL_NAMES:
        return None
    if _RE_IPV4_ONLY.match(domain):
        return None
    return domain


CATALOG: list[dict[str, Any]] = [
    {"id": "stevenblack", "name": "StevenBlack Unified",
     "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
     "description": "Canonical ad + tracker base hosts list."},
    {"id": "adguard-dns", "name": "AdGuard DNS filter",
     "url": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
     "description": "AdGuard general-purpose ad + tracker filter."},
    {"id": "oisd-basic", "name": "OISD Basic",
     "url": "https://small.oisd.nl/",
     "description": "Curated ads + trackers + phishing. Low false-positive."},
    {"id": "hagezi-normal", "name": "Hagezi Multi-Normal",
     "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/multi.txt",
     "description": "Balanced ad + tracker + telemetry."},
    {"id": "firebog-tick", "name": "Firebog — ticked",
     "url": "https://v.firebog.net/hosts/AdguardDNS.txt",
     "description": "Firebog's low-false-positive list."},
]


def _ensure_dirs() -> None:
    DNS_DIR.mkdir(parents=True, exist_ok=True)
    SOURCES_DIR.mkdir(parents=True, exist_ok=True)


def parse_line(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("!"):
        return None
    m = _RE_ADBLOCK.match(line)
    if m:
        return _normalize(m.group(1))
    m = _RE_HOSTS.match(line)
    if m:
        return _normalize(m.group(1))
    m = _RE_PLAIN.match(line)
    if m:
        return _normalize(m.group(1))
    return None


def download_source(url: str, timeout: int = 60) -> tuple[list[str], str | None]:
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "NFW-dnsblock/0.1",
            "Accept": "text/plain, */*",
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        return [], f"{type(e).__name__}: {e}"
    seen: set[str] = set()
    out: list[str] = []
    for line in raw.splitlines():
        d = parse_line(line)
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    return out, None


def _read_domain_file(p: Path) -> list[str]:
    if not p.exists():
        return []
    out = []
    try:
        for line in p.read_text().splitlines():
            d = parse_line(line)
            if d:
                out.append(d)
    except OSError:
        pass
    return out


def _write_domain_file(p: Path, domains: list[str]) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text("\n".join(sorted(set(domains))) + "\n")
    os.replace(tmp, p)


def _load_state() -> dict:
    if not STATE_FILE.exists():
        return {"sources": {}, "last_refresh": None, "total": 0}
    try:
        return json.loads(STATE_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        return {"sources": {}, "last_refresh": None, "total": 0}


def _save_state(state: dict) -> None:
    _ensure_dirs()
    tmp = STATE_FILE.with_name(STATE_FILE.name + ".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True))
    os.replace(tmp, STATE_FILE)


def _whitelist_matches(domain: str, whitelist: set[str]) -> bool:
    parts = domain.split(".")
    for i in range(len(parts)):
        if ".".join(parts[i:]) in whitelist:
            return True
    return False


def _write_include(domains: set[str], mode: str) -> None:
    zone = "always_refused" if mode == "refused" else "always_nxdomain"
    _ensure_dirs()
    tmp = INCLUDE_FILE.with_name(INCLUDE_FILE.name + ".tmp")
    with open(tmp, "w") as f:
        f.write("# NFW — GENERATED DNS blocklist. Do not edit by hand.\n")
        f.write("# Regenerated by nfw-dnsblock-refresh.\n\n")
        for d in sorted(domains):
            f.write(f'    local-zone: "{d}." {zone}\n')
    os.chmod(tmp, 0o644)
    os.replace(tmp, INCLUDE_FILE)


def _reload_unbound() -> None:
    try:
        r = subprocess.run(["systemctl", "reload", "unbound"],
                           capture_output=True, text=True, timeout=15)
        if r.returncode != 0:
            subprocess.run(["systemctl", "restart", "unbound"],
                           capture_output=True, text=True, timeout=20)
    except Exception as e:
        LOG.warning("unbound reload failed: %s", e)


def refresh(cfg: dict) -> dict:
    svc = cfg.get("services", {}).get("dns_config", {}) or {}
    bl = svc.get("blocklists", {}) or {}
    state = _load_state()
    state.setdefault("sources", {})
    state["last_refresh"] = time.time()

    if not bl.get("enabled"):
        _write_include(set(), "nxdomain")
        _reload_unbound()
        state["total"] = 0
        state["enabled"] = False
        _save_state(state)
        return state

    mode = bl.get("mode", "nxdomain")
    manual = {d.strip().rstrip(".").lower()
              for d in (bl.get("manual") or []) + (bl.get("domains") or []) if d}
    whitelist = {d.strip().rstrip(".").lower()
                 for d in (bl.get("whitelist") or []) if d}

    downloaded: set[str] = set()
    for src in bl.get("sources") or []:
        if not src.get("enabled", True):
            continue
        url = src.get("url")
        if not url:
            continue
        sid = src.get("id") or hashlib.sha256(url.encode()).hexdigest()[:12]
        domains, err = download_source(url)
        entry = state["sources"].setdefault(sid, {})
        entry["url"] = url
        entry["name"] = src.get("name", sid)
        entry["last_attempt"] = time.time()
        if err:
            entry["last_error"] = err
            LOG.error("blocklist source %s failed: %s", sid, err)
            downloaded.update(_read_domain_file(SOURCES_DIR / f"{sid}.txt"))
            continue
        _write_domain_file(SOURCES_DIR / f"{sid}.txt", domains)
        entry["last_success"] = time.time()
        entry["last_error"] = None
        entry["count"] = len(domains)
        downloaded.update(domains)

    merged = manual | downloaded
    filtered = {d for d in merged if not _whitelist_matches(d, whitelist)}

    _write_include(filtered, mode)
    _reload_unbound()

    state["total"] = len(filtered)
    state["downloaded"] = len(downloaded)
    state["manual"] = len(manual)
    state["whitelisted_excluded"] = len(merged) - len(filtered)
    _save_state(state)
    return state
