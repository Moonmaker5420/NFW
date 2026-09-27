"""Dynamic DNS updater — supports common providers via HTTP API."""
from __future__ import annotations
import ipaddress
import os
import socket
import subprocess
import urllib.request
import urllib.parse
from typing import Any

PROVIDERS = {
    "duckdns": "https://www.duckdns.org/update?domains={host}&token={token}&ip={ip}",
    "noip": "https://{user}:{pass}@dynupdate.no-ip.com/nic/update?hostname={host}&myip={ip}",
    "freedns": "https://freedns.afraid.org/dynamic/update.php?{token}",
    "cloudflare": "https://api.cloudflare.com/client/v4/zones/{zone}/dns_records/{record}",
    "custom": "{url}",
}


def get_public_ip() -> str:
    """Query an external service for our public IP."""
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip",
                "https://icanhazip.com"):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NFW/1.0"})
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.read().decode().strip()
        except Exception:
            continue
    return ""


def update(config: dict) -> dict:
    """Run all configured DDNS providers."""
    ddns = config.get("services", {}).get("ddns_config", {}) or {}
    entries = ddns.get("entries", []) or []
    if not entries:
        return {"updated": 0, "entries": []}

    current_ip = get_public_ip()
    if not current_ip:
        return {"error": "could not determine public IP", "entries": []}

    results = []
    for e in entries:
        if not e.get("enabled", True):
            continue
        provider = e.get("provider", "custom")
        url_template = PROVIDERS.get(provider, "")
        if not url_template:
            results.append({"provider": provider, "error": "unknown provider"})
            continue

        try:
            url = url_template.format(
                host=e.get("host", ""),
                token=e.get("token", ""),
                user=e.get("user", ""),
                password=e.get("password", ""),
                ip=current_ip,
                url=e.get("url", ""),
                zone=e.get("zone", ""),
                record=e.get("record", ""),
            )
            req = urllib.request.Request(url, headers={"User-Agent": "NFW/1.0"})
            with urllib.request.urlopen(req, timeout=15) as r:
                body = r.read().decode()[:500]
                results.append({
                    "provider": provider,
                    "host": e.get("host"),
                    "ip": current_ip,
                    "response": body,
                    "ok": True,
                })
        except Exception as ex:
            results.append({
                "provider": provider,
                "host": e.get("host"),
                "error": str(ex)[:300],
                "ok": False,
            })
    return {"public_ip": current_ip, "updated": len(results), "entries": results}
