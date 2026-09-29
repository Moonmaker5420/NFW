"""ACME client wrapper — uses certbot for cert issuance/renewal."""
from __future__ import annotations
import os
import subprocess
from typing import Any

LE_LIVE = "/etc/letsencrypt/live"
LE_RENEWAL = "/etc/letsencrypt/renewal"


CERTBOT = "/usr/bin/certbot"


def _run(cmd: list[str], timeout: int = 180) -> dict:
    if cmd and cmd[0] == CERTBOT and not os.path.exists(CERTBOT):
        return {"rc": 127, "out": "",
                "err": "certbot not installed. Run: apt install certbot"}
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"rc": r.returncode, "out": r.stdout, "err": r.stderr}
    except subprocess.TimeoutExpired:
        return {"rc": 124, "out": "", "err": "timeout"}
    except FileNotFoundError as e:
        return {"rc": 127, "out": "", "err": str(e)}


def list_certs() -> dict:
    """List all certs managed by certbot."""
    r = _run(["/usr/bin/certbot", "certificates"])
    certs = []
    if os.path.isdir(LE_LIVE):
        for name in sorted(os.listdir(LE_LIVE)):
            fullchain = f"{LE_LIVE}/{name}/fullchain.pem"
            privkey = f"{LE_LIVE}/{name}/privkey.pem"
            cert = f"{LE_LIVE}/{name}/cert.pem"
            if os.path.exists(fullchain):
                # Get expiry
                exp = _run(["/usr/bin/openssl", "x509", "-enddate",
                           "-noout", "-in", cert], timeout=10)
                expiry = exp["out"].strip().replace("notAfter=", "") if exp["rc"] == 0 else "unknown"
                certs.append({
                    "name": name,
                    "fullchain": fullchain,
                    "privkey": privkey,
                    "cert": cert,
                    "expires": expiry,
                })
    return {"certs": certs, "certbot_raw": r["out"][:1000]}


def issue(domain: str, email: str, webroot: str = "/var/www/html",
          dns_plugin: str = "", dns_credentials: str = "",
          staging: bool = False) -> dict:
    """Issue a new certificate."""
    if not domain or not email:
        raise ValueError("domain and email required")

    cmd = [
        "/usr/bin/certbot", "certonly", "--non-interactive",
        "--agree-tos", "--email", email,
        "-d", domain,
    ]
    if dns_plugin:
        cmd += ["--dns-" + dns_plugin, "--dns-" + dns_plugin + "-credentials",
                dns_credentials]
    else:
        cmd += ["--webroot", "-w", webroot]
    if staging:
        cmd.append("--staging")

    r = _run(cmd, timeout=300)
    return {
        "issued": r["rc"] == 0,
        "domain": domain,
        "output": r["out"][-1500:],
        "error": r["err"][-500:] if r["rc"] != 0 else "",
    }


def renew_all(dry_run: bool = False) -> dict:
    """Renew all certs."""
    cmd = ["/usr/bin/certbot", "renew", "--non-interactive"]
    if dry_run:
        cmd.append("--dry-run")
    r = _run(cmd, timeout=600)
    return {
        "renewed": r["rc"] == 0,
        "output": r["out"][-2000:],
        "error": r["err"][-500:] if r["rc"] != 0 else "",
    }


def revoke(domain: str) -> dict:
    """Revoke a certificate."""
    if not domain:
        raise ValueError("domain required")
    cert = f"{LE_LIVE}/{domain}/cert.pem"
    if not os.path.exists(cert):
        raise FileNotFoundError(f"no cert for {domain}")
    r = _run(["/usr/bin/certbot", "revoke", "--cert-path", cert,
             "--non-interactive"], timeout=60)
    return {"revoked": r["rc"] == 0, "output": r["out"][-500:]}
