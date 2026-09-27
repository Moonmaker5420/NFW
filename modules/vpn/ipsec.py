"""
IPsec module using strongSwan's legacy ipsec.conf format.

Ubuntu 24.04 ships strongswan-starter (ipsec.conf/ipsec.secrets) but not the
swanctl-based charon-systemd service. This format works on Debian 12,
Ubuntu 22.04/24.04 out of the box.

Writes:
  /etc/ipsec.conf     — connection definitions
  /etc/ipsec.secrets  — PSKs

Then restarts strongswan-starter.

NOTE: /etc is read-only inside configd's systemd namespace
      (ProtectSystem=full), so we MUST NOT create sibling .tmp files in
      /etc. We write the target files directly; they are in ReadWritePaths.
"""
from __future__ import annotations
import logging
import os
import subprocess
from typing import Any

LOG = logging.getLogger("vpn.ipsec")

IPSEC_CONF = "/etc/ipsec.conf"
IPSEC_SECRETS = "/etc/ipsec.secrets"
CONF_HEADER = "# NFW — GENERATED ipsec.conf. Manual edits will be overwritten.\n"


class IPsecError(ValueError):
    pass


def _run(cmd: list[str], timeout: int = 20) -> dict:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"rc": r.returncode, "out": r.stdout, "err": r.stderr}
    except subprocess.TimeoutExpired:
        return {"rc": 124, "out": "", "err": "timeout"}
    except FileNotFoundError as e:
        return {"rc": 127, "out": "", "err": str(e)}


def _write(path: str, content: str, mode: int = 0o600) -> None:
    """Direct in-place write. No .tmp siblings — /etc is read-only for the
    parent directory inside configd's sandbox, but the target files exist
    and are in ReadWritePaths."""
    # Ensure parent exists (no-op if present)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    except OSError:
        pass
    # Write the target file directly
    with open(path, "w") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def _render_conf(config: dict) -> str:
    ipsec = config.get("vpn", {}).get("ipsec", {}) or {}
    tunnels = ipsec.get("tunnels", []) or []

    L: list[str] = []
    L.append(CONF_HEADER)
    L.append("")
    L.append("config setup")
    L.append("    uniqueids=never")
    L.append('    charondebug="ike 1, knl 1, cfg 0"')
    L.append("")

    for t in tunnels:
        if not t.get("enabled", True):
            continue
        name = t.get("name") or "tunnel"
        local = t.get("local_addr") or "%any"
        remote = t.get("remote_addr") or ""
        if not remote:
            raise IPsecError(f"tunnel {name}: remote_addr required")

        left_ts = t.get("local_ts") or "0.0.0.0/0"
        right_ts = t.get("remote_ts") or "0.0.0.0/0"

        L.append(f"conn {name}")
        L.append("    keyexchange=ikev2")
        L.append("    authby=secret")
        L.append(f"    left={local}")
        L.append(f"    leftsubnet={left_ts}")
        L.append("    leftid=%any")
        L.append(f"    right={remote}")
        L.append(f"    rightsubnet={right_ts}")
        L.append("    ike=aes256-sha256-modp2048,aes128-sha256-modp2048")
        L.append("    esp=aes256-sha256,aes128-sha256")
        L.append("    auto=start")
        L.append("    dpdaction=restart")
        L.append("    dpddelay=30s")
        L.append("    dpdtimeout=120s")
        L.append("")

    return "\n".join(L)


def _render_secrets(config: dict) -> str:
    ipsec = config.get("vpn", {}).get("ipsec", {}) or {}
    tunnels = ipsec.get("tunnels", []) or []

    L: list[str] = []
    L.append("# NFW — GENERATED ipsec.secrets. Manual edits will be overwritten.")
    L.append("")

    for t in tunnels:
        if not t.get("enabled", True):
            continue
        remote = t.get("remote_addr") or ""
        psk = t.get("psk") or ""
        if not remote or not psk:
            continue
        L.append(f'%any {remote} : PSK "{psk}"')
        L.append(f'{remote} %any : PSK "{psk}"')

    return "\n".join(L)


def apply(config: dict) -> dict:
    """Write /etc/ipsec.conf and /etc/ipsec.secrets, then restart the
    strongswan-starter service."""
    conf_text = _render_conf(config)
    secrets_text = _render_secrets(config)

    _write(IPSEC_CONF, conf_text, mode=0o644)
    _write(IPSEC_SECRETS, secrets_text, mode=0o600)

    results = []
    for cmd in (
        ["/usr/bin/systemctl", "enable", "strongswan-starter"],
        ["/usr/bin/systemctl", "restart", "strongswan-starter"],
    ):
        r = _run(cmd)
        results.append({"cmd": " ".join(cmd), "rc": r["rc"], "err": r["err"]})

    return {
        "written": [IPSEC_CONF, IPSEC_SECRETS],
        "service": results,
    }


def status() -> dict:
    """Return `ipsec statusall` output."""
    r = _run(["/usr/sbin/ipsec", "statusall"], timeout=15)
    return {"raw": r["out"], "err": r["err"], "rc": r["rc"]}
