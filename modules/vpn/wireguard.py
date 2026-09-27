"""
WireGuard config generator.

Reads config["vpn"]["wireguard"] and emits:
  - /etc/wireguard/<iface>.conf per instance
  - systemd enable/start for each
  - QR code (PNG as base64) for peers
"""
from __future__ import annotations
import base64
import os
import subprocess
import tempfile
from typing import Any


class WGError(ValueError):
    pass


def _wg_genkey() -> tuple[str, str]:
    """Return (private_key, public_key)."""
    priv = subprocess.run(["/usr/bin/wg", "genkey"],
                          capture_output=True, text=True, check=True).stdout.strip()
    pub = subprocess.run(["/usr/bin/wg", "pubkey"],
                         input=priv + "\n",
                         capture_output=True, text=True, check=True).stdout.strip()
    return priv, pub


def gen_peer() -> dict:
    """Generate a fresh peer keypair."""
    priv, pub = _wg_genkey()
    return {"private_key": priv, "public_key": pub}


def _render_instance(cfg: dict, instance: dict) -> str:
    """Render a WireGuard config file for one instance."""
    iface = instance.get("interface", "wg0")
    address = instance.get("address", "")
    listen_port = instance.get("listen_port", 51820)
    private_key = instance.get("private_key", "")
    dns = instance.get("dns", []) or []
    mtu = instance.get("mtu")
    post_up = instance.get("post_up", "")
    post_down = instance.get("post_down", "")

    if not private_key:
        # Generate one
        priv, pub = _wg_genkey()
        private_key = priv
        instance["private_key"] = priv
        instance["public_key"] = pub

    if not address:
        raise WGError("instance.address required")

    L: list[str] = []
    L.append("# NFW — GENERATED WireGuard config")
    L.append("[Interface]")
    L.append(f"Address = {address}")
    L.append(f"ListenPort = {int(listen_port)}")
    L.append(f"PrivateKey = {private_key}")
    if mtu:
        L.append(f"MTU = {int(mtu)}")
    # DNS belongs in CLIENT configs only. Server config should not include
    # it, because wg-quick will try to hand it to resolvconf/systemd-resolved
    # and fail hard if neither is running.
    # (Client configs are rendered separately in peer_qr().)
    if post_up:
        L.append(f"PostUp = {post_up}")
    if post_down:
        L.append(f"PostDown = {post_down}")
    L.append("")

    for peer in instance.get("peers", []):
        L.append("[Peer]")
        if peer.get("name"):
            L.append(f"# {peer['name']}")
        L.append(f"PublicKey = {peer['public_key']}")
        if peer.get("preshared_key"):
            L.append(f"PresharedKey = {peer['preshared_key']}")
        allowed = peer.get("allowed_ips") or ["0.0.0.0/0"]
        L.append("AllowedIPs = " + ", ".join(allowed))
        if peer.get("endpoint"):
            L.append(f"Endpoint = {peer['endpoint']}")
        if peer.get("persistent_keepalive"):
            L.append(f"PersistentKeepalive = {int(peer['persistent_keepalive'])}")
        L.append("")

    return "\n".join(L)




def _cleanup_stale_units(active_ifaces: set[str]) -> list[str]:
    """Stop any wg-quick@<iface> services whose iface is NOT in active_ifaces."""
    stopped = []
    r = subprocess.run(
        ["/usr/bin/systemctl", "list-units", "--type=service", "--all",
         "--no-legend", "wg-quick@*"],
        capture_output=True, text=True,
    )
    for line in r.stdout.splitlines():
        parts = line.split()
        if not parts or not parts[0].startswith("wg-quick@"):
            continue
        unit = parts[0]
        iface = unit.split("@", 1)[1].split(".", 1)[0]
        if iface in active_ifaces:
            continue
        subprocess.run(["/usr/bin/systemctl", "stop", unit],
                       capture_output=True, text=True)
        subprocess.run(["/usr/bin/systemctl", "reset-failed", unit],
                       capture_output=True, text=True)
        subprocess.run(["/usr/bin/wg-quick", "down", iface],
                       capture_output=True, text=True)
        try:
            os.unlink(f"/etc/wireguard/{iface}.conf")
        except FileNotFoundError:
            pass
        stopped.append(unit)
    return stopped


def apply(config: dict) -> dict:
    """Write all WireGuard config files and (re)start wg-quick units."""
    wg = config.get("vpn", {}).get("wireguard", {}) or {}
    instances = wg.get("instances", []) or []

    written: list[str] = []
    results: list[dict] = []

    # Ensure runtime dir
    os.makedirs("/etc/wireguard", exist_ok=True)

    # Cleanup: stop any wg-quick@* units whose iface is not in this config
    active_ifaces = {i.get("interface", "wg0") for i in instances}
    cleaned = _cleanup_stale_units(active_ifaces)

    for inst in instances:
        iface = inst.get("interface", "wg0")
        text = _render_instance(config, inst)
        path = f"/etc/wireguard/{iface}.conf"
        with open(path, "w") as f:
            f.write(text)
        os.chmod(path, 0o600)
        written.append(path)

        if inst.get("enabled", True):
            # Bring down any existing interface (via systemd or wg-quick)
            # then start through systemd so the unit tracks it.
            subprocess.run(["/usr/bin/systemctl", "stop",
                            f"wg-quick@{iface}"],
                           capture_output=True, text=True)
            subprocess.run(["/usr/bin/wg-quick", "down", iface],
                           capture_output=True, text=True)
            subprocess.run(["/usr/bin/systemctl", "enable",
                            f"wg-quick@{iface}"],
                           capture_output=True, text=True)
            r = subprocess.run(["/usr/bin/systemctl", "start",
                                f"wg-quick@{iface}"],
                               capture_output=True, text=True)
            results.append({
                "interface": iface,
                "enabled": True,
                "start_rc": r.returncode,
                "start_stderr": r.stderr,
            })
        else:
            subprocess.run(["/usr/bin/systemctl", "stop",
                            f"wg-quick@{iface}"],
                           capture_output=True, text=True)
            subprocess.run(["/usr/bin/systemctl", "disable",
                            f"wg-quick@{iface}"],
                           capture_output=True, text=True)
            subprocess.run(["/usr/bin/wg-quick", "down", iface],
                           capture_output=True, text=True)
            results.append({"interface": iface, "enabled": False})

    return {"written": written, "instances": results, "cleaned": cleaned}


def status() -> dict:
    """Return current status of all wg-quick interfaces."""
    result = subprocess.run(["/usr/bin/wg", "show", "all", "dump"],
                            capture_output=True, text=True)
    if result.returncode != 0:
        return {"interfaces": [], "error": result.stderr}

    out = []
    for line in result.stdout.strip().split("\n"):
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        out.append({
            "interface": parts[0],
            "public_key": parts[1],
            "listen_port": parts[2],
            "peers": [],
        })
    return {"interfaces": out}


def peer_qr(config: dict, instance_id: str, peer_id: str) -> dict:
    """Generate client config + QR for a peer. Returns base64 PNG."""
    wg = config.get("vpn", {}).get("wireguard", {}) or {}
    for inst in wg.get("instances", []) or []:
        if inst.get("id") != instance_id:
            continue
        server_pub = inst.get("public_key", "")
        listen_port = inst.get("listen_port", 51820)
        endpoint_host = inst.get("endpoint_host", "")
        for peer in inst.get("peers", []):
            if peer.get("id") != peer_id:
                continue
            cfg_text = (
                "[Interface]\n"
                f"PrivateKey = {peer['private_key']}\n"
                f"Address = {peer.get('client_address', '')}\n"
                f"DNS = {inst.get('dns', ['1.1.1.1'])[0]}\n"
                "\n"
                "[Peer]\n"
                f"PublicKey = {server_pub}\n"
                f"AllowedIPs = 0.0.0.0/0, ::/0\n"
                f"Endpoint = {endpoint_host}:{listen_port}\n"
                "PersistentKeepalive = 25\n"
            )
            # Generate QR
            with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f:
                f.write(cfg_text)
                tmp = f.name
            try:
                png = subprocess.run(
                    ["/usr/bin/qrencode", "-o", "-", "-t", "PNG", "-s", "6",
                     "-m", "2", "-r", tmp],
                    capture_output=True,
                )
                b64 = base64.b64encode(png.stdout).decode()
            finally:
                os.unlink(tmp)
            return {"config": cfg_text, "qr_png_b64": b64}
    raise FileNotFoundError("instance/peer not found")
