"""
OpenVPN config generator.

Uses easy-rsa for PKI. On first apply, initializes the CA.
"""
from __future__ import annotations
import os
import subprocess
from typing import Any

EASYRSA_DIR = "/etc/openvpn/easy-rsa"
SERVER_DIR = "/etc/openvpn/server"
CLIENT_DIR = "/etc/openvpn/client"


class OVPNError(ValueError):
    pass


def _run(cmd: list[str], cwd: str = None, timeout: int = 30) -> dict:
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return {"rc": r.returncode, "out": r.stdout, "err": r.stderr}


def ensure_ca() -> dict:
    """Initialize easy-rsa PKI if not already done. Fully non-interactive."""
    if not os.path.isdir(EASYRSA_DIR) or not os.path.exists(f"{EASYRSA_DIR}/pki/ca.crt"):
        os.makedirs(EASYRSA_DIR, exist_ok=True)

        # Locate easy-rsa on disk
        easyrsa_bin = None
        for src in ("/usr/share/easy-rsa", "/usr/share/easy-rsa/easyrsa3"):
            if os.path.isfile(f"{src}/easyrsa"):
                # Copy tree
                _run(["/bin/cp", "-r", f"{src}/.", EASYRSA_DIR])
                easyrsa_bin = f"{EASYRSA_DIR}/easyrsa"
                break
        if not easyrsa_bin:
            raise OVPNError("easy-rsa not found at /usr/share/easy-rsa")

        os.chmod(easyrsa_bin, 0o755)

        # Init PKI
        r = _run([easyrsa_bin, "init-pki"], cwd=EASYRSA_DIR, timeout=60)
        if r["rc"] != 0:
            raise OVPNError(f"init-pki failed: {r['err']}")

        # Build CA (non-interactive)
        r = _run([easyrsa_bin, "--batch", "--req-cn=NFW-CA",
                  "build-ca", "nopass"],
                 cwd=EASYRSA_DIR, timeout=120)
        if r["rc"] != 0:
            raise OVPNError(f"build-ca failed: {r['err'] or r['out']}")

        # Server cert (non-interactive)
        r = _run([easyrsa_bin, "--batch",
                  "build-server-full", "server", "nopass"],
                 cwd=EASYRSA_DIR, timeout=120)
        if r["rc"] != 0:
            raise OVPNError(f"build-server-full failed: {r['err'] or r['out']}")

        # DH params (slow, allow 5 min)
        r = _run([easyrsa_bin, "gen-dh"], cwd=EASYRSA_DIR, timeout=300)
        if r["rc"] != 0:
            # Non-fatal — some OpenVPN setups don't need DH with ECDHE ciphers
            pass

        # CRL
        r = _run([easyrsa_bin, "gen-crl"], cwd=EASYRSA_DIR, timeout=60)
        if r["rc"] != 0:
            pass

        # TLS auth — OpenVPN 2.6 changed syntax
        r = _run(["/usr/bin/openvpn", "--genkey", "secret",
                  f"{SERVER_DIR}/ta.key"])
        if r["rc"] != 0:
            _run(["/usr/bin/openvpn", "--genkey", "--secret",
                  f"{SERVER_DIR}/ta.key"])

    return {"pki_dir": EASYRSA_DIR}



def ensure_client_cert(name: str) -> dict:
    """Generate a client certificate if not present. Non-interactive."""
    cert_path = f"{EASYRSA_DIR}/pki/issued/{name}.crt"
    if not os.path.exists(cert_path):
        r = _run([f"{EASYRSA_DIR}/easyrsa", "--batch",
                  "build-client-full", name, "nopass"],
                 cwd=EASYRSA_DIR, timeout=120)
        if r["rc"] != 0:
            raise OVPNError(f"build-client-full failed: {r['err'] or r['out']}")
    return {"cert": cert_path}


def _server_conf(inst: dict) -> str:
    proto = inst.get("proto", "udp")
    port = int(inst.get("port", 1194))
    dev = inst.get("dev", "tun")
    subnet = inst.get("subnet", "10.8.0.0")
    netmask = inst.get("netmask", "255.255.255.0")
    push_dns = inst.get("push_dns", ["1.1.1.1"])
    redirect_gw = inst.get("redirect_gw", True)

    L: list[str] = []
    L.append("# NFW — GENERATED OpenVPN server config")
    L.append(f"port {port}")
    L.append(f"proto {proto}")
    L.append(f"dev {dev}")
    L.append("topology subnet")
    L.append(f"server {subnet} {netmask}")
    L.append(f"ca {EASYRSA_DIR}/pki/ca.crt")
    L.append(f"cert {EASYRSA_DIR}/pki/issued/server.crt")
    L.append(f"key {EASYRSA_DIR}/pki/private/server.key")
    L.append(f"dh {EASYRSA_DIR}/pki/dh.pem")
    L.append(f"crl-verify {EASYRSA_DIR}/pki/crl.pem")
    L.append(f"tls-auth {SERVER_DIR}/ta.key 0")
    L.append("cipher AES-256-GCM")
    L.append("auth SHA256")
    L.append("tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384")
    L.append("tls-version-min 1.2")
    L.append("user nobody")
    L.append("group nogroup")
    L.append("persist-key")
    L.append("persist-tun")
    L.append("keepalive 10 120")
    L.append("status /var/log/openvpn-status.log")
    L.append("verb 3")
    L.append("explicit-exit-notify 1")

    for dns in push_dns:
        L.append(f'push "dhcp-option DNS {dns}"')
    if redirect_gw:
        L.append('push "redirect-gateway def1 bypass-dhcp"')

    return "\n".join(L)


def _client_conf(inst: dict, name: str) -> str:
    proto = inst.get("proto", "udp")
    port = int(inst.get("port", 1194))
    endpoint = inst.get("endpoint_host", "")
    dev = inst.get("dev", "tun")

    with open(f"{EASYRSA_DIR}/pki/ca.crt") as f:
        ca = f.read().strip()
    with open(f"{EASYRSA_DIR}/pki/issued/{name}.crt") as f:
        crt = f.read().strip()
    with open(f"{EASYRSA_DIR}/pki/private/{name}.key") as f:
        key = f.read().strip()
    with open(f"{SERVER_DIR}/ta.key") as f:
        ta = f.read().strip()

    L: list[str] = []
    L.append("client")
    L.append("dev tun")
    L.append(f"proto {proto}")
    L.append(f"remote {endpoint} {port}")
    L.append("resolv-retry infinite")
    L.append("nobind")
    L.append("persist-key")
    L.append("persist-tun")
    L.append("remote-cert-tls server")
    L.append("cipher AES-256-GCM")
    L.append("auth SHA256")
    L.append("verb 3")
    L.append("<ca>")
    L.append(ca)
    L.append("</ca>")
    L.append("<cert>")
    L.append(crt)
    L.append("</cert>")
    L.append("<key>")
    L.append(key)
    L.append("</key>")
    L.append("<tls-auth>")
    L.append(ta)
    L.append("</tls-auth>")
    L.append("key-direction 1")
    return "\n".join(L)


def apply(config: dict) -> dict:
    ovpn = config.get("vpn", {}).get("openvpn", {}) or {}
    servers = ovpn.get("servers", []) or []
    ca = ensure_ca()

    written: list[str] = []
    results: list[dict] = []

    for srv in servers:
        name = srv.get("name", "server")
        # Build conf
        conf = _server_conf(srv)
        path = f"{SERVER_DIR}/{name}.conf"
        with open(path, "w") as f:
            f.write(conf)
        written.append(path)

        # Generate client certs for each client entry
        for client in srv.get("clients", []) or []:
            cname = client.get("name")
            if not cname:
                continue
            ensure_client_cert(cname)
            cc = _client_conf(srv, cname)
            cpath = f"{CLIENT_DIR}/{cname}.ovpn"
            with open(cpath, "w") as f:
                f.write(cc)
            written.append(cpath)

        if srv.get("enabled", True):
            subprocess.run(["/usr/bin/systemctl", "enable", "--now",
                           f"openvpn-server@{name}"], capture_output=True)
            r = subprocess.run(["/usr/bin/systemctl", "restart",
                               f"openvpn-server@{name}"],
                               capture_output=True, text=True)
            results.append({"name": name, "enabled": True, "rc": r.returncode})
        else:
            subprocess.run(["/usr/bin/systemctl", "disable", "--now",
                           f"openvpn-server@{name}"], capture_output=True)
            results.append({"name": name, "enabled": False})

    return {"pki": ca, "written": written, "servers": results}


def status() -> dict:
    r = subprocess.run(["/usr/bin/systemctl", "list-units",
                        "--type=service", "--all",
                        "openvpn-server@*", "--no-legend"],
                       capture_output=True, text=True)
    out = []
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            out.append({"unit": parts[0], "state": parts[3]})
    return {"servers": out}


def export_client(name: str) -> str:
    path = f"{CLIENT_DIR}/{name}.ovpn"
    if not os.path.exists(path):
        raise FileNotFoundError(f"client {name} not found")
    with open(path) as f:
        return f.read()
