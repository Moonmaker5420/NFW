"""VPN actions: WireGuard, OpenVPN, IPsec."""
from __future__ import annotations
import logging
import sys
from typing import Any

from configd.registry import action

sys.path.insert(0, "/opt/nfw")
sys.path.insert(0, "/opt/nfw/core")

from config import store as cfg_store
from config.schema import validate
from modules.vpn import wireguard as wg
from modules.vpn import openvpn as ovpn
from modules.vpn import ipsec as ipsec

LOG = logging.getLogger("configd.vpn")


def _effective_config() -> dict:
    staged = cfg_store.get_staging()
    return dict(staged if staged is not None else cfg_store.read())


def _vpn_section(cfg: dict) -> dict:
    s = cfg.setdefault("vpn", {})
    s.setdefault("wireguard", {"instances": []})
    s.setdefault("openvpn", {"servers": []})
    s.setdefault("ipsec", {"tunnels": []})
    return s


# ===========================================================================
# WireGuard
# ===========================================================================
@action("vpn.wg.list")
def wg_list(_data):
    cfg = _effective_config()
    return {"instances": _vpn_section(cfg)["wireguard"].get("instances", []),
            "status": wg.status()}


@action("vpn.wg.add_instance")
def wg_add_instance(data):
    inst = data.get("instance")
    if not isinstance(inst, dict):
        raise ValueError("missing 'instance'")
    import secrets
    inst.setdefault("id", "wg-" + secrets.token_hex(4))
    inst.setdefault("interface", "wg0")
    inst.setdefault("listen_port", 51820)
    inst.setdefault("address", "10.7.0.1/24")
    inst.setdefault("peers", [])
    inst.setdefault("enabled", True)

    # Auto-generate keys if missing
    if not inst.get("private_key"):
        priv, pub = wg.gen_peer()["private_key"], None
        # regen to get both
        import subprocess
        priv = subprocess.run(["/usr/bin/wg", "genkey"],
                              capture_output=True, text=True, check=True).stdout.strip()
        pub = subprocess.run(["/usr/bin/wg", "pubkey"], input=priv + "\n",
                             capture_output=True, text=True, check=True).stdout.strip()
        inst["private_key"] = priv
        inst["public_key"] = pub

    cfg = _effective_config()
    instances = _vpn_section(cfg)["wireguard"].setdefault("instances", [])
    instances.append(inst)
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"instance": inst}


@action("vpn.wg.update_instance")
def wg_update_instance(data):
    iid = data.get("id")
    inst = data.get("instance")
    if not iid or not isinstance(inst, dict):
        raise ValueError("missing id or instance")
    cfg = _effective_config()
    instances = _vpn_section(cfg)["wireguard"].get("instances", [])
    for i, x in enumerate(instances):
        if x.get("id") == iid:
            inst["id"] = iid
            instances[i] = inst
            break
    else:
        raise FileNotFoundError(f"instance {iid} not found")
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"instance": inst}


@action("vpn.wg.delete_instance")
def wg_delete_instance(data):
    iid = data.get("id")
    cfg = _effective_config()
    instances = _vpn_section(cfg)["wireguard"].get("instances", [])

    target = next((x for x in instances if x.get("id") == iid), None)
    if target is None:
        raise FileNotFoundError(f"instance {iid} not found")

    iface = target.get("interface", "wg0")

    # Bring the interface down + remove config file + disable unit
    import subprocess, os
    results = []
    for cmd in (
        ["/usr/bin/wg-quick", "down", iface],
        ["/usr/bin/systemctl", "disable", f"wg-quick@{iface}"],
    ):
        r = subprocess.run(cmd, capture_output=True, text=True)
        results.append({"cmd": " ".join(cmd), "rc": r.returncode,
                        "stderr": r.stderr.strip()})

    try:
        os.unlink(f"/etc/wireguard/{iface}.conf")
    except FileNotFoundError:
        pass

    # Remove from config
    new = [x for x in instances if x.get("id") != iid]
    _vpn_section(cfg)["wireguard"]["instances"] = new
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"deleted": iid, "interface": iface, "system": results}


@action("vpn.wg.add_peer")
def wg_add_peer(data):
    iid = data.get("instance_id")
    peer = data.get("peer")
    if not iid or not isinstance(peer, dict):
        raise ValueError("missing instance_id or peer")
    import secrets
    peer.setdefault("id", "peer-" + secrets.token_hex(4))

    # Auto-generate keys
    if not peer.get("private_key"):
        import subprocess
        priv = subprocess.run(["/usr/bin/wg", "genkey"],
                              capture_output=True, text=True, check=True).stdout.strip()
        pub = subprocess.run(["/usr/bin/wg", "pubkey"], input=priv + "\n",
                             capture_output=True, text=True, check=True).stdout.strip()
        peer["private_key"] = priv
        peer["public_key"] = pub

    cfg = _effective_config()
    for inst in _vpn_section(cfg)["wireguard"].get("instances", []):
        if inst.get("id") == iid:
            inst.setdefault("peers", []).append(peer)
            break
    else:
        raise FileNotFoundError(f"instance {iid} not found")
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"peer": peer}


@action("vpn.wg.delete_peer")
def wg_delete_peer(data):
    iid = data.get("instance_id")
    pid = data.get("peer_id")
    cfg = _effective_config()

    iface = None
    peer_pubkey = None
    for inst in _vpn_section(cfg)["wireguard"].get("instances", []):
        if inst.get("id") == iid:
            iface = inst.get("interface", "wg0")
            for p in inst.get("peers", []):
                if p.get("id") == pid:
                    peer_pubkey = p.get("public_key")
                    break
            peers = inst.get("peers", [])
            new = [p for p in peers if p.get("id") != pid]
            if len(new) == len(peers):
                raise FileNotFoundError(f"peer {pid} not found")
            inst["peers"] = new
            break
    else:
        raise FileNotFoundError(f"instance {iid} not found")

    # Remove the peer from the live interface
    import subprocess
    system_result = None
    if iface and peer_pubkey:
        r = subprocess.run(
            ["/usr/bin/wg", "set", iface, "peer", peer_pubkey, "remove"],
            capture_output=True, text=True,
        )
        system_result = {"rc": r.returncode, "stderr": r.stderr.strip()}

    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"deleted": pid, "system": system_result}


@action("vpn.wg.preview")
def wg_preview(_data):
    cfg = _effective_config()
    wg_cfg = _vpn_section(cfg)["wireguard"]
    files = []
    for inst in wg_cfg.get("instances", []):
        iface = inst.get("interface", "wg0")
        try:
            text = wg._render_instance(cfg, inst)
            files.append({"path": f"/etc/wireguard/{iface}.conf", "content": text})
        except Exception as e:
            files.append({"path": iface, "error": str(e)})
    return {"files": files}


@action("vpn.wg.apply")
def wg_apply(data):
    cfg = _effective_config()
    return wg.apply(cfg)


@action("vpn.wg.qr")
def wg_qr(data):
    iid = data.get("instance_id")
    pid = data.get("peer_id")
    cfg = _effective_config()
    return wg.peer_qr(cfg, iid, pid)


# ===========================================================================
# OpenVPN
# ===========================================================================
@action("vpn.ovpn.list")
def ovpn_list(_data):
    cfg = _effective_config()
    return {"servers": _vpn_section(cfg)["openvpn"].get("servers", []),
            "status": ovpn.status()}


@action("vpn.ovpn.add_server")
def ovpn_add_server(data):
    srv = data.get("server")
    if not isinstance(srv, dict):
        raise ValueError("missing 'server'")
    import secrets
    srv.setdefault("id", "ovpn-" + secrets.token_hex(4))
    srv.setdefault("name", "server")
    srv.setdefault("proto", "udp")
    srv.setdefault("port", 1194)
    srv.setdefault("subnet", "10.8.0.0")
    srv.setdefault("netmask", "255.255.255.0")
    srv.setdefault("clients", [])
    srv.setdefault("enabled", True)

    cfg = _effective_config()
    servers = _vpn_section(cfg)["openvpn"].setdefault("servers", [])
    servers.append(srv)
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"server": srv}


@action("vpn.ovpn.delete_server")
def ovpn_delete_server(data):
    sid = data.get("id")
    if not sid:
        raise ValueError("missing id")

    cfg = _effective_config()
    servers = _vpn_section(cfg)["openvpn"].get("servers", [])

    target = next((x for x in servers if x.get("id") == sid), None)
    if target is None:
        raise FileNotFoundError(f"server {sid} not found")

    name = target.get("name", "server")

    import subprocess, os
    results = []

    # 1. Stop and disable the systemd unit
    for cmd in (
        ["/usr/bin/systemctl", "stop", f"openvpn-server@{name}"],
        ["/usr/bin/systemctl", "disable", f"openvpn-server@{name}"],
        ["/usr/bin/systemctl", "reset-failed", f"openvpn-server@{name}"],
    ):
        r = subprocess.run(cmd, capture_output=True, text=True)
        results.append({"cmd": " ".join(cmd), "rc": r.returncode,
                        "stderr": r.stderr.strip()})

    # 2. Remove server config file
    try:
        os.unlink(f"/etc/openvpn/server/{name}.conf")
    except FileNotFoundError:
        pass

    # 3. Remove + revoke client configs
    easyrsa = "/etc/openvpn/easy-rsa/easyrsa"
    for client in target.get("clients", []) or []:
        cname = client.get("name")
        if not cname:
            continue
        try:
            os.unlink(f"/etc/openvpn/client/{cname}.ovpn")
        except FileNotFoundError:
            pass
        if os.path.exists(easyrsa) and os.path.exists(
                f"/etc/openvpn/easy-rsa/pki/issued/{cname}.crt"):
            subprocess.run(
                [easyrsa, "--batch", "revoke", cname],
                cwd="/etc/openvpn/easy-rsa",
                capture_output=True, text=True, timeout=30,
            )
            subprocess.run(
                [easyrsa, "gen-crl"],
                cwd="/etc/openvpn/easy-rsa",
                capture_output=True, text=True, timeout=30,
            )

    # 4. Remove from config
    new = [x for x in servers if x.get("id") != sid]
    _vpn_section(cfg)["openvpn"]["servers"] = new
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"deleted": sid, "name": name, "system": results}


@action("vpn.ovpn.add_client")
def ovpn_add_client(data):
    sid = data.get("server_id")
    name = data.get("name")
    if not sid or not name:
        raise ValueError("missing server_id or name")
    cfg = _effective_config()
    for srv in _vpn_section(cfg)["openvpn"].get("servers", []):
        if srv.get("id") == sid:
            srv.setdefault("clients", []).append({"name": name})
            break
    else:
        raise FileNotFoundError(f"server {sid} not found")
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"client": name}


@action("vpn.ovpn.apply")
def ovpn_apply(data):
    cfg = _effective_config()
    servers = _vpn_section(cfg)["openvpn"].get("servers", [])
    active_names = {s.get("name", "server") for s in servers}

    # Cleanup orphan units
    import subprocess
    r = subprocess.run(
        ["/usr/bin/systemctl", "list-units", "--type=service", "--all",
         "--no-legend", "openvpn-server@*"],
        capture_output=True, text=True,
    )
    cleaned = []
    for line in r.stdout.splitlines():
        parts = line.split()
        if not parts or not parts[0].startswith("openvpn-server@"):
            continue
        unit = parts[0]
        name = unit.split("@", 1)[1].split(".", 1)[0]
        if name in active_names:
            continue
        subprocess.run(["/usr/bin/systemctl", "stop", unit],
                       capture_output=True, text=True)
        subprocess.run(["/usr/bin/systemctl", "disable", unit],
                       capture_output=True, text=True)
        subprocess.run(["/usr/bin/systemctl", "reset-failed", unit],
                       capture_output=True, text=True)
        try:
            import os
            os.unlink(f"/etc/openvpn/server/{name}.conf")
        except FileNotFoundError:
            pass
        cleaned.append(unit)

    result = ovpn.apply(cfg)
    result["cleaned"] = cleaned
    return result


@action("vpn.ovpn.export")
def ovpn_export(data):
    name = data.get("name")
    if not name:
        raise ValueError("missing name")
    try:
        content = ovpn.export_client(name)
    except FileNotFoundError as e:
        raise ValueError(str(e))
    return {"name": name, "config": content}


# ===========================================================================
# IPsec
# ===========================================================================
@action("vpn.ipsec.list")
def ipsec_list(_data):
    cfg = _effective_config()
    return {"tunnels": _vpn_section(cfg)["ipsec"].get("tunnels", []),
            "status": ipsec.status()}


@action("vpn.ipsec.add_tunnel")
def ipsec_add(data):
    t = data.get("tunnel")
    if not isinstance(t, dict):
        raise ValueError("missing 'tunnel'")
    import secrets
    t.setdefault("id", "ipsec-" + secrets.token_hex(4))
    t.setdefault("enabled", True)
    cfg = _effective_config()
    tunnels = _vpn_section(cfg)["ipsec"].setdefault("tunnels", [])
    tunnels.append(t)
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")
    return {"tunnel": t}


@action("vpn.ipsec.delete_tunnel")
def ipsec_delete(data):
    tid = data.get("id")
    if not tid:
        raise ValueError("missing id")

    cfg = _effective_config()
    tunnels = _vpn_section(cfg)["ipsec"].get("tunnels", [])

    target = next((x for x in tunnels if x.get("id") == tid), None)
    if target is None:
        raise FileNotFoundError(f"tunnel {tid} not found")

    name = target.get("name", "tunnel")

    import subprocess
    results = []

    # Terminate the specific connection (best-effort)
    r = subprocess.run(["/usr/sbin/ipsec", "down", name],
                       capture_output=True, text=True, timeout=15)
    results.append({"cmd": f"ipsec down {name}",
                    "rc": r.returncode, "stderr": r.stderr.strip()})

    # Remove from config
    new = [x for x in tunnels if x.get("id") != tid]
    _vpn_section(cfg)["ipsec"]["tunnels"] = new
    validate(cfg)
    cfg_store.stage(cfg, author=data.get("author") or "unknown")

    # Rewrite ipsec.conf + ipsec.secrets without this tunnel
    try:
        from modules.vpn import ipsec as ipsec_mod
        ipsec_mod.apply(cfg)
        results.append({"cmd": "rewrite ipsec.conf", "rc": 0})
    except Exception as e:
        results.append({"cmd": "rewrite ipsec.conf", "rc": 1, "stderr": str(e)})

    return {"deleted": tid, "name": name, "system": results}


@action("vpn.ipsec.apply")
def ipsec_apply(data):
    cfg = _effective_config()
    # Rewrite full ipsec.conf + ipsec.secrets and restart strongswan-starter.
    # Any tunnel not in the config is automatically absent from the new file.
    return ipsec.apply(cfg)
