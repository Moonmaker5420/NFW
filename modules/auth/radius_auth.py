"""RADIUS authentication (Phase 9.9b)."""
from __future__ import annotations
import logging

LOG = logging.getLogger("auth.radius")

_RANK = {"readonly": 1, "operator": 2, "admin": 3}
_DICT = "/etc/nfw/radius-dictionary"


def _role_from_attrs(attrs: dict, mapping: dict, default: str) -> str:
    """Match RADIUS reply attributes against the role map. Highest role wins.
    mapping format:
        {"Filter-Id": {"nfw-admin": "admin", "nfw-ops": "operator"}}
    """
    best = None
    for attr_name, valmap in (mapping or {}).items():
        vals = attrs.get(attr_name) or []
        if not isinstance(vals, list):
            vals = [vals]
        for v in vals:
            vs = str(v).strip()
            if vs in valmap and valmap[vs] in _RANK:
                role = valmap[vs]
                if best is None or _RANK[role] > _RANK[best]:
                    best = role
    return best or (default if default in _RANK else "readonly")


def authenticate(cfg: dict, username: str, password: str) -> dict:
    try:
        from pyrad.client import Client
        from pyrad.dictionary import Dictionary
        import pyrad.packet
    except ImportError as e:
        return {"ok": False, "reason": f"pyrad not installed: {e}"}

    rc = (cfg.get("auth") or {}).get("radius") or {}
    server = (rc.get("server") or "").strip()
    secret = rc.get("secret") or ""
    if not server or not secret:
        return {"ok": False, "reason": "radius server and secret required"}

    port = int(rc.get("port", 1812))
    timeout = float(rc.get("timeout", 5))
    nas_id = rc.get("nas_id") or "nfw"

    try:
        client = Client(server=server, authport=port, timeout=timeout)
        client.dictionary = Dictionary(_DICT)
        client.secret = secret.encode("ascii") if isinstance(secret, str) else secret

        req = client.CreateAuthPacket(code=pyrad.packet.AccessRequest,
                                      User_Name=username.encode("utf-8"),
                                      NAS_Identifier=nas_id)
        req["User-Password"] = req.PwCrypt(password)
        req["Service-Type"] = "Login-User"

        reply = client.SendPacket(req)
        if reply.code == pyrad.packet.AccessAccept:
            attrs = {k: list(v) for k, v in reply.items()}
            role = _role_from_attrs(attrs, rc.get("attribute_role_map") or {},
                                    rc.get("default_role", "readonly"))
            return {"ok": True, "method": "radius", "role": role,
                    "attrs": {k: [str(x) for x in v] for k, v in attrs.items()}}
        elif reply.code == pyrad.packet.AccessReject:
            return {"ok": False, "reason": "invalid credentials"}
        else:
            return {"ok": False, "reason": f"radius returned code {reply.code}"}
    except Exception as e:
        LOG.exception("radius auth failed")
        return {"ok": False, "reason": f"radius error: {type(e).__name__}: {e}"}


def test_reachability(cfg: dict) -> dict:
    """Send a synthetic Access-Request. The server's reply tells us whether
    the host+secret combo is reachable."""
    try:
        from pyrad.client import Client
        from pyrad.dictionary import Dictionary
        import pyrad.packet
    except ImportError as e:
        return {"ok": False, "reason": f"pyrad not installed: {e}"}

    rc = (cfg.get("auth") or {}).get("radius") or {}
    server = (rc.get("server") or "").strip()
    secret = rc.get("secret") or ""
    if not server or not secret:
        return {"ok": False, "reason": "server and secret required"}

    try:
        client = Client(server=server, authport=int(rc.get("port", 1812)),
                        timeout=float(rc.get("timeout", 5)))
        client.dictionary = Dictionary(_DICT)
        client.secret = secret.encode("ascii")
        req = client.CreateAuthPacket(code=pyrad.packet.AccessRequest,
                                      User_Name="nfw-reachability-test",
                                      NAS_Identifier=(rc.get("nas_id") or "nfw"))
        req["User-Password"] = req.PwCrypt("invalid-probe-password")
        reply = client.SendPacket(req)
        return {"ok": True, "code": int(reply.code),
                "interpretation": "reachable — server replied"}
    except Exception as e:
        return {"ok": False, "reason": f"{type(e).__name__}: {e}"}
