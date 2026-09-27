"""Wake-on-LAN via etherwake or wakeonlan."""
from __future__ import annotations
import re
import subprocess


def wake(mac: str, broadcast: str = "") -> dict:
    if not re.match(r"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$", mac):
        raise ValueError(f"invalid MAC address: {mac}")
    cmd = ["/usr/bin/etherwake", "-i", broadcast, mac] if broadcast else \
          ["/usr/sbin/etherwake", mac]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            # Try wakeonlan as fallback
            cmd = ["/usr/bin/wakeonlan", mac]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return {"ok": r.returncode == 0, "out": r.stdout, "err": r.stderr}
    except FileNotFoundError:
        return {"ok": False, "err": "etherwake/wakeonlan not installed"}
