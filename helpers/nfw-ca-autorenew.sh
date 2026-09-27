#!/usr/bin/env bash
set -euo pipefail
echo "[$(date -Is)] nfw-ca-autorenew starting"

EXPIRING=$(python3 - <<'PY'
import json, socket, sys
req = {"action": "ca.expiring", "data": {"within_days": 30}}
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect("/run/nfw/configd.sock")
    s.sendall((json.dumps(req) + "\n").encode())
    data = b""
    while not data.endswith(b"\n"):
        chunk = s.recv(4096)
        if not chunk: break
        data += chunk
    r = json.loads(data.decode())
    certs = (r.get("result") or {}).get("certs") or []
    for c in certs:
        print(c["serial"])
except Exception as e:
    print(f"ERROR: {e}", file=sys.stderr)
PY
)

if [ -z "$EXPIRING" ]; then
    echo "  no certs expiring within 30 days"
    exit 0
fi

for SERIAL in $EXPIRING; do
    echo "  renewing $SERIAL"
    python3 - <<PY
import json, socket
req = {"action": "ca.renew", "data": {"serial": "$SERIAL"}}
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect("/run/nfw/configd.sock")
    s.sendall((json.dumps(req) + "\n").encode())
    data = b""
    while not data.endswith(b"\n"):
        chunk = s.recv(4096)
        if not chunk: break
        data += chunk
    print("   ", data.decode()[:200])
except Exception as e:
    print("    ERROR:", e)
PY
done
echo "[$(date -Is)] nfw-ca-autorenew done"
