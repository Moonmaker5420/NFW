#!/usr/bin/env bash
set -euo pipefail
IFACE="$1"; FILTER="$2"; MAX_SEC="$3"; MAX_MB="$4"; OUT="$5"
umask 027
LOG="${OUT}.err"
echo "start: iface=$IFACE filter=$FILTER max_sec=$MAX_SEC max_mb=$MAX_MB out=$OUT" > "$LOG"

if [ ! -x "/usr/bin/tcpdump" ]; then
    echo "tcpdump not found at /usr/bin/tcpdump" >> "$LOG"
    exit 127
fi
if ! ip link show "$IFACE" >/dev/null 2>&1; then
    echo "interface not found: $IFACE" >> "$LOG"
    exit 1
fi

exec /usr/bin/timeout --signal=INT --kill-after=5 "$MAX_SEC" \
    "/usr/bin/tcpdump" -i "$IFACE" -n -s 0 -w "$OUT" -Z root \
        -- "$FILTER" 2>> "$LOG"
