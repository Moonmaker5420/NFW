#!/usr/bin/env bash
# OPNsense-style CA invariant enforcement.
#
# The API reads its TLS key via systemd's LoadCredential=, not from the
# filesystem. Therefore no service user needs group access to /var/lib/nfw/ca.
# This script enforces the root-only invariants after every boot.
#
# It no longer does chgrp -R nfw on the CA tree, because that would silently
# re-open the very hole the LoadCredential model closes.
set -uo pipefail

LOG=/var/log/nfw/fix-ca-perms.log
mkdir -p /var/log/nfw
touch "$LOG"
exec >>"$LOG" 2>&1

echo "[$(date -u +%FT%TZ)] enforcing CA invariants"

CA=/var/lib/nfw/ca
[ -d "$CA" ] || { echo "  no CA dir — nothing to do"; exit 0; }

fail=0

# Directories
chown root:root "$CA" 2>/dev/null || fail=1
chmod 0755 "$CA" 2>/dev/null || fail=1
for d in certs csrs; do
    [ -d "$CA/$d" ] || continue
    chown root:root "$CA/$d" 2>/dev/null || fail=1
    chmod 0755 "$CA/$d" 2>/dev/null || fail=1
done
if [ -d "$CA/private" ]; then
    chown root:root "$CA/private" 2>/dev/null || fail=1
    chmod 0700 "$CA/private" 2>/dev/null || fail=1
fi

# Keys — root:root 0400
shopt -s nullglob
for f in "$CA"/*.key "$CA"/private/*.key; do
    chown root:root "$f" || fail=1
    chmod 0400 "$f" || fail=1
done

# Cert/public PEM — root:root 0644
for f in "$CA"/*.crt "$CA"/*.pem "$CA"/certs/*.crt; do
    chown root:root "$f" || fail=1
    chmod 0644 "$f" || fail=1
done

# CA DB bookkeeping — root:root 0640
for f in "$CA"/index.txt "$CA"/serial "$CA"/crlnumber "$CA"/*.lock; do
    [ -e "$f" ] || continue
    chown root:root "$f" || fail=1
    chmod 0640 "$f" || fail=1
done

if [ "$fail" = 0 ]; then
    echo "  ok"
else
    echo "  WARN: one or more chown/chmod failed"
fi
exit 0
