#!/bin/bash
# Enforce /var/lib/nfw invariants on every boot.
# Targeted — does NOT touch CA private material or setgid dirs.
set -uo pipefail

NFW=/var/lib/nfw
[ -d "$NFW" ] || exit 0

# Top level
chown root:nfw "$NFW"
chmod 0750 "$NFW"

# Directories the API and portal need to traverse
for d in config config/revisions captiveportal; do
    p="$NFW/$d"
    [ -d "$p" ] || continue
    chown root:nfw "$p"
    chmod 0750 "$p"
done

# Captive portal needs write access for the www-data:nfw portal service
if [ -d "$NFW/captiveportal" ]; then
    chmod 0770 "$NFW/captiveportal"
fi
