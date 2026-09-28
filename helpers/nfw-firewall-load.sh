#!/bin/bash
# Load /etc/nftables.conf at boot.
#
# Runs before nfw-configd starts so the box isn't briefly exposed with no
# firewall. Silent no-op if the file is missing or the tables are already
# loaded (configd applies them on its own when a change is committed).
set -uo pipefail

[ -r /etc/nftables.conf ] || exit 0

# If nfw_filter is already loaded (e.g. systemd re-starting this unit),
# don't clobber it — a full re-apply could drop active connections.
if nft list table inet nfw_filter >/dev/null 2>&1; then
    exit 0
fi

# Load the ruleset. Errors here are fatal — we'd rather fail loudly than
# boot without a firewall.
if ! nft -f /etc/nftables.conf; then
    echo "nfw-firewall-load: nft -f failed" >&2
    exit 1
fi

exit 0
