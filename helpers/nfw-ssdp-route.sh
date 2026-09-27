#!/usr/bin/env bash
CONFIG=/var/lib/nfw/config/staging.json
[ -f "$CONFIG" ] || CONFIG=/var/lib/nfw/config/active.json
[ -f "$CONFIG" ] || exit 0
LAN=$(python3 -c "import json,sys;c=json.load(open('$CONFIG'));n=c.get('network',{});r=c.get('_resolved_interfaces') or {};print(r.get('lan') or n.get('lan') or '')" 2>/dev/null)
[ "$LAN" = "auto" ] && LAN=""
if [ -z "$LAN" ]; then
    LAN=$(python3 -c "import sys;sys.path.insert(0,'/opt/nfw');sys.path.insert(0,'/opt/nfw/core');from modules.network.interfaces import auto_assign;print(auto_assign().get('lan',''))" 2>/dev/null)
fi
[ -z "$LAN" ] && { echo "ssdp: no LAN iface"; exit 0; }
ip link show "$LAN" >/dev/null 2>&1 || { echo "ssdp: $LAN missing"; exit 0; }
ip route replace 239.255.255.250/32 dev "$LAN"
echo "ssdp: route on $LAN"
