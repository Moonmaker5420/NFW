#!/usr/bin/env bash
#
# Called every minute by nfw-schedule-refresh.timer. Determines which
# schedules are active now. If the set changed since the last tick,
# recompiles + applies the firewall so rules referencing the schedule
# take effect immediately.

CONFIG=/var/lib/nfw/config/staging.json
[ -f "$CONFIG" ] || CONFIG=/var/lib/nfw/config/active.json
[ -f "$CONFIG" ] || exit 0

ACTIVE=$(python3 -c "
import json, datetime, sys
try:
    cfg = json.load(open('$CONFIG'))
except Exception:
    sys.exit(0)
now = datetime.datetime.now()
day = ['mon','tue','wed','thu','fri','sat','sun'][now.weekday()]
hhmm = now.strftime('%H:%M')
active = []
for s in cfg.get('firewall', {}).get('schedules', []) or []:
    if not s.get('enabled', True): continue
    for r in s.get('ranges', []) or []:
        days = r.get('days', [])
        if days and day not in days: continue
        if r.get('start', '00:00') <= hhmm <= r.get('end', '23:59'):
            active.append(s.get('name', ''))
            break
print(','.join(sorted(active)))
")

MARKER=/var/lib/nfw/schedules.active
LAST=$(cat "$MARKER" 2>/dev/null || echo "")
if [ "$ACTIVE" = "$LAST" ]; then
    exit 0
fi
echo "$ACTIVE" > "$MARKER"

# Trigger a firewall recompile+apply via the configd socket
python3 -c "
import json, socket, sys
req = {'action': 'firewall.apply_staged', 'data': {}}
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect('/run/nfw/configd.sock')
    s.sendall((json.dumps(req) + '\n').encode())
    data = b''
    while not data.endswith(b'\n'):
        chunk = s.recv(4096)
        if not chunk: break
        data += chunk
    sys.stderr.write('sched-refresh: ' + data.decode()[:200] + '\n')
except Exception as e:
    sys.stderr.write(f'sched-refresh: {e}\n')
"
