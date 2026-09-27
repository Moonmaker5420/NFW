#!/bin/bash
# NFW verification — report PASS/FAIL per check
set -uo pipefail

PW="${1:-1eM246gNKeyjA0Vj}"
BASE="https://127.0.0.1:8443"
JAR=/tmp/nfw-verify.jar
PASS=0; FAIL=0

check() {
    local name="$1"; shift
    if "$@" >/dev/null 2>&1; then
        printf '  \033[32mPASS\033[0m  %s\n' "$name"
        PASS=$((PASS+1))
    else
        printf '  \033[31mFAIL\033[0m  %s\n' "$name"
        FAIL=$((FAIL+1))
    fi
}

api() {
    local path="$1"
    curl -sk -L -b "$JAR" -o /tmp/nfw-r.json -w '%{http_code}' "$BASE$path" \
        | grep -q '^200$' && python3 -c 'import json; json.load(open("/tmp/nfw-r.json"))' 2>/dev/null
}

echo "=============================================================="
echo "  NFW verification — $(date -u +%FT%TZ)"
echo "=============================================================="

echo "Services:"
check "nfw-configd active"     systemctl is-active nfw-configd
check "nfw-api active"         systemctl is-active nfw-api
check "nfw-portal active"      systemctl is-active nfw-portal

echo "Timers:"
for t in nfw-alias-refresh nfw-ca-autorenew nfw-cp-bypass-refresh \
         nfw-cp-bytes nfw-geoip-update nfw-rrd-collector nfw-schedule-refresh; do
    check "$t.timer active" systemctl is-active "$t.timer"
done

echo "Listeners:"
check ":8443 listening"  bash -c "ss -tln | grep -q ':8443'"
check ":8081 listening"  bash -c "ss -tln | grep -q ':8081'"

echo "State:"
check "/var/lib/nfw writable"        test -w /var/lib/nfw
check "users.json exists"            test -f /etc/nfw/users.json
check "secret.key exists"            test -f /etc/nfw/secret.key
check "bootstrap cert exists"        test -f /var/lib/nfw/ca/bootstrap/web.crt
check "rrd dir populated"            bash -c "ls /var/lib/nfw/rrd/*.rrd 2>/dev/null | head -1 | grep -q ."

echo "Auth:"
if curl -sk -c "$JAR" -X POST "$BASE/api/auth/login" \
        -H 'Content-Type: application/json' \
        -d "{\"username\":\"admin\",\"password\":\"$PW\"}" \
        -o /tmp/nfw-r.json -w '%{http_code}' | grep -q '^200$'; then
    printf '  \033[32mPASS\033[0m  login\n'; PASS=$((PASS+1))
else
    printf '  \033[31mFAIL\033[0m  login\n'; FAIL=$((FAIL+1))
fi

echo "API endpoints:"
check "GET /api/health"              api /api/health
check "GET /api/config"              api /api/config
check "GET /api/network/ifaces"      api /api/network/ifaces
check "GET /api/firewall/rules"      api /api/firewall/rules
check "GET /api/firewall/aliases"    api /api/firewall/aliases
check "GET /api/firewall/schedules"  api /api/firewall/schedules
check "GET /api/services/dhcp"       api /api/services/dhcp
check "GET /api/services/dns"        api /api/services/dns
check "GET /api/services/ntp"        api /api/services/ntp
check "GET /api/services/captiveportal/status" api /api/services/captiveportal/status
check "GET /api/services/captiveportal/sessions" api /api/services/captiveportal/sessions
check "GET /api/services/captiveportal/vouchers" api /api/services/captiveportal/vouchers
check "GET /api/system/interfaces"   api /api/system/interfaces
check "GET /api/users"               api /api/users
check "GET /api/ca/expiring"         api /api/ca/expiring
check "GET /api/reporting/graphs"    api /api/reporting/graphs
check "GET /api/gateways"            api /api/gateways

echo "Kernel:"
check "nft nfw_filter loaded"        bash -c "nft list table inet nfw_filter >/dev/null 2>&1"
check "nft nfw_nat loaded"           bash -c "nft list table ip nfw_nat >/dev/null 2>&1"
check "nftables.conf has NFW rules"  bash -c "grep -q 'NFW ruleset' /etc/nftables.conf"

echo "RRD:"
check "rrdtool binary present"       test -x /usr/bin/rrdtool
check "rrd collector ran"            bash -c "test -f /var/lib/nfw/rrd/system.rrd"

echo "Portal:"
check "portal login page reachable"  bash -c "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8081/ | grep -q '^200$'"
check "CPD handler redirects unauth" bash -c "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8081/hotspot-detect.html | grep -q '302'"

echo "=============================================================="
printf "  PASS: \033[32m%d\033[0m   FAIL: \033[31m%d\033[0m\n" "$PASS" "$FAIL"
echo "=============================================================="
