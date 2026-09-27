#!/bin/bash
# NFW — Next Firewall — installer
# Pi-hole style: interactive with auto-detected defaults.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/Moonmaker5420/NFW/main/install.sh | sudo bash
#   NFW_SOURCE=/path/to/tree sudo bash install.sh   # local dev
#   NFW_REPO=https://github.com/you/NFW.git NFW_BRANCH=dev sudo bash install.sh
#
set -euo pipefail

VERSION="0.1.0"
INSTALL_DIR="/opt/nfw"
REPO_URL="${NFW_REPO:-https://github.com/Moonmaker5420/NFW.git}"
REPO_BRANCH="${NFW_BRANCH:-main}"
SOURCE_OVERRIDE="${NFW_SOURCE:-}"
LOG_FILE="/var/log/nfw-install.log"
MARKER="/var/lib/nfw/config/initialized"

red() { printf '\033[31m%s\033[0m\n' "$*"; }
grn() { printf '\033[32m%s\033[0m\n' "$*"; }
ylw() { printf '\033[33m%s\033[0m\n' "$*"; }
log() { printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$LOG_FILE" >&2; }
die() { red "FATAL: $*"; exit 1; }

# ==========================================================================
# 1. Pre-flight
# ==========================================================================
[ "$(id -u)" -eq 0 ] || die "must run as root"
[ -d /run/systemd/system ] || die "systemd required"
. /etc/os-release
case "$ID" in
    ubuntu|debian) : ;;
    *) die "unsupported distro: $ID (need ubuntu or debian)" ;;
esac
ARCH=$(dpkg --print-architecture)
case "$ARCH" in
    amd64|arm64|armhf) : ;;
    *) die "unsupported arch: $ARCH" ;;
esac
log "NFW $VERSION installer — $ID $VERSION_ID on $ARCH"

if [ -f "$MARKER" ]; then
    ylw "An NFW install already exists at $INSTALL_DIR."
    whiptail --title "NFW already installed" \
             --yesno "Reinstall / upgrade NFW in place?\n\nThis will preserve your existing config." 10 60 \
        || die "aborted by user"
fi

# ==========================================================================
# 2. Dependencies
# ==========================================================================
export DEBIAN_FRONTEND=noninteractive
log "installing system dependencies..."
apt-get update -qq
apt-get install -y -qq \
    python3 python3-venv python3-pip \
    nftables openssl chrony jq whiptail socat \
    isc-dhcp-server bind9-dnsutils conntrack \
    kmod procps psmisc curl ca-certificates \
    >/dev/null
log "dependencies installed"

# ==========================================================================
# 3. Collect config (whiptail with auto-detected defaults)
# ==========================================================================
# Enumerate physical NICs (exclude lo, veth, docker, tailscale, etc.)
NICS=$(ip -o link show | awk -F': ' '{print $2}' | grep -vE '^(lo|docker|veth|br-|virbr|tailscale|wg)' | sort)
[ -n "$NICS" ] || die "no usable network interfaces found"

NIC_MENU=()
for nic in $NICS; do
    MAC=$(cat /sys/class/net/$nic/address 2>/dev/null || echo "")
    STATE=$(cat /sys/class/net/$nic/operstate 2>/dev/null || echo "unknown")
    NIC_MENU+=("$nic" "MAC $MAC ($STATE)")
done

# Default: first NIC = WAN, second = LAN. If only one NIC, same for both with warning.
DEFAULT_WAN=$(echo "$NICS" | head -1)
DEFAULT_LAN=$(echo "$NICS" | sed -n '2p')
[ -z "$DEFAULT_LAN" ] && DEFAULT_LAN="$DEFAULT_WAN"

WAN=$(whiptail --title "WAN interface" --menu \
    "Select the WAN (internet-facing) interface:" 20 70 10 \
    "${NIC_MENU[@]}" \
    3>&1 1>&2 2>&3) || die "cancelled"

# Remove WAN from LAN options
LAN_MENU=()
for nic in $NICS; do
    [ "$nic" = "$WAN" ] && continue
    MAC=$(cat /sys/class/net/$nic/address 2>/dev/null || echo "")
    LAN_MENU+=("$nic" "MAC $MAC")
done
if [ ${#LAN_MENU[@]} -eq 0 ]; then
    ylw "Only one NIC; WAN and LAN will share $WAN. This is single-NIC mode — OK for testing, not production."
    LAN="$WAN"
else
    LAN=$(whiptail --title "LAN interface" --menu \
        "Select the LAN (internal) interface:" 20 70 10 \
        "${LAN_MENU[@]}" \
        3>&1 1>&2 2>&3) || die "cancelled"
fi

LAN_IP=$(whiptail --title "LAN IP address" --inputbox \
    "LAN interface will get this static IP (CIDR):" 10 60 \
    "192.168.10.1/24" \
    3>&1 1>&2 2>&3) || die "cancelled"

HOSTNAME=$(whiptail --title "Hostname" --inputbox \
    "System hostname:" 10 60 \
    "nfw" \
    3>&1 1>&2 2>&3) || die "cancelled"

# Generate random admin password, show it
ADMIN_PW=$(openssl rand -base64 12)
whiptail --title "Admin password" --msgbox \
    "Generated admin password:\n\n    $ADMIN_PW\n\nWrite this down. You'll use it to log in at\nhttps://${LAN_IP%/*}:8443" 14 60

# Confirm
whiptail --title "Confirm installation" --yesno \
"NFW will be installed with:

  WAN interface:  $WAN
  LAN interface:  $LAN
  LAN IP:         $LAN_IP
  Hostname:       $HOSTNAME
  Admin user:     admin
  Admin password: (shown above)

Install location: $INSTALL_DIR
Log file:         $LOG_FILE

Proceed?" 18 70 || die "aborted by user"

# ==========================================================================
# 4. Fetch source
# ==========================================================================
log "fetching NFW source..."
if [ -n "$SOURCE_OVERRIDE" ]; then
    [ -d "$SOURCE_OVERRIDE" ] || die "NFW_SOURCE=$SOURCE_OVERRIDE is not a directory"
    log "using local source: $SOURCE_OVERRIDE"
    mkdir -p "$INSTALL_DIR"
    rsync -a --delete \
        --exclude='.git' --exclude='venv' --exclude='__pycache__' \
        "$SOURCE_OVERRIDE/" "$INSTALL_DIR/"
else
    command -v git >/dev/null || apt-get install -y -qq git
    if [ -d "$INSTALL_DIR/.git" ]; then
        log "updating existing git checkout"
        git -C "$INSTALL_DIR" fetch origin "$REPO_BRANCH"
        git -C "$INSTALL_DIR" reset --hard "origin/$REPO_BRANCH"
    else
        # Preserve existing venv/wheels if present
        if [ -d "$INSTALL_DIR" ] && [ -n "$(ls -A "$INSTALL_DIR" 2>/dev/null)" ]; then
            log "backing up existing $INSTALL_DIR -> ${INSTALL_DIR}.bak.$(date +%s)"
            mv "$INSTALL_DIR" "${INSTALL_DIR}.bak.$(date +%s)"
        fi
        git clone --branch "$REPO_BRANCH" --depth 1 "$REPO_URL" "$INSTALL_DIR"
    fi
fi

[ -d "$INSTALL_DIR/core" ] || die "source fetch failed: $INSTALL_DIR/core missing"
[ -d "$INSTALL_DIR/wheels" ] || die "source fetch failed: $INSTALL_DIR/wheels missing"
log "source ready at $INSTALL_DIR"

# ==========================================================================
# 5. Users, groups, directories, permissions
# ==========================================================================
log "creating nfw user and directories..."

getent group nfw >/dev/null || groupadd -r nfw
id -u nfw >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin -g nfw -d /var/lib/nfw nfw
usermod -aG nfw www-data 2>/dev/null || true

# /var/lib/nfw: root:nfw 0750
mkdir -p /var/lib/nfw/{config/revisions,captiveportal,shaper,aliases,geoip,rrd,pcap,ca}
chown root:nfw /var/lib/nfw
chmod 0750     /var/lib/nfw
for d in config captiveportal shaper aliases geoip rrd pcap ca; do
    [ -d "/var/lib/nfw/$d" ] && chown -R root:nfw "/var/lib/nfw/$d"
done

# /etc/nfw
mkdir -p /etc/nfw
chmod 0750 /etc/nfw
chown root:nfw /etc/nfw

# /var/log/nfw
mkdir -p /var/log/nfw
chown root:nfw /var/log/nfw
chmod 0750 /var/log/nfw

# /run/nfw (transient)
mkdir -p /run/nfw
chown root:nfw /run/nfw
chmod 0750 /run/nfw

# /opt/nfw ownership (code dir)
chown -R root:root "$INSTALL_DIR"
chmod 0755 "$INSTALL_DIR"

# ==========================================================================
# 6. Deploy systemd units + helper scripts
# ==========================================================================
log "deploying systemd units and helpers..."

# Copy helpers
if [ -d "$INSTALL_DIR/helpers" ]; then
    for f in "$INSTALL_DIR/helpers"/nfw-*; do
        [ -f "$f" ] || continue
        install -m 0755 "$f" /usr/local/sbin/
    done
fi

# Copy units
if [ -d "$INSTALL_DIR/systemd" ]; then
    for f in "$INSTALL_DIR/systemd"/nfw-*.service \
             "$INSTALL_DIR/systemd"/nfw-*.timer; do
        [ -f "$f" ] || continue
        install -m 0644 "$f" /etc/systemd/system/
    done
    # Drop-ins
    if [ -d "$INSTALL_DIR/systemd/nfw-api.service.d" ]; then
        mkdir -p /etc/systemd/system/nfw-api.service.d
        cp -a "$INSTALL_DIR/systemd/nfw-api.service.d/." \
              /etc/systemd/system/nfw-api.service.d/
    fi
fi

systemctl daemon-reload

# ==========================================================================
# 7. Build venv from bundled wheels
# ==========================================================================
log "building /opt/nfw/venv from bundled wheels (this may take ~60s)..."
rm -rf "$INSTALL_DIR/venv"
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip wheel

if [ "$(ls -1 "$INSTALL_DIR/wheels"/*.whl 2>/dev/null | wc -l)" -gt 0 ]; then
    "$INSTALL_DIR/venv/bin/pip" install --quiet --no-index \
        --find-links="$INSTALL_DIR/wheels" \
        fastapi 'uvicorn[standard]' jinja2 python-multipart \
        itsdangerous pyjwt pyotp 'qrcode[pil]' pillow \
        cryptography bcrypt pyyaml httpx websockets pyrad
    log "venv built: $(du -sh "$INSTALL_DIR/venv" | cut -f1)"
else
    die "no wheels found at $INSTALL_DIR/wheels — cannot build offline venv"
fi

# pyrad for system python3 (configd RADIUS actions)
if ! python3 -c 'import pyrad' 2>/dev/null; then
    log "installing pyrad for system python3..."
    python3 -m pip install --quiet --break-system-packages \
        --no-index --find-links="$INSTALL_DIR/wheels" pyrad || \
        ylw "pyrad install failed; RADIUS client feature will not work"
fi

# ==========================================================================
# 8. Bootstrap TLS cert
# ==========================================================================
BOOTSTRAP_DIR=/var/lib/nfw/ca/bootstrap
if [ ! -f "$BOOTSTRAP_DIR/web.crt" ]; then
    log "generating bootstrap self-signed TLS certificate..."
    mkdir -p "$BOOTSTRAP_DIR"
    chmod 0750 "$BOOTSTRAP_DIR"
    chown root:nfw "$BOOTSTRAP_DIR"

    LAN_IP_ADDR="${LAN_IP%/*}"
    openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
        -keyout "$BOOTSTRAP_DIR/web.key" \
        -out    "$BOOTSTRAP_DIR/web.crt" \
        -subj   "/CN=NFW/O=Next Firewall/OU=self-signed" \
        -addext "subjectAltName=DNS:nfw.local,DNS:localhost,IP:127.0.0.1,IP:$LAN_IP_ADDR" \
        -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
        -addext "extendedKeyUsage=serverAuth" \
        >/dev/null 2>&1
    chmod 0600 "$BOOTSTRAP_DIR/web.key"
    chmod 0644 "$BOOTSTRAP_DIR/web.crt"
    chown root:root "$BOOTSTRAP_DIR/web.key"
    chown root:nfw  "$BOOTSTRAP_DIR/web.crt"
fi

# ==========================================================================
# 9. Initial config
# ==========================================================================
log "writing initial config..."

LAN_IP_ADDR="${LAN_IP%/*}"
LAN_PREFIX="${LAN_IP#*/}"

NOW_TS=$(date +%s)
REV="$(date -u +%Y%m%dT%H%M%SZ)-install"

python3 - "$REV" "$LAN_IP_ADDR" "$LAN_PREFIX" "$WAN" "$LAN" "$HOSTNAME" <<'PY'
import json, sys, os
rev, lan_ip, lan_plen, wan, lan, hostname = sys.argv[1:7]

cfg = {
    "version": 1,
    "system": {
        "hostname": hostname,
        "domain": "lan",
        "timezone": "UTC",
        "admin_email": "",
    },
    "network": {
        "wan": wan,
        "lan": lan,
        "opt": [],
        "interfaces": {
            wan: {"ipv4": {"mode": "dhcp"}, "ipv6": {"mode": "auto"}},
            lan: {"ipv4": {"mode": "static", "address": lan_ip,
                            "prefixlen": int(lan_plen)},
                  "ipv6": {"mode": "none"}},
        },
    },
    "firewall": {
        "rules": [],
        "aliases": [],
        "nat": {"port_forwards": [], "outbound": [], "one_to_one": [],
                "npt": [], "reflection": {"enabled": False}},
        "schedules": [],
        "normalization": {"items": []},
        "settings": {},
    },
    "services": {
        "captiveportal_config": {"enabled": False},
    },
    "auth": {
        "providers": [
            {"type": "local",  "enabled": True},
            {"type": "ldap",   "enabled": False},
            {"type": "radius", "enabled": False},
            {"type": "oauth",  "enabled": False},
        ],
        "acls": {"enabled": False, "roles": {}, "users": {}},
    },
}

rev_path = f"/var/lib/nfw/config/revisions/{rev}.json"
with open(rev_path, "w") as f:
    json.dump(cfg, f, indent=2, sort_keys=True)
with open("/var/lib/nfw/config/active.json", "w") as f:
    json.dump({"revision": rev, "ts": int(os.times().elapsed)}, f, indent=2)

# Meta
with open(f"/var/lib/nfw/config/revisions/{rev}.meta", "w") as f:
    json.dump({"revision": rev, "ts": 0, "author": "installer",
                "message": "initial install"}, f, indent=2)

print(f"config revision: {rev}")
PY

chown -R root:nfw /var/lib/nfw/config
chmod -R 0750     /var/lib/nfw/config

# ==========================================================================
# 10. Admin user
# ==========================================================================
log "creating admin user..."
python3 - "$ADMIN_PW" <<'PY'
import bcrypt, json, sys, os
pw = sys.argv[1]
h = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
users = {
    "admin": {
        "password_hash": h,
        "role": "admin",
        "totp_enabled": False,
        "created_at": 0,
    }
}
path = "/etc/nfw/users.json"
with open(path, "w") as f:
    json.dump(users, f, indent=2)
os.chmod(path, 0o600)
PY
chown root:nfw /etc/nfw/users.json

# ==========================================================================
# 11. Enable + start
# ==========================================================================
log "enabling and starting services..."

# Mask services that don't belong
for svc in nftables.service unbound.service suricata.service; do
    systemctl mask "$svc" 2>/dev/null || true
done

systemctl enable nfw-configd.service  >/dev/null 2>&1 || true
systemctl enable nfw-api.service      >/dev/null 2>&1 || true
systemctl enable nfw-portal.service   >/dev/null 2>&1 || true
systemctl enable nfw-sysctl.service   >/dev/null 2>&1 || true
systemctl enable nfw-fix-ca-perms.service >/dev/null 2>&1 || true

for t in nfw-alias-refresh nfw-ca-autorenew nfw-cp-bypass-refresh \
         nfw-cp-bytes nfw-geoip-update nfw-rrd-collector nfw-schedule-refresh; do
    systemctl enable "${t}.timer" >/dev/null 2>&1 || true
done

systemctl start nfw-configd.service
sleep 3
systemctl start nfw-api.service
systemctl start nfw-portal.service
sleep 3

# ==========================================================================
# 12. Marker + summary
# ==========================================================================
touch "$MARKER"
chown root:nfw "$MARKER" 2>/dev/null || true

API_STATE=$(systemctl is-active nfw-api 2>/dev/null || echo "unknown")
PORTAL_STATE=$(systemctl is-active nfw-portal 2>/dev/null || echo "unknown")
CD_STATE=$(systemctl is-active nfw-configd 2>/dev/null || echo "unknown")

# HTTPS cert check
HTTPS_OK="no"
if [ "$API_STATE" = "active" ]; then
    if curl -sk --max-time 5 "https://127.0.0.1:8443/api/health" | grep -q '"ok"'; then
        HTTPS_OK="yes"
    fi
fi

clear
grn "==============================================================="
grn "  NFW $VERSION installed successfully"
grn "==============================================================="
echo
echo "  Web GUI:      https://${LAN_IP_ADDR}:8443"
echo "  Username:     admin"
echo "  Password:     $ADMIN_PW"
echo
echo "  Service state:"
echo "    nfw-configd   $CD_STATE"
echo "    nfw-api       $API_STATE"
echo "    nfw-portal    $PORTAL_STATE"
echo "    HTTPS health: $HTTPS_OK"
echo
echo "  Log file:     $LOG_FILE"
echo "  Install dir:  $INSTALL_DIR"
echo
echo "  Your browser will warn about the self-signed certificate."
echo "  This is expected — accept and continue."
echo
grn "==============================================================="
