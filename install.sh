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

NFW_VERSION="0.1.0"
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
# Shared — re-assert known file permissions
# ==========================================================================
nfw_enforce_perms() {
    [ -d /etc/nfw ] && chown root:nfw /etc/nfw && chmod 0750 /etc/nfw
    [ -f /etc/nfw/secret.key ] && chown root:nfw /etc/nfw/secret.key && chmod 0640 /etc/nfw/secret.key
    [ -f /etc/nfw/users.json ] && chown root:nfw /etc/nfw/users.json && chmod 0640 /etc/nfw/users.json
    [ -d /var/lib/nfw ] && chown root:nfw /var/lib/nfw && chmod 0750 /var/lib/nfw
    return 0
}

# ==========================================================================
# Upgrade helpers — backup / rollback
# ==========================================================================
NFW_DATA_PATHS=(
    "/var/lib/nfw/config"
    "/var/lib/nfw/ca"
    "/var/lib/nfw/captiveportal"
    "/var/lib/nfw/aliases"
    "/var/lib/nfw/geoip"
    "/etc/nfw/users.json"
    "/etc/nfw/secret.key"
)

NFW_CODE_PATHS=(
    "core"
    "modules"
    "web"
    "systemd"
    "helpers"
    "wheels"
)

_nfw_service_state() {
    for u in nfw-configd nfw-api nfw-portal; do
        printf "%s=%s\n" "$u" "$(systemctl is-active "$u" 2>/dev/null || echo inactive)"
    done
}

nfw_backup() {
    local src_version="$1"
    local ts
    ts="$(date -u +%Y%m%dT%H%M%SZ)"
    local bdir="$INSTALL_DIR/.backups/$ts"
    log "backing up to $bdir"
    mkdir -p "$bdir"

    # Config / data (small)
    for p in "${NFW_DATA_PATHS[@]}"; do
        if [ -e "$p" ]; then
            local rel="${p#/}"
            mkdir -p "$bdir/state/$(dirname "$rel")"
            cp -a "$p" "$bdir/state/$rel"
        fi
    done

    # Code (medium — venv excluded, rebuildable)
    mkdir -p "$bdir/code"
    for c in "${NFW_CODE_PATHS[@]}"; do
        [ -e "$INSTALL_DIR/$c" ] && cp -a "$INSTALL_DIR/$c" "$bdir/code/$c"
    done

    # Metadata
    echo "$src_version" > "$bdir/VERSION"
    _nfw_service_state > "$bdir/services.state"
    date -u +%FT%TZ > "$bdir/timestamp"
    echo "$bdir"
}

nfw_rollback() {
    local bdir="$1"
    [ -d "$bdir" ] || { red "rollback: $bdir missing"; return 1; }
    ylw "Rolling back from $bdir..."

    systemctl stop nfw-api nfw-portal 2>/dev/null || true
    systemctl stop nfw-configd 2>/dev/null || true

    # Restore code
    for c in "${NFW_CODE_PATHS[@]}"; do
        if [ -d "$bdir/code/$c" ]; then
            rm -rf "$INSTALL_DIR/$c"
            cp -a "$bdir/code/$c" "$INSTALL_DIR/$c"
        fi
    done

    # Restore config / data
    if [ -d "$bdir/state" ]; then
        for p in "${NFW_DATA_PATHS[@]}"; do
            local rel="${p#/}"
            if [ -e "$bdir/state/$rel" ]; then
                rm -rf "$p"
                mkdir -p "$(dirname "$p")"
                cp -a "$bdir/state/$rel" "$p"
            fi
        done
    fi

    # Restore version marker
    [ -f "$bdir/VERSION" ] && cp "$bdir/VERSION" "$INSTALL_DIR/VERSION"

    # Rebuild venv (new wheel set may be incompatible with old code)
    if [ -d "$INSTALL_DIR/wheels" ]; then
        log "rollback: rebuilding venv"
        rm -rf "$INSTALL_DIR/venv"
        python3 -m venv "$INSTALL_DIR/venv"
        "$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip wheel
        "$INSTALL_DIR/venv/bin/pip" install --quiet --no-index \
            --find-links="$INSTALL_DIR/wheels" \
            fastapi 'uvicorn[standard]' jinja2 python-multipart \
            itsdangerous pyjwt pyotp 'qrcode[pil]' pillow \
            cryptography bcrypt pyyaml httpx websockets pyrad
    fi

    # Re-assert sensitive file permissions. cp -a from the backup may
    # restore root:root if the backup captured pre-existing bad perms.
    nfw_enforce_perms

    systemctl daemon-reload
    systemctl start nfw-configd
    sleep 3
    systemctl start nfw-api nfw-portal
    sleep 3

    red "Rollback complete. System is at previous version."
    return 0
}

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
log "NFW $NFW_VERSION installer — $ID $VERSION_ID on $ARCH"

# ==========================================================================
# 0. Mode detection — fresh / upgrade / reinstall / same
# ==========================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
SOURCE_VERSION=""
if [ -n "${NFW_SOURCE:-}" ] && [ -f "$NFW_SOURCE/VERSION" ]; then
    SOURCE_VERSION="$(cat "$NFW_SOURCE/VERSION")"
    log "source version from NFW_SOURCE/VERSION"
elif [ -f "$SCRIPT_DIR/VERSION" ]; then
    SOURCE_VERSION="$(cat "$SCRIPT_DIR/VERSION")"
    log "source version from script VERSION file"
elif [ -n "${NFW_VERSION:-}" ]; then
    SOURCE_VERSION="$NFW_VERSION"
    log "source version from embedded default"
else
    SOURCE_VERSION="0.1.0"
fi
log "SOURCE_VERSION=$SOURCE_VERSION"

INSTALLED_VERSION=""
if [ -f "$INSTALL_DIR/VERSION" ]; then
    INSTALLED_VERSION="$(cat "$INSTALL_DIR/VERSION" 2>/dev/null || echo '')"
fi

MODE_REQUESTED=""
FORCE=0
DRY_RUN=0
NONINTERACTIVE="${NFW_NONINTERACTIVE:-0}"
[ "${NFW_FORCE:-0}" = "1" ] && FORCE=1

for arg in "$@"; do
    case "$arg" in
        --upgrade)   MODE_REQUESTED="upgrade" ;;
        --reinstall) MODE_REQUESTED="reinstall" ;;
        --force)     FORCE=1 ;;
        --dry-run)   DRY_RUN=1 ;;
        -y|--yes)    NONINTERACTIVE=1 ;;
        -h|--help)
            cat <<HELPEOF
Usage: install.sh [--upgrade|--reinstall] [--force] [--dry-run] [-y]

  (no args)      fresh install, or auto-detected upgrade
  --upgrade      require existing install, upgrade it
  --reinstall    require existing install, reinstall same version
  --force        overwrite even if versions match
  --dry-run      print plan, don't do anything
  -y             non-interactive (skip confirmations)

Env:
  NFW_SOURCE=/path           install from a local tree
  NFW_REPO=https://...       override repo URL
  NFW_BRANCH=main            override branch
  NFW_FORCE=1                same as --force
  NFW_NONINTERACTIVE=1       same as -y
HELPEOF
            exit 0 ;;
        *) die "unknown argument: $arg" ;;
    esac
done

if [ -z "$INSTALLED_VERSION" ]; then
    if [ "$MODE_REQUESTED" = "upgrade" ] || [ "$MODE_REQUESTED" = "reinstall" ]; then
        die "--$MODE_REQUESTED requires an existing install at $INSTALL_DIR (none found)"
    fi
    MODE="fresh"
elif [ "$MODE_REQUESTED" = "upgrade" ] && \
     [ -n "$INSTALLED_VERSION" ] && [ "$FORCE" = "0" ] && \
     [ "$INSTALLED_VERSION" != "$SOURCE_VERSION" ] && \
     [ "$(printf '%s\n%s\n' "$SOURCE_VERSION" "$INSTALLED_VERSION" | sort -V | head -1)" = "$SOURCE_VERSION" ]; then
    die "installed version $INSTALLED_VERSION is newer than source $SOURCE_VERSION — refusing to downgrade (use --force)"
elif [ "$INSTALLED_VERSION" = "$SOURCE_VERSION" ] && [ "$FORCE" = "0" ]; then
    if [ "$MODE_REQUESTED" = "upgrade" ]; then
        die "already at version $INSTALLED_VERSION — nothing to do (use --force to overwrite)"
    fi
    MODE="same"
else
    MODE="${MODE_REQUESTED:-upgrade}"
fi

log "installer: SOURCE_VERSION=$SOURCE_VERSION INSTALLED_VERSION=${INSTALLED_VERSION:-none} MODE=$MODE DRY_RUN=$DRY_RUN FORCE=$FORCE"

if [ "$MODE" = "same" ]; then
    grn "NFW is already at $INSTALLED_VERSION. Nothing to do."
    exit 0
fi

case "$MODE" in
    upgrade)   grn "Upgrade: $INSTALLED_VERSION → $SOURCE_VERSION" ;;
    reinstall) grn "Reinstall: $INSTALLED_VERSION (forced)" ;;
    fresh)     grn "Fresh install: $SOURCE_VERSION" ;;
esac

if [ "$DRY_RUN" = "1" ]; then
    ylw "Dry-run — no changes made."
    exit 0
fi


# (existing-install detection handled in §0 below)


# ==========================================================================
# 2. Dependencies
# ==========================================================================
export DEBIAN_FRONTEND=noninteractive
log "installing system dependencies..."
apt-get update -qq
apt-get install -y -qq \
    python3 python3-venv python3-pip python3-bcrypt rsync \
    nftables rrdtool openssl chrony jq whiptail socat \
    isc-dhcp-server bind9-dnsutils conntrack \
    kmod procps psmisc curl ca-certificates \
    >/dev/null
log "dependencies installed"

# Section 3 skipped on upgrade (existing config preserved)
if [ "$MODE" = "fresh" ]; then
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


fi  # fresh-only: whiptail config

# ==========================================================================
# 4. Upgrade: backup current state BEFORE replacing code
# ==========================================================================
BACKUP_DIR=""
if [ "$MODE" = "upgrade" ] || [ "$MODE" = "reinstall" ]; then
    BACKUP_DIR="$(nfw_backup "$INSTALLED_VERSION")"
    log "backup complete: $BACKUP_DIR"
    # Stop services so code can be replaced safely
    systemctl stop nfw-api nfw-portal 2>/dev/null || true
    systemctl stop nfw-configd 2>/dev/null || true
    log "services stopped for upgrade"
fi

# ==========================================================================
# 4b. Fetch source
# ==========================================================================
log "fetching NFW source..."
if [ -n "$SOURCE_OVERRIDE" ]; then
    [ -d "$SOURCE_OVERRIDE" ] || die "NFW_SOURCE=$SOURCE_OVERRIDE is not a directory"
    log "using local source: $SOURCE_OVERRIDE"
    mkdir -p "$INSTALL_DIR"
    # Pre-flight: verify the source tree has the expected shape BEFORE
    # we rsync --delete it over the live install. Bad source = data loss.
    for d in core modules web wheels; do
        [ -d "$SOURCE_OVERRIDE/$d" ] || \
            die "NFW_SOURCE=$SOURCE_OVERRIDE missing required directory: $d"
    done
    [ -f "$SOURCE_OVERRIDE/install.sh" ] || \
        die "NFW_SOURCE=$SOURCE_OVERRIDE missing install.sh"
    [ -f "$SOURCE_OVERRIDE/VERSION" ] || \
        die "NFW_SOURCE=$SOURCE_OVERRIDE missing VERSION — refusing to sync"
    log "source tree structure verified"

    rsync -a --delete \
        --exclude='.git' --exclude='venv' --exclude='__pycache__' \
        --exclude='.backups' \
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

# Re-assert sensitive file permissions (secret.key, users.json, etc.)
nfw_enforce_perms

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

# API cookie-signing key. Generate NOW so the API only ever reads it.
# Inside the service sandbox, /etc is read-only (ProtectSystem=full),
# so if this is missing when nfw-api starts, the API can't create it.
if [ ! -f /etc/nfw/secret.key ]; then
    log "generating API session secret..."
    dd if=/dev/urandom of=/etc/nfw/secret.key bs=32 count=1 2>/dev/null
    chown root:nfw /etc/nfw/secret.key
    chmod 0640 /etc/nfw/secret.key
fi
nfw_enforce_perms

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

# Sections 9+10 skipped on upgrade (existing config preserved)
if [ "$MODE" = "fresh" ]; then
# ==========================================================================
# 9. Initial config
# ==========================================================================
log "writing initial config..."

LAN_IP_ADDR="${LAN_IP%/*}"
LAN_PREFIX="${LAN_IP#*/}"

NOW_TS=$(date +%s)
REV="$(date -u +%Y%m%dT%H%M%SZ)-install"

python3 - "$REV" "$LAN_IP_ADDR" "$LAN_PREFIX" "$WAN" "$LAN" "$HOSTNAME" <<'PY'
import json, sys, os, time
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
    json.dump({"revision": rev, "ts": int(time.time())}, f, indent=2)

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
        "hash": h,
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


fi  # fresh-only: initial config + admin user

if [ "$MODE" = "fresh" ]; then
# ==========================================================================
# 10b. Mark setup as pending (checked by API wizard gate)
# ==========================================================================
touch /var/lib/nfw/config/setup_pending
chown root:nfw /var/lib/nfw/config/setup_pending 2>/dev/null || true
chmod 0644 /var/lib/nfw/config/setup_pending
log "setup marker written: /var/lib/nfw/config/setup_pending"
fi  # fresh-only: setup marker


# ==========================================================================
# 11. Enable + start
# ==========================================================================
log "enabling and starting services..."

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
    systemctl enable --now "${t}.timer" >/dev/null 2>&1 || true
done

systemctl start nfw-configd.service
sleep 3
systemctl start nfw-api.service
systemctl start nfw-portal.service
sleep 5

# Firewall apply (fresh install; upgrade already has it)
if [ "$MODE" = "fresh" ]; then
    log "applying initial firewall ruleset..."
    python3 - <<'PYFW'
import json, socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(60)
try:
    s.connect('/run/nfw/configd.sock')
    s.sendall((json.dumps({'action': 'firewall.apply_staged', 'data': {}}) + '\n').encode())
    buf = b''
    while not buf.endswith(b'\n'):
        c = s.recv(4096)
        if not c:
            break
        buf += c
    r = json.loads(buf)
    print('firewall:', 'ok' if r.get('ok') else r.get('error'))
except Exception as e:
    print('firewall error:', e)
PYFW
fi

# ==========================================================================
# 11b. Upgrade health check — rollback if anything is broken
# ==========================================================================
if [ "$MODE" = "upgrade" ] || [ "$MODE" = "reinstall" ]; then
    log "health check after upgrade..."
    HEALTH_OK=0
    for attempt in $(seq 1 15); do
        HEALTH_OK=1
        for u in nfw-configd nfw-api nfw-portal; do
            state="$(systemctl is-active "$u" 2>/dev/null || echo inactive)"
            if [ "$state" != "active" ]; then
                HEALTH_OK=0
                break
            fi
        done
        if [ "$HEALTH_OK" = "1" ]; then
            if curl -sk --max-time 5 https://127.0.0.1:8443/api/health \
                    | grep -q '"ok"'; then
                break
            else
                HEALTH_OK=0
            fi
        fi
        [ "$attempt" = "15" ] && break
        log "health check: attempt $attempt/15 — waiting..."
        sleep 2
    done
    if [ "$HEALTH_OK" != "1" ]; then
        ylw "health check failed after 30s:"
        for u in nfw-configd nfw-api nfw-portal; do
            ylw "  $u = $(systemctl is-active "$u" 2>/dev/null || echo inactive)"
        done
    fi
    if [ "$HEALTH_OK" = "0" ] && [ -n "$BACKUP_DIR" ]; then
        red "Health check failed — rolling back"
        nfw_rollback "$BACKUP_DIR" || true
        die "upgrade failed; rollback attempted"
    fi
    log "health check passed"
fi

# ==========================================================================
# 12. Marker + summary
# ==========================================================================
# Legacy initialized marker — fresh only.
if [ "$MODE" = "fresh" ]; then
    touch "$MARKER"
    chown root:nfw "$MARKER" 2>/dev/null || true
fi
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
if [ "$MODE" = "fresh" ]; then
    grn "==============================================================="
    grn "  NFW $NFW_VERSION installed successfully"
    grn "==============================================================="
    echo
    echo "  Web GUI:      https://${LAN_IP_ADDR:-<lan-ip>}:8443"
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
else
    grn "==============================================================="
    grn "  NFW upgraded: $INSTALLED_VERSION → $SOURCE_VERSION"
    grn "==============================================================="
    echo
    echo "  Service state:"
    echo "    nfw-configd   $CD_STATE"
    echo "    nfw-api       $API_STATE"
    echo "    nfw-portal    $PORTAL_STATE"
    echo "    HTTPS health: $HTTPS_OK"
    echo
    echo "  Config preserved in place. Existing password unchanged."
    echo "  Backup:       $BACKUP_DIR"
    echo "  Log file:     $LOG_FILE"
    echo
    grn "==============================================================="
fi
