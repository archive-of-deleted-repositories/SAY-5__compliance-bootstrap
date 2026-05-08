#!/usr/bin/env bash
# bootstrap-debian.sh — idempotent provisioning for Debian/Ubuntu hosts.
#
# Re-running produces no further change. Designed to be safe to invoke
# from cloud-init's `runcmd:` block on a freshly-imaged VM.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root" >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive

REQUIRED_PACKAGES=(
    auditd
    libpam-pwquality
    openssh-server
    ufw
    unattended-upgrades
)

UNWANTED_PACKAGES=(
    rsh-client
    rsh-server
    talk
    talkd
    telnet
    telnetd
)

echo "[1/4] apt-get update"
apt-get update -y

echo "[2/4] installing required packages"
apt-get install -y --no-install-recommends "${REQUIRED_PACKAGES[@]}"

echo "[3/4] purging unwanted packages"
to_purge=()
for pkg in "${UNWANTED_PACKAGES[@]}"; do
    if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed'; then
        to_purge+=("$pkg")
    fi
done
if [ "${#to_purge[@]}" -gt 0 ]; then
    apt-get purge -y "${to_purge[@]}"
fi

echo "[4/4] enabling unattended-upgrades"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

echo "bootstrap-debian.sh complete"
