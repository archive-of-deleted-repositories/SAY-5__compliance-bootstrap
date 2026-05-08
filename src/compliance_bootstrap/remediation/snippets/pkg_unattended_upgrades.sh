#!/usr/bin/env bash
# summary: Enable apt unattended-upgrades via 20auto-upgrades
set -euo pipefail

if ! command -v apt-get >/dev/null 2>&1; then
    echo "apt not present; nothing to do on non-Debian systems"
    exit 0
fi

if ! dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -q 'install ok installed'; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades
fi

DEST="/etc/apt/apt.conf.d/20auto-upgrades"
cat > "$DEST" <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
echo "wrote $DEST"
