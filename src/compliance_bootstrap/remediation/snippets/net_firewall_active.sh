#!/usr/bin/env bash
# summary: Install ufw, allow SSH, and enable the firewall
set -euo pipefail

if ! command -v ufw >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y ufw
    else
        echo "ufw not available and not on Debian/Ubuntu; configure nftables manually"
        exit 1
    fi
fi

# Pre-allow SSH so enabling the firewall does not lock us out.
ufw allow OpenSSH 2>/dev/null || ufw allow 22/tcp
yes | ufw enable >/dev/null 2>&1 || ufw --force enable

CFG="/etc/ufw/ufw.conf"
if grep -qE '^ENABLED=' "$CFG"; then
    sed -i -E 's/^ENABLED=.*/ENABLED=yes/' "$CFG"
fi
echo "ufw enabled"
