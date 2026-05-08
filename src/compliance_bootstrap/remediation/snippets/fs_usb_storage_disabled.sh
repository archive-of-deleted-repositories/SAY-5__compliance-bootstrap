#!/usr/bin/env bash
# summary: Blacklist the usb-storage kernel module via /etc/modprobe.d
set -euo pipefail

DEST="/etc/modprobe.d/cis-usb-storage.conf"
mkdir -p "$(dirname "$DEST")"

if [ -f "$DEST" ] && grep -q '^install usb-storage /bin/true' "$DEST"; then
    echo "usb-storage already blacklisted at $DEST"
    exit 0
fi

cat > "$DEST" <<'EOF'
# Managed by compliance-bootstrap (CIS 1.1.10).
install usb-storage /bin/true
blacklist usb-storage
EOF
echo "wrote $DEST"
