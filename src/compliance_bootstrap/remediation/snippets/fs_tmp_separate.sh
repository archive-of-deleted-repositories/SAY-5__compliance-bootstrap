#!/usr/bin/env bash
# summary: Mount /tmp on a separate tmpfs entry in /etc/fstab
set -euo pipefail

FSTAB="/etc/fstab"
LINE="tmpfs /tmp tmpfs defaults,nodev,nosuid,size=2G 0 0"

if grep -E '^\s*tmpfs\s+/tmp\s+tmpfs' "$FSTAB" >/dev/null 2>&1; then
    echo "fstab already has a tmpfs entry for /tmp"
    exit 0
fi

printf '%s\n' "$LINE" >> "$FSTAB"
echo "appended tmpfs /tmp entry; reboot or 'mount /tmp' required to activate"
