#!/usr/bin/env bash
# summary: Set pwquality minlen to 14
set -euo pipefail

CFG="/etc/security/pwquality.conf"
if [ ! -f "$CFG" ]; then
    install -m 0644 /dev/null "$CFG"
fi

if grep -qE '^\s*minlen\s*=' "$CFG"; then
    sed -i -E 's/^\s*minlen\s*=.*/minlen = 14/' "$CFG"
else
    printf '\n# Managed by compliance-bootstrap (CIS 5.3.1).\nminlen = 14\n' >> "$CFG"
fi
echo "minlen=14 in $CFG"
