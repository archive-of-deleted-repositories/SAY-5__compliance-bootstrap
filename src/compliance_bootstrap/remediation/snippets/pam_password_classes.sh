#!/usr/bin/env bash
# summary: Set pwquality minclass to 4
set -euo pipefail

CFG="/etc/security/pwquality.conf"
if [ ! -f "$CFG" ]; then
    install -m 0644 /dev/null "$CFG"
fi

if grep -qE '^\s*minclass\s*=' "$CFG"; then
    sed -i -E 's/^\s*minclass\s*=.*/minclass = 4/' "$CFG"
else
    printf '\n# Managed by compliance-bootstrap (CIS 5.3.2).\nminclass = 4\n' >> "$CFG"
fi
echo "minclass=4 in $CFG"
