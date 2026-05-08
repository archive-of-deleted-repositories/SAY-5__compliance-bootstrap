#!/usr/bin/env bash
# summary: Remove apt overrides that disable signature verification
set -euo pipefail

if [ ! -d /etc/apt ]; then
    echo "/etc/apt missing"
    exit 0
fi

CHANGED=0
for f in /etc/apt/apt.conf /etc/apt/apt.conf.d/*; do
    [ -f "$f" ] || continue
    if grep -Eqi '(AllowInsecureRepositories|AllowUnauthenticated)\s*"true"' "$f"; then
        sed -i.bak -E 's/(AllowInsecureRepositories|AllowUnauthenticated)\s*"true"/\1 "false"/Ig' "$f"
        echo "tightened $f"
        CHANGED=1
    fi
done
[ "$CHANGED" -eq 0 ] && echo "no apt overrides relaxed signature checks"
