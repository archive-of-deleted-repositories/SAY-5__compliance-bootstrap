#!/usr/bin/env bash
# summary: Remove any explicit Protocol directive from sshd_config (modern OpenSSH is v2 only)
set -euo pipefail

CFG="/etc/ssh/sshd_config"
if [ ! -f "$CFG" ]; then
    echo "$CFG missing"
    exit 1
fi

if grep -qiE '^\s*Protocol\s+1' "$CFG"; then
    sed -i.bak -E 's/^\s*Protocol\s+1.*$/# &/' "$CFG"
    echo "commented out Protocol 1 lines in $CFG"
else
    echo "no Protocol 1 directive present"
fi
