#!/usr/bin/env bash
# summary: Set PermitRootLogin to no in sshd_config and reload sshd
set -euo pipefail

CFG="/etc/ssh/sshd_config"
DROP="/etc/ssh/sshd_config.d/cis-permit-root.conf"

mkdir -p "$(dirname "$DROP")"
if [ -f "$DROP" ] && grep -q '^PermitRootLogin no' "$DROP"; then
    echo "PermitRootLogin already set in $DROP"
else
    cat > "$DROP" <<'EOF'
# Managed by compliance-bootstrap (CIS 5.2.8).
PermitRootLogin no
EOF
    echo "wrote $DROP"
fi

if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ssh 2>/dev/null; then
    systemctl reload ssh || true
fi

# Sanity check: openssh syntax
if command -v sshd >/dev/null 2>&1; then
    sshd -t -f "$CFG" || { echo "sshd config invalid"; exit 1; }
fi
