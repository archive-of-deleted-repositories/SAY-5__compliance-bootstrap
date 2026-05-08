#!/usr/bin/env bash
# summary: Disable PasswordAuthentication in sshd (key-based auth only)
set -euo pipefail

DROP="/etc/ssh/sshd_config.d/cis-password-auth.conf"
mkdir -p "$(dirname "$DROP")"

if [ -f "$DROP" ] && grep -q '^PasswordAuthentication no' "$DROP"; then
    echo "PasswordAuthentication already disabled in $DROP"
else
    cat > "$DROP" <<'EOF'
# Managed by compliance-bootstrap (CIS 5.2.10).
PasswordAuthentication no
EOF
    echo "wrote $DROP"
fi

if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ssh 2>/dev/null; then
    systemctl reload ssh || true
fi
