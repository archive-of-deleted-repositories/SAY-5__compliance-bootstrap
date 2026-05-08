#!/usr/bin/env bash
# summary: Set sshd MaxAuthTries to 4
set -euo pipefail

DROP="/etc/ssh/sshd_config.d/cis-max-auth-tries.conf"
mkdir -p "$(dirname "$DROP")"
cat > "$DROP" <<'EOF'
# Managed by compliance-bootstrap (CIS 5.2.7).
MaxAuthTries 4
EOF

if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ssh 2>/dev/null; then
    systemctl reload ssh || true
fi
echo "wrote $DROP"
