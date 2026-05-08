#!/usr/bin/env bash
# summary: Set ClientAliveInterval=300 and ClientAliveCountMax=3 for sshd
set -euo pipefail

DROP="/etc/ssh/sshd_config.d/cis-client-alive.conf"
mkdir -p "$(dirname "$DROP")"
cat > "$DROP" <<'EOF'
# Managed by compliance-bootstrap (CIS 5.2.16).
ClientAliveInterval 300
ClientAliveCountMax 3
EOF

if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ssh 2>/dev/null; then
    systemctl reload ssh || true
fi
echo "wrote $DROP"
