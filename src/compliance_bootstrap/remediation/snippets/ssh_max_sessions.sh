#!/usr/bin/env bash
# summary: Cap sshd MaxSessions at 10
set -euo pipefail

DROP="/etc/ssh/sshd_config.d/cis-max-sessions.conf"
mkdir -p "$(dirname "$DROP")"
cat > "$DROP" <<'EOF'
# Managed by compliance-bootstrap (CIS 5.2.22).
MaxSessions 10
EOF

if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ssh 2>/dev/null; then
    systemctl reload ssh || true
fi
echo "wrote $DROP"
