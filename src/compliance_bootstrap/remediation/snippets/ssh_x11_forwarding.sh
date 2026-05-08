#!/usr/bin/env bash
# summary: Disable X11Forwarding in sshd
set -euo pipefail

DROP="/etc/ssh/sshd_config.d/cis-x11.conf"
mkdir -p "$(dirname "$DROP")"
cat > "$DROP" <<'EOF'
# Managed by compliance-bootstrap (CIS 5.2.6).
X11Forwarding no
EOF

if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ssh 2>/dev/null; then
    systemctl reload ssh || true
fi
echo "wrote $DROP"
