#!/usr/bin/env bash
# summary: Enable log_martians via sysctl drop-in
set -euo pipefail

DROP="/etc/sysctl.d/60-cis-log-martians.conf"
cat > "$DROP" <<'EOF'
# Managed by compliance-bootstrap (CIS 3.3.4).
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
EOF
if command -v sysctl >/dev/null 2>&1; then
    sysctl --system >/dev/null 2>&1 || true
fi
echo "wrote $DROP"
