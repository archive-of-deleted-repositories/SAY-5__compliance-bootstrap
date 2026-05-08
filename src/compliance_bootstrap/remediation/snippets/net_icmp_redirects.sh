#!/usr/bin/env bash
# summary: Disable ICMP redirects via sysctl drop-in and reload
set -euo pipefail

DROP="/etc/sysctl.d/60-cis-icmp-redirects.conf"
cat > "$DROP" <<'EOF'
# Managed by compliance-bootstrap (CIS 3.3.2).
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
EOF
if command -v sysctl >/dev/null 2>&1; then
    sysctl --system >/dev/null 2>&1 || true
fi
echo "wrote $DROP"
