#!/usr/bin/env bash
# summary: Disable IPv6 router advertisements via sysctl
set -euo pipefail

DROP="/etc/sysctl.d/60-cis-ipv6-ra.conf"
cat > "$DROP" <<'EOF'
# Managed by compliance-bootstrap (CIS 3.3.9).
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
EOF
if command -v sysctl >/dev/null 2>&1; then
    sysctl --system >/dev/null 2>&1 || true
fi
echo "wrote $DROP"
