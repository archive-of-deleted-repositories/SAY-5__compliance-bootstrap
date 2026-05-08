#!/usr/bin/env bash
# summary: Disable source-routed packets via sysctl drop-in
set -euo pipefail

DROP="/etc/sysctl.d/60-cis-source-route.conf"
cat > "$DROP" <<'EOF'
# Managed by compliance-bootstrap (CIS 3.3.1).
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
EOF
if command -v sysctl >/dev/null 2>&1; then
    sysctl --system >/dev/null 2>&1 || true
fi
echo "wrote $DROP"
