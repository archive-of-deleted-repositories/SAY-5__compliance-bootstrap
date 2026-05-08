#!/usr/bin/env bash
# summary: Enable fs.protected_hardlinks and fs.protected_symlinks
set -euo pipefail

DROP="/etc/sysctl.d/60-cis-protected-links.conf"
cat > "$DROP" <<'EOF'
# Managed by compliance-bootstrap (CIS 1.6.5).
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF
if command -v sysctl >/dev/null 2>&1; then
    sysctl --system >/dev/null 2>&1 || true
fi
echo "wrote $DROP"
