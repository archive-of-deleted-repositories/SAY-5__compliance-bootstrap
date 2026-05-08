#!/usr/bin/env bash
# summary: Set kernel.kptr_restrict=1 to hide kernel pointers from non-root
set -euo pipefail

DROP="/etc/sysctl.d/60-cis-kptr.conf"
cat > "$DROP" <<'EOF'
# Managed by compliance-bootstrap (CIS 1.6.4).
kernel.kptr_restrict = 1
EOF
if command -v sysctl >/dev/null 2>&1; then
    sysctl --system >/dev/null 2>&1 || true
fi
echo "wrote $DROP"
