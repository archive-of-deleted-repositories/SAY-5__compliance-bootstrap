#!/usr/bin/env bash
# summary: Enable full ASLR (kernel.randomize_va_space=2)
set -euo pipefail

DROP="/etc/sysctl.d/60-cis-aslr.conf"
cat > "$DROP" <<'EOF'
# Managed by compliance-bootstrap (CIS 1.6.3).
kernel.randomize_va_space = 2
EOF
if command -v sysctl >/dev/null 2>&1; then
    sysctl --system >/dev/null 2>&1 || true
fi
echo "wrote $DROP"
