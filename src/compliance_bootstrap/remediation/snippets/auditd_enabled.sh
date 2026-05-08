#!/usr/bin/env bash
# summary: Enable auditd via -e 1 in audit.rules
set -euo pipefail

DROP="/etc/audit/rules.d/99-cis-enable.rules"
mkdir -p "$(dirname "$DROP")"

if [ -f "$DROP" ] && grep -q '^-e 1' "$DROP"; then
    echo "audit -e 1 already set in $DROP"
    exit 0
fi

cat > "$DROP" <<'EOF'
## Managed by compliance-bootstrap (CIS 4.1.1.2).
-e 1
EOF

if command -v augenrules >/dev/null 2>&1; then
    augenrules --load 2>/dev/null || true
fi
echo "wrote $DROP"
