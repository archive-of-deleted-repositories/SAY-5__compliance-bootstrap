#!/usr/bin/env bash
# summary: Install audit watches for /etc/sudoers and /etc/passwd
set -euo pipefail

DROP="/etc/audit/rules.d/50-cis-watches.rules"
mkdir -p "$(dirname "$DROP")"

WANTED='-w /etc/sudoers -p wa -k scope
-w /etc/passwd -p wa -k identity'

if [ -f "$DROP" ] && diff -q <(printf '%s\n' "$WANTED") <(grep -E '^-w (/etc/sudoers|/etc/passwd)' "$DROP" || true) >/dev/null 2>&1; then
    echo "watches already in place at $DROP"
    exit 0
fi

cat > "$DROP" <<'EOF'
## Managed by compliance-bootstrap (CIS 4.1.3.6).
-w /etc/sudoers -p wa -k scope
-w /etc/passwd -p wa -k identity
EOF

if command -v augenrules >/dev/null 2>&1; then
    augenrules --load 2>/dev/null || true
fi
echo "wrote $DROP"
