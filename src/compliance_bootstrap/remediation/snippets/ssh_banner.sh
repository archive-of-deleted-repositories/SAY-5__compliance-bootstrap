#!/usr/bin/env bash
# summary: Install /etc/issue.net banner and point sshd at it
set -euo pipefail

BANNER="/etc/issue.net"
DROP="/etc/ssh/sshd_config.d/cis-banner.conf"

if [ ! -s "$BANNER" ] || ! grep -q 'Authorized uses only' "$BANNER" 2>/dev/null; then
    cat > "$BANNER" <<'EOF'
Authorized uses only. All activity may be monitored and reported.
EOF
fi

mkdir -p "$(dirname "$DROP")"
cat > "$DROP" <<EOF
# Managed by compliance-bootstrap (CIS 5.2.21).
Banner $BANNER
EOF

if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ssh 2>/dev/null; then
    systemctl reload ssh || true
fi
echo "wrote $BANNER and $DROP"
