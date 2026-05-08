#!/usr/bin/env bash
# summary: Document the requirement to mount /var/log on a separate filesystem
set -euo pipefail

# Creating a separate /var/log filesystem at runtime is destructive
# (data migration, mount point conflicts) and is therefore not done
# automatically. This snippet records the requirement in a marker file
# the operator can reference when re-imaging.
MARK="/etc/compliance-bootstrap/pending-var-log-separate"
mkdir -p "$(dirname "$MARK")"
cat > "$MARK" <<'EOF'
/var/log must be mounted on a separate filesystem (CIS 1.1.5.1).
This is an install-time decision. Recreate the host with a dedicated
/var/log partition or LVM volume; runtime conversion is unsafe.
EOF
echo "marker written to $MARK"
