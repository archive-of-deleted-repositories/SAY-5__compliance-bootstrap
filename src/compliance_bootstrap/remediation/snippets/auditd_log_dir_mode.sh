#!/usr/bin/env bash
# summary: chmod 0750 /var/log/audit so non-root cannot read audit logs
set -euo pipefail

DIR="/var/log/audit"
if [ ! -d "$DIR" ]; then
    echo "$DIR missing — install auditd first"
    exit 0
fi
chmod 0750 "$DIR"
echo "set 0750 on $DIR"
