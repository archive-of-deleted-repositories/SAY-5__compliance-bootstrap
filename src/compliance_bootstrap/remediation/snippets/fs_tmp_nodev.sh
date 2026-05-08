#!/usr/bin/env bash
# summary: Add nodev to the /tmp mount options in /etc/fstab
set -euo pipefail

FSTAB="/etc/fstab"

if ! grep -E '^\s*\S+\s+/tmp\s+' "$FSTAB" >/dev/null 2>&1; then
    echo "no /tmp entry in $FSTAB; run fs_tmp_separate first"
    exit 1
fi

# Replace the options field (column 4) for the /tmp row, adding nodev
# only when not already present. The awk uses tab/space-tolerant
# field separation and writes back atomically.
tmp_file="$(mktemp)"
awk '
    BEGIN { OFS="\t" }
    /^[[:space:]]*#/ { print; next }
    NF >= 4 && $2 == "/tmp" {
        n = split($4, opts, ",")
        seen=0
        for (i=1;i<=n;i++) if (opts[i]=="nodev") seen=1
        if (!seen) $4 = $4",nodev"
        print; next
    }
    { print }
' "$FSTAB" > "$tmp_file"

if ! cmp -s "$FSTAB" "$tmp_file"; then
    mv "$tmp_file" "$FSTAB"
    echo "added nodev to /tmp; remount required"
else
    rm -f "$tmp_file"
    echo "/tmp already has nodev"
fi
