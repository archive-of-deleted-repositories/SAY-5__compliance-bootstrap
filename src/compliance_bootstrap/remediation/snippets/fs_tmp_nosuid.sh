#!/usr/bin/env bash
# summary: Add nosuid to the /tmp mount options in /etc/fstab
set -euo pipefail

FSTAB="/etc/fstab"

if ! grep -E '^\s*\S+\s+/tmp\s+' "$FSTAB" >/dev/null 2>&1; then
    echo "no /tmp entry in $FSTAB; run fs_tmp_separate first"
    exit 1
fi

tmp_file="$(mktemp)"
awk '
    BEGIN { OFS="\t" }
    /^[[:space:]]*#/ { print; next }
    NF >= 4 && $2 == "/tmp" {
        n = split($4, opts, ",")
        seen=0
        for (i=1;i<=n;i++) if (opts[i]=="nosuid") seen=1
        if (!seen) $4 = $4",nosuid"
        print; next
    }
    { print }
' "$FSTAB" > "$tmp_file"

if ! cmp -s "$FSTAB" "$tmp_file"; then
    mv "$tmp_file" "$FSTAB"
    echo "added nosuid to /tmp; remount required"
else
    rm -f "$tmp_file"
    echo "/tmp already has nosuid"
fi
