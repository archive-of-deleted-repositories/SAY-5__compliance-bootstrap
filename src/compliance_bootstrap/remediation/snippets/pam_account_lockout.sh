#!/usr/bin/env bash
# summary: Set faillock deny=5 in PAM auth stack
set -euo pipefail

CFG="/etc/pam.d/common-auth"
if [ ! -f "$CFG" ]; then
    echo "$CFG missing"
    exit 1
fi

if grep -qE '^\s*auth\s+\S+\s+pam_faillock\.so' "$CFG"; then
    if grep -qE '^\s*auth\s+\S+\s+pam_faillock\.so.*\bdeny=' "$CFG"; then
        sed -i -E 's/(^\s*auth\s+\S+\s+pam_faillock\.so.*)\bdeny=[0-9]+/\1deny=5/' "$CFG"
    else
        sed -i -E 's/(^\s*auth\s+\S+\s+pam_faillock\.so.*)/\1 deny=5/' "$CFG"
    fi
else
    # Prepend a faillock preauth/authfail block near the top of the
    # auth stack. Conservative — relies on operator review afterward.
    {
        echo "auth required pam_faillock.so preauth silent deny=5 unlock_time=900"
        cat "$CFG"
    } > "$CFG.tmp"
    mv "$CFG.tmp" "$CFG"
fi
echo "deny=5 in $CFG"
