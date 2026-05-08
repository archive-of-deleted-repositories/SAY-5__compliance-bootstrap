#!/usr/bin/env bash
# summary: Block reuse of the last 5 passwords via pam_pwhistory in common-password
set -euo pipefail

CFG="/etc/pam.d/common-password"
if [ ! -f "$CFG" ]; then
    echo "$CFG missing; PAM stack not configured by Debian conventions"
    exit 1
fi

if grep -qE '^\s*password\s+\S+\s+pam_pwhistory\.so' "$CFG"; then
    if grep -qE '^\s*password\s+\S+\s+pam_pwhistory\.so.*\bremember=' "$CFG"; then
        sed -i -E 's/(^\s*password\s+\S+\s+pam_pwhistory\.so.*)\bremember=[0-9]+/\1remember=5/' "$CFG"
    else
        sed -i -E 's/(^\s*password\s+\S+\s+pam_pwhistory\.so.*)/\1 remember=5/' "$CFG"
    fi
else
    # Insert pam_pwhistory before pam_unix.so so it runs first.
    awk '
        /^password\s+\S+\s+pam_unix\.so/ && !ins {
            print "password\trequired\tpam_pwhistory.so\tremember=5"
            ins=1
        }
        { print }
    ' "$CFG" > "$CFG.tmp"
    mv "$CFG.tmp" "$CFG"
fi
echo "remember=5 set in $CFG"
