#!/usr/bin/env bash
# summary: Purge insecure packages (telnet, rsh-client, talk, ...)
set -euo pipefail

UNWANTED=(telnet telnetd rsh-client rsh-server talk talkd)

if command -v apt-get >/dev/null 2>&1; then
    INSTALLED=()
    for pkg in "${UNWANTED[@]}"; do
        if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed'; then
            INSTALLED+=("$pkg")
        fi
    done
    if [ "${#INSTALLED[@]}" -gt 0 ]; then
        DEBIAN_FRONTEND=noninteractive apt-get purge -y "${INSTALLED[@]}"
    fi
elif command -v dnf >/dev/null 2>&1; then
    for pkg in "${UNWANTED[@]}"; do
        if rpm -q "$pkg" >/dev/null 2>&1; then
            dnf remove -y "$pkg"
        fi
    done
else
    echo "no supported package manager"
    exit 1
fi
echo "unwanted packages purged"
