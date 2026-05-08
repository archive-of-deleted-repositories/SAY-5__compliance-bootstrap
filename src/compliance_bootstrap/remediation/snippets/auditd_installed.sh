#!/usr/bin/env bash
# summary: Install auditd via apt or dnf
set -euo pipefail

if command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W -f='${Status}' auditd 2>/dev/null | grep -q 'install ok installed'; then
    echo "auditd already installed (dpkg)"
    exit 0
fi
if command -v rpm >/dev/null 2>&1 && rpm -q audit >/dev/null 2>&1; then
    echo "audit already installed (rpm)"
    exit 0
fi

if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y auditd
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y audit
elif command -v yum >/dev/null 2>&1; then
    yum install -y audit
else
    echo "no supported package manager"
    exit 1
fi
echo "auditd installed"
