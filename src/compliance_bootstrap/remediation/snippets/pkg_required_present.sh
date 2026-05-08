#!/usr/bin/env bash
# summary: Install required packages (auditd, ufw, openssh-server)
set -euo pipefail

REQUIRED=(auditd ufw openssh-server)

if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${REQUIRED[@]}"
elif command -v dnf >/dev/null 2>&1; then
    # RHEL package names differ; map the common cases.
    dnf install -y audit firewalld openssh-server
else
    echo "no supported package manager"
    exit 1
fi
echo "required packages installed"
