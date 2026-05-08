#!/usr/bin/env bash
# bootstrap-rhel.sh — idempotent provisioning for RHEL/Rocky/Alma hosts.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root" >&2
    exit 1
fi

REQUIRED_PACKAGES=(
    audit
    libpwquality
    openssh-server
    firewalld
)

UNWANTED_PACKAGES=(
    rsh
    rsh-server
    talk
    talk-server
    telnet
    telnet-server
)

echo "[1/3] installing required packages"
dnf install -y "${REQUIRED_PACKAGES[@]}"

echo "[2/3] removing unwanted packages"
for pkg in "${UNWANTED_PACKAGES[@]}"; do
    if rpm -q "$pkg" >/dev/null 2>&1; then
        dnf remove -y "$pkg"
    fi
done

echo "[3/3] enabling auditd and firewalld"
systemctl enable --now auditd
systemctl enable --now firewalld

echo "bootstrap-rhel.sh complete"
