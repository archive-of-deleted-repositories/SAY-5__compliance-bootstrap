# compliance-bootstrap audit — Sais-MacBook-Pro.local

- policy: `cis-ubuntu-22`
- host: `Sais-MacBook-Pro.local`
- os: `unknown` — kernel `25.0.0` — arch `arm64`
- started_at: `2026-05-08T04:50:27.384198Z`

- summary: 3 pass / 11 fail / 0 skip / 19 unavailable (33 total)

## auditd

| Check | Status | Detail |
|---|---|---|
| `auditd.enabled` | UNAVAIL | no audit rules found |
| `auditd.installed` | FAIL | auditd not installed |
| `auditd.log_dir_mode` | UNAVAIL | /var/log/audit missing |
| `auditd.sudoers_rules` | UNAVAIL | no audit rules found |

## fs

| Check | Status | Detail |
|---|---|---|
| `fs.tmp_nodev` | UNAVAIL | /proc/mounts unreadable |
| `fs.tmp_nosuid` | UNAVAIL | /proc/mounts unreadable |
| `fs.tmp_separate` | UNAVAIL | /proc/mounts unreadable |
| `fs.usb_storage_disabled` | UNAVAIL | /etc/modprobe.d missing |
| `fs.var_log_separate` | UNAVAIL | /proc/mounts unreadable |

## kernel

| Check | Status | Detail |
|---|---|---|
| `kernel.aslr` | UNAVAIL | randomize_va_space not exposed |
| `kernel.kptr_restrict` | UNAVAIL | kptr_restrict not exposed |
| `kernel.protected_links` | UNAVAIL | protected_hardlinks/symlinks not exposed |

## net

| Check | Status | Detail |
|---|---|---|
| `net.firewall_active` | FAIL | no active firewall configuration detected |
| `net.icmp_redirects` | UNAVAIL | net.ipv4.conf.all.accept_redirects not exposed via /proc/sys |
| `net.ipv6_ra_disabled` | UNAVAIL | ipv6 not exposed in /proc/sys |
| `net.log_martians` | UNAVAIL | net.ipv4.conf.all.log_martians not exposed via /proc/sys |
| `net.source_route` | UNAVAIL | net.ipv4.conf.all.accept_source_route not exposed via /proc/sys |

## pam

| Check | Status | Detail |
|---|---|---|
| `pam.account_lockout` | FAIL | no faillock/tally2 deny= directive found |
| `pam.password_classes` | FAIL | pwquality.conf missing minclass |
| `pam.password_minlen` | FAIL | pwquality.conf missing minlen |
| `pam.password_reuse` | UNAVAIL | /etc/pam.d/common-password missing |

## pkg

| Check | Status | Detail |
|---|---|---|
| `pkg.required_present` | UNAVAIL | dpkg status file not present |
| `pkg.signature_verification` | UNAVAIL | /etc/apt missing |
| `pkg.unattended_upgrades` | FAIL | 20auto-upgrades not present |
| `pkg.unwanted_absent` | UNAVAIL | dpkg status file not present |

## ssh

| Check | Status | Detail |
|---|---|---|
| `ssh.banner` | FAIL | Banner not configured |
| `ssh.client_alive_interval` | FAIL | ClientAliveInterval=0; expected 1..300 |
| `ssh.max_auth_tries` | FAIL | MaxAuthTries=6; expected <= 4 |
| `ssh.max_sessions` | PASS | MaxSessions=10 |
| `ssh.password_authentication` | FAIL | PasswordAuthentication=yes; expected no |
| `ssh.permit_root_login` | FAIL | PermitRootLogin=prohibit-password; expected no |
| `ssh.protocol_2` | PASS | protocol 2 only |
| `ssh.x11_forwarding` | PASS | X11Forwarding=no |

## Remediation snippets

Each failing check below includes the Bash snippet that fixes the deviation. Run them in order, or invoke `compliance-bootstrap remediate --apply` to apply them all (pulled from the same source tree).

### `auditd.installed` — auditd not installed

```bash
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
```

### `net.firewall_active` — no active firewall configuration detected

```bash
#!/usr/bin/env bash
# summary: Install ufw, allow SSH, and enable the firewall
set -euo pipefail

if ! command -v ufw >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y ufw
    else
        echo "ufw not available and not on Debian/Ubuntu; configure nftables manually"
        exit 1
    fi
fi

# Pre-allow SSH so enabling the firewall does not lock us out.
ufw allow OpenSSH 2>/dev/null || ufw allow 22/tcp
yes | ufw enable >/dev/null 2>&1 || ufw --force enable

CFG="/etc/ufw/ufw.conf"
if grep -qE '^ENABLED=' "$CFG"; then
    sed -i -E 's/^ENABLED=.*/ENABLED=yes/' "$CFG"
fi
echo "ufw enabled"
```

### `pam.account_lockout` — no faillock/tally2 deny= directive found

```bash
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
```

### `pam.password_classes` — pwquality.conf missing minclass

```bash
#!/usr/bin/env bash
# summary: Set pwquality minclass to 4
set -euo pipefail

CFG="/etc/security/pwquality.conf"
if [ ! -f "$CFG" ]; then
    install -m 0644 /dev/null "$CFG"
fi

if grep -qE '^\s*minclass\s*=' "$CFG"; then
    sed -i -E 's/^\s*minclass\s*=.*/minclass = 4/' "$CFG"
else
    printf '\n# Managed by compliance-bootstrap (CIS 5.3.2).\nminclass = 4\n' >> "$CFG"
fi
echo "minclass=4 in $CFG"
```

### `pam.password_minlen` — pwquality.conf missing minlen

```bash
#!/usr/bin/env bash
# summary: Set pwquality minlen to 14
set -euo pipefail

CFG="/etc/security/pwquality.conf"
if [ ! -f "$CFG" ]; then
    install -m 0644 /dev/null "$CFG"
fi

if grep -qE '^\s*minlen\s*=' "$CFG"; then
    sed -i -E 's/^\s*minlen\s*=.*/minlen = 14/' "$CFG"
else
    printf '\n# Managed by compliance-bootstrap (CIS 5.3.1).\nminlen = 14\n' >> "$CFG"
fi
echo "minlen=14 in $CFG"
```

### `pkg.unattended_upgrades` — 20auto-upgrades not present

```bash
#!/usr/bin/env bash
# summary: Enable apt unattended-upgrades via 20auto-upgrades
set -euo pipefail

if ! command -v apt-get >/dev/null 2>&1; then
    echo "apt not present; nothing to do on non-Debian systems"
    exit 0
fi

if ! dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -q 'install ok installed'; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades
fi

DEST="/etc/apt/apt.conf.d/20auto-upgrades"
cat > "$DEST" <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
echo "wrote $DEST"
```

### `ssh.banner` — Banner not configured

```bash
#!/usr/bin/env bash
# summary: Install /etc/issue.net banner and point sshd at it
set -euo pipefail

BANNER="/etc/issue.net"
DROP="/etc/ssh/sshd_config.d/cis-banner.conf"

if [ ! -s "$BANNER" ] || ! grep -q 'Authorized uses only' "$BANNER" 2>/dev/null; then
    cat > "$BANNER" <<'EOF'
Authorized uses only. All activity may be monitored and reported.
EOF
fi

mkdir -p "$(dirname "$DROP")"
cat > "$DROP" <<EOF
# Managed by compliance-bootstrap (CIS 5.2.21).
Banner $BANNER
EOF

if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ssh 2>/dev/null; then
    systemctl reload ssh || true
fi
echo "wrote $BANNER and $DROP"
```

### `ssh.client_alive_interval` — ClientAliveInterval=0; expected 1..300

```bash
#!/usr/bin/env bash
# summary: Set ClientAliveInterval=300 and ClientAliveCountMax=3 for sshd
set -euo pipefail

DROP="/etc/ssh/sshd_config.d/cis-client-alive.conf"
mkdir -p "$(dirname "$DROP")"
cat > "$DROP" <<'EOF'
# Managed by compliance-bootstrap (CIS 5.2.16).
ClientAliveInterval 300
ClientAliveCountMax 3
EOF

if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ssh 2>/dev/null; then
    systemctl reload ssh || true
fi
echo "wrote $DROP"
```

### `ssh.max_auth_tries` — MaxAuthTries=6; expected <= 4

```bash
#!/usr/bin/env bash
# summary: Set sshd MaxAuthTries to 4
set -euo pipefail

DROP="/etc/ssh/sshd_config.d/cis-max-auth-tries.conf"
mkdir -p "$(dirname "$DROP")"
cat > "$DROP" <<'EOF'
# Managed by compliance-bootstrap (CIS 5.2.7).
MaxAuthTries 4
EOF

if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ssh 2>/dev/null; then
    systemctl reload ssh || true
fi
echo "wrote $DROP"
```

### `ssh.password_authentication` — PasswordAuthentication=yes; expected no

```bash
#!/usr/bin/env bash
# summary: Disable PasswordAuthentication in sshd (key-based auth only)
set -euo pipefail

DROP="/etc/ssh/sshd_config.d/cis-password-auth.conf"
mkdir -p "$(dirname "$DROP")"

if [ -f "$DROP" ] && grep -q '^PasswordAuthentication no' "$DROP"; then
    echo "PasswordAuthentication already disabled in $DROP"
else
    cat > "$DROP" <<'EOF'
# Managed by compliance-bootstrap (CIS 5.2.10).
PasswordAuthentication no
EOF
    echo "wrote $DROP"
fi

if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ssh 2>/dev/null; then
    systemctl reload ssh || true
fi
```

### `ssh.permit_root_login` — PermitRootLogin=prohibit-password; expected no

```bash
#!/usr/bin/env bash
# summary: Set PermitRootLogin to no in sshd_config and reload sshd
set -euo pipefail

CFG="/etc/ssh/sshd_config"
DROP="/etc/ssh/sshd_config.d/cis-permit-root.conf"

mkdir -p "$(dirname "$DROP")"
if [ -f "$DROP" ] && grep -q '^PermitRootLogin no' "$DROP"; then
    echo "PermitRootLogin already set in $DROP"
else
    cat > "$DROP" <<'EOF'
# Managed by compliance-bootstrap (CIS 5.2.8).
PermitRootLogin no
EOF
    echo "wrote $DROP"
fi

if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ssh 2>/dev/null; then
    systemctl reload ssh || true
fi

# Sanity check: openssh syntax
if command -v sshd >/dev/null 2>&1; then
    sshd -t -f "$CFG" || { echo "sshd config invalid"; exit 1; }
fi
```
