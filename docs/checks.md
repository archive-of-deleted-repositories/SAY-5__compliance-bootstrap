# Checks reference

Every check has a stable `check_id`, a CIS reference, an evaluator that
returns one of `pass | fail | skip | unavailable`, and (for `fail`) a
remediation snippet under `src/compliance_bootstrap/remediation/snippets/`.

## Conventions

- `check_id` uses dot-separated lower-snake categories: `ssh.permit_root_login`
- `cis_ref` cites the section number from the CIS Ubuntu 22.04 Server Benchmark
- `unavailable` means the check could not measure the property (e.g. the
  config file is absent on a non-Debian host); it is *not* a pass and
  not a fail. Strict mode promotes it to fail.

## Categories

### Filesystem (5)

| ID | CIS | What it checks |
|---|---|---|
| `fs.tmp_separate` | 1.1.2.1 | `/tmp` is a separate filesystem (in `/proc/mounts`) |
| `fs.tmp_nodev` | 1.1.2.2 | `/tmp` mount has the `nodev` option |
| `fs.tmp_nosuid` | 1.1.2.3 | `/tmp` mount has the `nosuid` option |
| `fs.var_log_separate` | 1.1.5.1 | `/var/log` is a separate filesystem |
| `fs.usb_storage_disabled` | 1.1.10 | `usb-storage` is blacklisted in `/etc/modprobe.d` |

### SSH (8)

| ID | CIS | What it checks |
|---|---|---|
| `ssh.protocol_2` | 5.2.1 | No `Protocol 1` directive (modern OpenSSH is v2-only by default) |
| `ssh.permit_root_login` | 5.2.8 | `PermitRootLogin no` (not `prohibit-password`) |
| `ssh.password_authentication` | 5.2.10 | `PasswordAuthentication no` (key-based only) |
| `ssh.max_auth_tries` | 5.2.7 | `MaxAuthTries <= 4` |
| `ssh.client_alive_interval` | 5.2.16 | `ClientAliveInterval` between 1 and 300 seconds |
| `ssh.x11_forwarding` | 5.2.6 | `X11Forwarding no` |
| `ssh.max_sessions` | 5.2.22 | `MaxSessions <= 10` |
| `ssh.banner` | 5.2.21 | `Banner` points at a readable file |

### PAM (4)

| ID | CIS | What it checks |
|---|---|---|
| `pam.password_minlen` | 5.3.1 | pwquality `minlen >= 14` |
| `pam.password_classes` | 5.3.2 | pwquality `minclass >= 4` |
| `pam.password_reuse` | 5.3.3 | `remember >= 5` on `pam_pwhistory.so` or `pam_unix.so` |
| `pam.account_lockout` | 5.3.2 | `deny <= 5` on `pam_faillock.so` or `pam_tally2.so` |

### auditd (4)

| ID | CIS | What it checks |
|---|---|---|
| `auditd.installed` | 4.1.1.1 | `/etc/audit` exists; `auditd` binary or `auditctl` on PATH |
| `auditd.enabled` | 4.1.1.2 | `-e 1` or `-e 2` in `/etc/audit/rules.d/*.rules` |
| `auditd.log_dir_mode` | 4.1.3.1 | `/var/log/audit` mode is `0750` or stricter |
| `auditd.sudoers_rules` | 4.1.3.6 | watches present on `/etc/sudoers` and `/etc/passwd` |

### Network (5)

| ID | CIS | What it checks |
|---|---|---|
| `net.icmp_redirects` | 3.3.2 | `/proc/sys/net/ipv4/conf/all/accept_redirects == 0` |
| `net.source_route` | 3.3.1 | `/proc/sys/net/ipv4/conf/all/accept_source_route == 0` |
| `net.log_martians` | 3.3.4 | `/proc/sys/net/ipv4/conf/all/log_martians == 1` |
| `net.ipv6_ra_disabled` | 3.3.9 | `/proc/sys/net/ipv6/conf/all/accept_ra == 0` |
| `net.firewall_active` | 3.5.1 | ufw enabled flag or non-empty `/etc/nftables.conf` |

### Packages (4)

| ID | CIS | What it checks |
|---|---|---|
| `pkg.required_present` | 1.2.1 (org) | `auditd`, `ufw`, `openssh-server` installed (dpkg) |
| `pkg.unwanted_absent` | 2.3.* | `telnet`, `rsh-client`, `talk`, … absent (dpkg) |
| `pkg.unattended_upgrades` | 1.9 | `20auto-upgrades` enables periodic Unattended-Upgrade |
| `pkg.signature_verification` | 1.2.2 | no apt override sets `AllowInsecureRepositories "true"` |

### Kernel (3)

| ID | CIS | What it checks |
|---|---|---|
| `kernel.aslr` | 1.6.3 | `kernel.randomize_va_space == 2` |
| `kernel.kptr_restrict` | 1.6.4 | `kernel.kptr_restrict >= 1` |
| `kernel.protected_links` | 1.6.5 | `fs.protected_hardlinks == 1` and `fs.protected_symlinks == 1` |

## How to read the report

The JSON report's `checks` array is sorted by id. Each entry carries:

- `id` — `check_id`
- `status` — one of the four states
- `summary` — short human-readable explanation
- `evidence` — small dict with the actual measurement (varies per check)
- `remediation_id` — name of the Bash snippet (only set on `fail`)
- `remediation` — one-line text from the snippet's `# summary:` header

The Markdown report groups by category, lists each check, and inlines
the remediation Bash for every `fail`.
