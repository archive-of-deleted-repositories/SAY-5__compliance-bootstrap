# Bootstrap scripts

`bootstrap-<distro>.sh` performs the *provisioning* half of compliance:
installing required packages, removing insecure ones, and (where
applicable) enabling auditd / firewalld / unattended-upgrades.

These scripts are **idempotent**. Running them twice produces no further
change. CI runs shellcheck on every file and the `remediation-smoke`
job exercises one of them inside a debian:bookworm container.

| Distro | Script | Package manager |
|---|---|---|
| Debian / Ubuntu | `bootstrap-debian.sh` | apt-get |
| RHEL / Rocky / Alma | `bootstrap-rhel.sh` | dnf |
| Amazon Linux 2 | `bootstrap-amzn2.sh` | yum |

Run as root, e.g. from cloud-init:

```yaml
runcmd:
  - [ bash, /opt/compliance-bootstrap/scripts/bootstrap-debian.sh ]
```

The provisioning step does *not* attempt to be CIS-complete on its own;
it is the minimum needed to make the audit produce useful output. For
the full pass run `compliance-bootstrap audit` followed by
`compliance-bootstrap remediate --apply`.
