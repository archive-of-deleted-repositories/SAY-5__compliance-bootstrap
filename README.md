# compliance-bootstrap

`compliance-bootstrap` is a Linux compliance audit + remediation
runner: 33 checks across filesystem, SSH, PAM, auditd, network,
packages, and kernel — modelled on the CIS Ubuntu 22.04 Server
benchmark — each emitting one of `pass | fail | skip | unavailable`.
For every failing check the runner ships a Bash remediation snippet that
fixes the deviation, and the Markdown report inlines the snippet next
to the failure so an operator can paste-and-run after a one-screen
read. Provisioning is the other half: `scripts/bootstrap-<distro>.sh`
installs the required packages on Debian/Ubuntu, RHEL/Rocky, and
Amazon Linux 2.

## What this studies

- **Declarative compliance policies.** A YAML file names which checks
  to run; the loader fails loud on unknown ids so typos cannot silently
  bypass a control. The default `policies/cis-ubuntu-22.yaml` lists 33
  ids; `policies/strict.yaml` adds a `treat_unavailable_as_fail` flag
  that promotes the four-state model into a strict pass/fail one.
- **Per-deviation remediation snippets as first-class artefacts.** Each
  failing check returns a `remediation_id` matching a Bash file under
  `src/compliance_bootstrap/remediation/snippets/`. The snippets are
  shellcheck-clean, `set -euo pipefail`, and idempotent — running them
  twice produces no further change, which the integration test loops
  through the corpus to verify. Each snippet's content hash is logged
  before it runs, so a downstream log scanner can prove which exact
  Bash executed on a given host.
- **The four-state result model, reused.** This is the same
  pass/fail/skip/unavailable contract `hw-preflight` ships, deliberately
  *not* collapsed: a host that lacks `/etc/audit` (running RHEL where
  auditd is in `audit/` instead) is honestly `unavailable`, not
  fake-passed and not falsely failed. `audit` exits 1 only on `fail`,
  so a missing-on-this-distro check does not break a CI gate.
- **CIS-baseline-as-config.** Every CIS section number ends up in the
  registered `Check` class as a `cis_ref` ClassVar, surfaced in the
  `list-checks` command and the JSON report — auditors can grep the
  output for "5.2.8" and find the exact evaluator that backs that
  control, then read its 30-line `evaluate()` to confirm the semantics.

## Differentiation from `hw-preflight`

[`hw-preflight`](https://github.com/SAY-5/hw-preflight) runs 24
**hardware-readiness** checks — CPU features, RAM, sensors, serial
I/O, NVMe SMART. It answers *can this box do the job?*

`compliance-bootstrap` runs 33 **OS-level security baseline** checks
— sshd config, PAM stack, auditd rules, sysctl hardening. It answers
*has this box been hardened to policy?* The four-state result model
and the report shape are inherited from `hw-preflight`; the rule
domain and the remediation-snippet model are new here.

## Sample audit output

The numbers below are the actual output of `compliance-bootstrap
audit --policy cis-ubuntu-22` on the maintainer's macOS workstation
(see `examples/sample-runs/local-darwin-arm64.json`). On a non-Linux
host most checks correctly report `unavailable` — there is no
`/proc/sys`, no `/etc/audit`, no dpkg status file — and only the few
that target generic POSIX paths produce concrete results. This is the
same robustness story `hw-preflight` makes: never fake a pass or a
fail when the surface to measure isn't there.

```
3 pass / 11 fail / 0 skip / 19 unavailable (33 total)
```

The CI job `audit-self-test` runs the same command against the
GitHub Actions `ubuntu-24.04` runner and uploads the report as a
build artefact (`sample-runs`); the runner is not a hardened box
either, so the breakdown is honest pass/fail/unavailable rather
than green-washed numbers. Download the artefact from a recent run
on Actions to see the live numbers.

## Module table

| Path | What it does |
|---|---|
| `src/compliance_bootstrap/cli.py` | Click CLI (`audit`, `remediate`, `report`, `provision`, `list-checks`, `list-remediations`) |
| `src/compliance_bootstrap/checks/` | 33 check evaluators across 7 categories (`filesystem`, `ssh_config`, `pam`, `auditd`, `network`, `packages`, `kernel`) |
| `src/compliance_bootstrap/checks/_base.py` | `Check` Protocol, four-state `Status` enum, `register_check` decorator, `BaseCheck` mixin |
| `src/compliance_bootstrap/policy.py` | YAML policy loader; rejects unknown `check_id`s up-front |
| `src/compliance_bootstrap/runner.py` | Audit runner with structlog and strict-mode override |
| `src/compliance_bootstrap/reports/json_emit.py` | JSON serializer, sorted keys, schema_version pinned |
| `src/compliance_bootstrap/reports/markdown.py` | Markdown renderer, groups by category, inlines remediation Bash on fails |
| `src/compliance_bootstrap/remediation/` | One Bash snippet per `remediation_id`, plus `snippet_hash()` audit trail |
| `src/compliance_bootstrap/provision/` | Thin Python wrappers around apt/dnf/ufw/sshd_config drop-ins |
| `scripts/bootstrap-debian.sh` | Idempotent apt-flavored provisioning (Ubuntu / Debian) |
| `scripts/bootstrap-rhel.sh` | Idempotent dnf-flavored provisioning (RHEL / Rocky / Alma) |
| `scripts/bootstrap-amzn2.sh` | Idempotent yum-flavored provisioning (Amazon Linux 2) |
| `policies/cis-ubuntu-22.yaml` | CIS Ubuntu 22.04 baseline policy (33 enabled checks) |
| `policies/strict.yaml` | Same checks, `treat_unavailable_as_fail` on |
| `tests/unit/` | 130 unit tests, fixture-tree based, no real I/O |
| `tests/integration/` | Container-gated smoke (gated by `RUN_INTEGRATION=1`) |
| `Dockerfile` | Multi-stage: `tool` (just the CLI), `target` (debian:bookworm with the CLI) |

## Quickstart

```bash
# install
make dev

# audit the host with the default policy
make audit
cat out/audit.md           # human-readable report
jq .summary out/audit.json # JSON summary

# dry-run the remediation snippets — shows what would change
compliance-bootstrap remediate --policy cis-ubuntu-22

# actually apply them (root required for most snippets)
sudo compliance-bootstrap remediate --policy cis-ubuntu-22 --apply
```

## Architecture

```
+---------------------+
|   compliance CLI    |  <-- click; main entry point
|  audit | remediate  |
+----------+----------+
           |
           v
+---------------------+
|   policy.py         |  <-- YAML -> Policy(name, enabled, overrides)
+---------------------+      fails loud on unknown check_id
           |
           v
+---------------------+
|   runner.py         |  <-- iterates Policy.enabled
+---------------------+      wraps every evaluator in try/except
           |
           v
+---------------------+
| checks/<category>/  |  <-- 33 BaseCheck subclasses
+---------------------+      each evaluate(ctx) -> CheckResult
           |
           v
+---------------------+
|   reports/{json,md} |  <-- inline remediation Bash on fails
+---------------------+
           |
           v
+---------------------+
| remediation/snippets|  <-- shellcheck-clean idempotent Bash
+---------------------+      sha256 logged before apply
```

## What this is *not*

- **No agent push.** The audit is pull-based: it runs on the target
  itself and reads `/proc`, `/etc`, `/var/lib`. There is no daemon, no
  control-plane, and no inbound network. Push-style enforcement
  belongs to a configuration-management tool (Ansible, Puppet, Salt);
  this just measures and remediates.
- **No compliance-as-a-service backend.** No SaaS, no telemetry, no
  scoring portal. The output is two files (`.json` + `.md`); a fleet
  operator who wants to aggregate them across hosts feeds the JSON to
  whatever they already have.
- **No scoring or grading.** A host that fails 5 of 33 checks is just
  that — five concrete deviations with five concrete remediation
  snippets. There is no "compliance score" weighting, because the
  numerical model that would justify one (which we don't have) is
  exactly the kind of fake-precision a real auditor distrusts.
- **No CI/CD enforcement / IaC integration.** This tool does not
  refuse to deploy a Terraform plan that would result in a
  non-compliant host. That's the job of the planner that builds the
  IaC, not the auditor that checks it after-the-fact.
- **No SCAP/OVAL output.** The JSON is a small custom shape that's
  obvious from one read. SCAP is a meaningful interop format — the
  comparison path is documented in `ARCHITECTURE.md` (see "What's
  deliberately not here") for anyone who wants to bolt on a SCAP
  exporter.
- **No Windows / no macOS first-class.** Linux only. macOS produces
  almost-all-`unavailable` and that's deliberate.
- **No real-time monitoring.** Audit is a one-shot operation. Drift
  detection is a follow-on problem; the cron-call pattern is documented
  in `docs/` rather than baked into the tool.

## License

MIT — see `LICENSE`.
