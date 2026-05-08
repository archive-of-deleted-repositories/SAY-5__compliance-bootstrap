# Architecture

This document covers the design choices behind `compliance-bootstrap`.

## Check Protocol + auto-registration

Every check is a class that subclasses `BaseCheck` and exposes:

```python
check_id: ClassVar[str]    # "ssh.permit_root_login"
category: ClassVar[str]    # "ssh"
cis_ref: ClassVar[str]     # "CIS 5.2.8"
description: ClassVar[str] # "PermitRootLogin is no"

def evaluate(self, ctx: HostContext) -> CheckResult: ...
```

The `@register_check` decorator instantiates the class with no
arguments (every check is stateless) and stores the instance in a
package-global registry keyed by `check_id`. Importing the
`compliance_bootstrap.checks` package triggers the side-effects in
each submodule, so by the time `runner.run_audit()` runs the registry
is populated. Tests that need a clean slate call
`reset_registry_for_tests()`.

The registration model is the simplest thing that satisfies the four
constraints:

1. checks are discovered by importing modules — no manifest file to
   forget to update
2. `policy.load_policy()` validates check ids against the live registry
   so a typo in a YAML file fails before any evaluator runs
3. `cli list-checks` enumerates the registry — no separate "list of
   things to document" to keep in sync
4. `tests/unit/test_runner_and_policy.py::test_registry_has_thirty_or_more_checks`
   asserts the README's "33 checks" claim against reality on every CI
   run

## Four-state result model

```python
class Status(str, enum.Enum):
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"
    UNAVAILABLE = "unavailable"
```

- `pass` — measurement happened and matched the expected value
- `fail` — measurement happened and did *not* match; remediation_id is set
- `skip` — policy said don't run this check (currently unused; reserved
  for per-check enable/disable when policy gains overrides)
- `unavailable` — measurement could not happen (file missing, binary
  absent, kernel didn't expose the sysctl); the check has no opinion

`audit` exits 1 only on `fail`. `unavailable` does not break a CI gate
unless the policy sets `treat_unavailable_as_fail: true` (strict
mode), in which case the runner promotes any `unavailable` it sees.

## Policy YAML schema

```yaml
name: <id>
description: <one sentence>
enabled: [check_id, ...]      # required
disabled: [check_id, ...]     # informational only; loader ignores
overrides:
  treat_unavailable_as_fail: false
```

The schema is deliberately small. There is no per-check threshold
override — a check that needs to be configurable carries its own
config knob inside its module (e.g. `PkgRequired.REQUIRED` is a class
attribute). When two policies need different thresholds, the right
move is a second check class, not a YAML override; the cost of
duplicating eight lines of code is much lower than the cost of a YAML
schema that nobody can read at a glance.

## Remediation snippet design

Every remediation snippet is a Bash file that:

1. Has a shebang line (`#!/usr/bin/env bash`)
2. Sets a one-line `# summary:` header (used in JSON reports)
3. Calls `set -euo pipefail` immediately after
4. Is shellcheck-clean (`shellcheck -x` on every PR)
5. Is idempotent — running twice produces no further change

The runner shells out to `/bin/bash <snippet>` (no shell-string
splicing, no env propagation beyond `LC_ALL=C`). Before each apply we
log:

```
[apply] ssh.permit_root_login -> ssh_permit_root_login (sha256=4c2d...)
```

Downstream log scanners can prove which exact snippet ran on a host
by matching that sha256 against the build artefact's snippet
directory. Snippets are versioned with the package; bumping the
package version is how you publish a new snippet body.

### Why Bash and not Python?

Three reasons:

1. The reader of a remediation is often an SRE auditing what changed
   on their host. Bash maps 1:1 to what they would type at the prompt;
   Python introduces an extra translation layer.
2. The snippets need to run inside a `target` Docker image (the
   integration test) which only has Python at all because the tool
   itself is Python. A future image without Python (e.g. a static
   Bash-only build of the CLI) should still execute the snippets.
3. CIS documentation cites Bash one-liners directly; staying in the
   same shape makes it trivial to confirm "yes, this is exactly what
   the benchmark recommends".

## Per-distro provisioning rationale

Three Bash scripts cover the supported package managers:

| Distro | Script | Manager | Notes |
|---|---|---|---|
| Debian / Ubuntu | `bootstrap-debian.sh` | apt-get | DEBIAN_FRONTEND=noninteractive |
| RHEL / Rocky / Alma / Fedora | `bootstrap-rhel.sh` | dnf | systemctl enable --now auditd |
| Amazon Linux 2 | `bootstrap-amzn2.sh` | yum | older RHEL-flavor; `audit` not `auditd` |

The scripts are intentionally not abstracted into a generic shell
"library" — the cost of an apt/dnf indirection layer in Bash exceeds
the duplication cost of three scripts that each total ~50 lines. When
package names diverge (`audit` vs `auditd`, `firewalld` vs `ufw`) the
divergence is honest in the script that uses it, not hidden behind a
case statement.

## What's deliberately not here

- **A SCAP/OVAL exporter.** SCAP is the standard format for
  compliance content; we ship custom JSON instead. The path to SCAP
  is straightforward — generate an XCCDF document at build time from
  the registry — but it would 5x the build dependencies and obscure
  the simple "click run, get JSON" loop. Anyone who needs SCAP can
  parse our JSON and emit XCCDF; the mapping is mechanical.
- **A scoring model.** Compliance benchmarks weight controls
  inconsistently across releases (CIS Level 1 vs Level 2 has shifted
  twice in the last five years). Putting a score on top would
  pretend a precision we don't have. The right artefact is a
  pass/fail count by category; the operator decides which fails are
  acceptable for their threat model.
- **An "auto-fix on next boot" hook.** Tempting, but the failure
  mode (a snippet with a typo bricks every host on reboot) is so
  bad that we explicitly require an interactive `remediate --apply`
  invocation. The provisioning scripts are the cloud-init-ready
  half; the audit half is always opt-in.
- **A Python plugin entry point.** `compliance_bootstrap.checks` is
  a regular package; if someone wants to register a third-party
  check they can call `register_check` from their own code. We
  consciously do not advertise an `entry_points` group, because the
  set of registered checks is part of the compliance contract — a
  policy targeting `cis-ubuntu-22` should produce identical output
  on every host that runs the same package version.
- **Concurrency.** The runner is sequential. The full audit on the
  GH Actions ubuntu-24.04 runner completes in well under a second;
  parallel evaluation would obscure log ordering for negligible
  wall-clock gain.

## Test strategy

- **Unit tests** (130) construct a fake root under `tmp_path` and
  call evaluators against it. No real I/O, no real subprocess calls,
  fast (~0.6 s for the suite).
- **Integration tests** (gated by `RUN_INTEGRATION=1`) build the
  multi-stage `target` image and run audit + remediate inside it.
  CI's `remediation-smoke` job runs this and asserts the post-fail
  count is strictly less than the pre-fail count.
- **shellcheck** (`-x` for `source` resolution) on every `.sh` file
  in `scripts/` and `src/.../snippets/` blocks the merge.
- **mypy strict** is mandatory on `src/`. Tests are mypy-checked but
  not strict (test fixtures lean on `Any` more than production code).
- **Coverage gate** at 80% (current: ~86%). The provision/ wrappers
  (which are thin shims over subprocess calls) get unit tests via
  mocks rather than counting on integration coverage.
