# Policies

A policy is a YAML file that selects which checks the audit will run.

```yaml
name: cis-ubuntu-22                 # policy id (and --policy argument)
description: <one sentence>
enabled: [check_id, ...]            # required
disabled: [check_id, ...]           # informational only
overrides:
  treat_unavailable_as_fail: false  # strict mode flag
```

## Resolution

`compliance-bootstrap` looks for the policy in this order:

1. `--policies-dir` (default `./policies`)
2. The package's bundled `compliance_bootstrap/policies/`

The first match wins. If neither directory contains a file named
`<policy>.yaml`, `audit` exits with an error.

## Validation

Loading is fail-loud:

- `enabled` is required and must be a list of strings
- Every id under `enabled` must correspond to a registered check;
  unknown ids raise immediately rather than silently skipping
- Unknown top-level keys are ignored (forward compatibility)

## Strict mode

`overrides.treat_unavailable_as_fail: true` promotes any
`unavailable` result to `fail`. Use this on hosts where every check is
expected to be measurable (production servers running a known OS).
The default for `cis-ubuntu-22` is the lenient four-state model.

## Authoring

To add a policy:

1. Drop a YAML file in `policies/`.
2. Run `compliance-bootstrap audit --policy <name>` to validate.
3. Commit the file.

To see what's available:

```bash
compliance-bootstrap list-checks
```

## Example: a minimal policy

```yaml
name: ssh-only
description: Only audit SSH-related checks
enabled:
  - ssh.permit_root_login
  - ssh.password_authentication
  - ssh.max_auth_tries
```
