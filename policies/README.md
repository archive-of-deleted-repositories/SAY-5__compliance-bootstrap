# Policies

A policy is a YAML file that selects which checks are executed.

## Schema

```yaml
name: cis-ubuntu-22                 # policy id, also referenced by --policy
description: <one sentence>
enabled: [check_id, ...]            # checks to run
disabled: [check_id, ...]           # informational; loader does not consult
overrides:
  treat_unavailable_as_fail: false  # strict mode flag
```

## Adding a policy

1. Drop a YAML file in this directory.
2. Pass `--policy your-name --policies-dir policies/` to `audit`.
3. The `audit` command refuses to run a policy that names an unknown
   check — typos fail loudly rather than silently skipping.

## Resolution order

`compliance-bootstrap` looks for the policy file under `--policies-dir`
first (defaults to `./policies`), then under
`<package>/policies/`. The first match wins.
