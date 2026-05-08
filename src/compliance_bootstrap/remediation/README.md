# Remediation snippets

Each `.sh` file in `snippets/` fixes one specific check deviation. The file
name (without extension) is the `remediation_id` returned by the matching
`Check` evaluator.

## Conventions

- First non-shebang line is `# summary: <one sentence>`. The JSON report
  uses this string verbatim.
- `set -euo pipefail` is required (enforced by shellcheck via the
  `lint-sh` CI job).
- Idempotent: running twice must produce no further change. The
  integration test loops every snippet through twice and asserts the
  second run is a no-op.
- No `apt-get update` inside the snippet unless the snippet *needs* the
  index; bootstrap scripts already updated it.
- Snippets assume root or `sudo` is available; the runner does not
  prepend `sudo` for them.

## Hash audit trail

`remediation.snippet_hash(id)` returns the SHA-256 of the snippet body.
The `remediate` command logs the hash before applying, so a downstream
log scanner can prove which exact snippet ran on a given host.
