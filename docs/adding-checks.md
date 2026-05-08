# Adding a check

A check is a small class with four pieces of metadata and an
`evaluate(ctx) -> CheckResult`.

## Skeleton

```python
from typing import ClassVar

from compliance_bootstrap.checks._base import (
    BaseCheck,
    CheckResult,
    failed,
    passed,
    register_check,
    unavailable,
)
from compliance_bootstrap.settings import HostContext


@register_check
class MyCheck(BaseCheck):
    check_id: ClassVar[str] = "category.short_id"
    category: ClassVar[str] = "category"
    cis_ref: ClassVar[str] = "CIS X.Y.Z"
    description: ClassVar[str] = "what this check enforces"

    def evaluate(self, ctx: HostContext) -> CheckResult:
        path = ctx.root / "etc" / "thing"
        if not path.is_file():
            return unavailable(self.check_id, "/etc/thing missing")
        if path.read_text(encoding="utf-8").strip() == "ok":
            return passed(self.check_id, "thing is ok")
        return failed(
            self.check_id,
            "thing is not ok",
            remediation_id="my_check",
            current="not-ok",
            expected="ok",
        )
```

Then:

1. Import the module from `src/compliance_bootstrap/checks/__init__.py`
   so the registration side-effect runs.
2. Add a Bash snippet at
   `src/compliance_bootstrap/remediation/snippets/my_check.sh` whose
   first non-shebang line is `# summary: <one sentence>`.
3. Add `category.short_id` to `policies/cis-ubuntu-22.yaml` under
   `enabled:`.
4. Write unit tests under `tests/unit/test_<category>_checks.py`
   covering pass / fail / unavailable.

## Why `ctx.root`?

Every filesystem read goes through `ctx.root / ...` so unit tests can
construct a fixture tree under `tmp_path` and pass it as the audit
root. Production code passes `Path("/")`, which collapses to the real
root.

## Conventions

- `evidence` dicts are small and JSON-serialisable (str/int/bool/list)
- `remediation_id` matches the snippet filename (without `.sh`)
- Always set `remediation_id` on `fail`; never on `pass | skip | unavailable`
- Prefer `failed(...)`, `passed(...)`, `skipped(...)`, `unavailable(...)`
  helpers over building `CheckResult` directly — they enforce the
  evidence-vs-remediation invariant
