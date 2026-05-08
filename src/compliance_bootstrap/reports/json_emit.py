"""JSON report builder and serializer.

The shape of the report is documented in README.md and pinned by
`tests/unit/test_reports.py`. Keys are sorted at every level so diffs
are stable across runs (handy when committing sample-runs to git).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from compliance_bootstrap.checks import CheckResult, Status
from compliance_bootstrap.remediation import remediation_text
from compliance_bootstrap.settings import HostContext


def _summary(results: list[CheckResult]) -> dict[str, int]:
    counts = {s.value: 0 for s in Status}
    for r in results:
        counts[r.status.value] += 1
    counts["total"] = len(results)
    return counts


def build_report(
    *,
    ctx: HostContext,
    policy: str,
    results: list[CheckResult],
    started_at: datetime | None = None,
) -> dict[str, Any]:
    started = started_at or datetime.now(UTC)
    return {
        "schema_version": 1,
        "host": ctx.to_meta(),
        "policy": policy,
        "started_at": started.isoformat().replace("+00:00", "Z"),
        "summary": _summary(results),
        "checks": [
            {
                **r.to_dict(),
                "remediation": remediation_text(r.remediation_id) if r.remediation_id else None,
            }
            for r in sorted(results, key=lambda r: r.check_id)
        ],
    }


def emit_json(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
