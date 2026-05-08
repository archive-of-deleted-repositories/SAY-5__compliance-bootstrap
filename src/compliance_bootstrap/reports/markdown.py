"""Markdown report renderer.

Reads the same dict that `json_emit.build_report` produces. Fail rows
include the remediation snippet inline as a fenced code block so a
reader can paste-and-run after a quick read.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

from compliance_bootstrap.checks import Status
from compliance_bootstrap.remediation import remediation_snippet

_STATUS_BADGE = {
    Status.PASS.value: "PASS",
    Status.FAIL.value: "FAIL",
    Status.SKIP.value: "SKIP",
    Status.UNAVAILABLE.value: "UNAVAIL",
}


def render_markdown(report: dict[str, Any]) -> str:
    host = report["host"]
    summary = report["summary"]
    lines: list[str] = []
    lines.append(f"# compliance-bootstrap audit — {host.get('hostname', 'unknown')}")
    lines.append("")
    lines.append(f"- policy: `{report['policy']}`")
    lines.append(f"- host: `{host.get('hostname', 'unknown')}`")
    lines.append(
        f"- os: `{host.get('os', 'unknown')}` — kernel `{host.get('kernel', 'unknown')}` — arch `{host.get('arch', 'unknown')}`"
    )
    lines.append(f"- started_at: `{report['started_at']}`")
    lines.append("")
    lines.append(
        "- summary: "
        f"{summary['pass']} pass / {summary['fail']} fail / "
        f"{summary['skip']} skip / {summary['unavailable']} unavailable "
        f"({summary['total']} total)"
    )
    lines.append("")

    by_category: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for check in report["checks"]:
        # Category is the prefix before the first dot.
        category = check["id"].split(".", 1)[0]
        by_category[category].append(check)

    for category in sorted(by_category):
        lines.append(f"## {category}")
        lines.append("")
        lines.append("| Check | Status | Detail |")
        lines.append("|---|---|---|")
        for check in by_category[category]:
            badge = _STATUS_BADGE.get(check["status"], check["status"].upper())
            detail = check["summary"].replace("|", "\\|")
            lines.append(f"| `{check['id']}` | {badge} | {detail} |")
        lines.append("")

    fails = [c for c in report["checks"] if c["status"] == Status.FAIL.value]
    if fails:
        lines.append("## Remediation snippets")
        lines.append("")
        lines.append(
            "Each failing check below includes the Bash snippet that fixes the deviation. "
            "Run them in order, or invoke `compliance-bootstrap remediate --apply` to "
            "apply them all (pulled from the same source tree)."
        )
        lines.append("")
        for check in fails:
            rid = check.get("remediation_id")
            lines.append(f"### `{check['id']}` — {check['summary']}")
            lines.append("")
            if rid:
                snippet = remediation_snippet(rid)
                if snippet is None:
                    lines.append(f"_no remediation snippet registered for id `{rid}`_")
                else:
                    lines.append("```bash")
                    lines.append(snippet.rstrip())
                    lines.append("```")
            else:
                lines.append("_no remediation registered_")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def emit_markdown(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_markdown(report), encoding="utf-8")
