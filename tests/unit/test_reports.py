"""Report builder + Markdown renderer tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from compliance_bootstrap.checks import CheckResult, Status
from compliance_bootstrap.reports import build_report, emit_json, emit_markdown
from compliance_bootstrap.reports.markdown import render_markdown
from compliance_bootstrap.settings import HostContext


def _ctx() -> HostContext:
    return HostContext(
        hostname="h",
        os_id="ubuntu",
        os_version="22.04",
        os_pretty="Ubuntu 22.04",
        kernel="6.1",
        arch="x86_64",
        root=Path("/"),
        binaries=frozenset(),
    )


def _results() -> list[CheckResult]:
    return [
        CheckResult(
            "ssh.permit_root_login",
            Status.FAIL,
            "yes",
            evidence={"current": "yes"},
            remediation_id="ssh_permit_root_login",
        ),
        CheckResult("fs.tmp_separate", Status.PASS, "ok"),
        CheckResult("kernel.aslr", Status.UNAVAILABLE, "unexposed"),
        CheckResult("net.firewall_active", Status.SKIP, "skipped"),
    ]


def test_build_report_summary_counts():
    report = build_report(
        ctx=_ctx(),
        policy="cis-ubuntu-22",
        results=_results(),
        started_at=datetime(2026, 5, 1, 12, 0, 0, tzinfo=UTC),
    )
    assert report["summary"]["pass"] == 1
    assert report["summary"]["fail"] == 1
    assert report["summary"]["skip"] == 1
    assert report["summary"]["unavailable"] == 1
    assert report["summary"]["total"] == 4
    assert report["started_at"] == "2026-05-01T12:00:00Z"
    assert report["policy"] == "cis-ubuntu-22"


def test_build_report_sorts_checks_by_id():
    report = build_report(ctx=_ctx(), policy="cis", results=_results())
    ids = [c["id"] for c in report["checks"]]
    assert ids == sorted(ids)


def test_emit_json_round_trips(tmp_path):
    report = build_report(ctx=_ctx(), policy="cis", results=_results())
    path = tmp_path / "out.json"
    emit_json(report, path)
    parsed = json.loads(path.read_text(encoding="utf-8"))
    assert parsed["summary"] == report["summary"]


def test_render_markdown_lists_categories():
    report = build_report(ctx=_ctx(), policy="cis", results=_results())
    md = render_markdown(report)
    assert "## ssh" in md
    assert "## kernel" in md
    assert "## fs" in md
    assert "1 pass / 1 fail / 1 skip / 1 unavailable" in md


def test_render_markdown_includes_remediation_for_fails():
    report = build_report(ctx=_ctx(), policy="cis", results=_results())
    md = render_markdown(report)
    assert "## Remediation snippets" in md
    assert "PermitRootLogin no" in md  # the snippet body is inlined


def test_emit_markdown_writes_file(tmp_path):
    report = build_report(ctx=_ctx(), policy="cis", results=_results())
    path = tmp_path / "out.md"
    emit_markdown(report, path)
    text = path.read_text(encoding="utf-8")
    assert "compliance-bootstrap audit" in text


def test_pipe_in_summary_is_escaped():
    """A summary string containing `|` must not break the Markdown table."""

    results = [
        CheckResult("x.y", Status.FAIL, "thing|with|pipes", remediation_id=None),
    ]
    report = build_report(ctx=_ctx(), policy="cis", results=results)
    md = render_markdown(report)
    # Each pipe in the cell should have been backslash-escaped.
    assert "thing\\|with\\|pipes" in md
