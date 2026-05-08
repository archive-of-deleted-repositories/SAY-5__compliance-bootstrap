"""End-to-end CLI smoke tests via Click's testing harness."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from compliance_bootstrap.cli import main


def test_help_lists_subcommands():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    for sub in ("audit", "remediate", "report", "list-checks", "list-remediations"):
        assert sub in result.output


def test_list_checks_runs():
    runner = CliRunner()
    result = runner.invoke(main, ["list-checks"])
    assert result.exit_code == 0
    assert "ssh.permit_root_login" in result.output


def test_list_remediations_runs():
    runner = CliRunner()
    result = runner.invoke(main, ["list-remediations"])
    assert result.exit_code == 0
    assert "ssh_permit_root_login" in result.output


def test_audit_against_empty_root_emits_reports(tmp_path: Path):
    """Running against an empty fake root must produce a report, even if
    every check is unavailable. Many checks will FAIL because the
    fixture lacks /etc/ssh/sshd_config et al, but the runner must not
    crash and must emit valid JSON."""

    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "proc").mkdir()
    (root / "etc" / "os-release").write_text(
        'ID=ubuntu\nVERSION_ID="22.04"\nPRETTY_NAME="Ubuntu"\n', encoding="utf-8"
    )
    out = tmp_path / "out"
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "audit",
            "--policy",
            "cis-ubuntu-22",
            "--root",
            str(root),
            "--json",
            str(out / "a.json"),
            "--md",
            str(out / "a.md"),
        ],
    )
    # Many checks fail or are unavailable on an empty root — exit 1 is expected.
    assert result.exit_code in (0, 1)
    parsed = json.loads((out / "a.json").read_text(encoding="utf-8"))
    assert parsed["summary"]["total"] >= 30
    assert (out / "a.md").exists()


def test_remediate_dry_run_reports_actions(tmp_path: Path):
    """Dry-run must list the snippets it *would* run without running them."""

    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "proc").mkdir()
    (root / "etc" / "os-release").write_text(
        'ID=ubuntu\nVERSION_ID="22.04"\nPRETTY_NAME="Ubuntu"\n', encoding="utf-8"
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["remediate", "--policy", "cis-ubuntu-22", "--root", str(root)],
    )
    assert "[dry-run]" in result.output
