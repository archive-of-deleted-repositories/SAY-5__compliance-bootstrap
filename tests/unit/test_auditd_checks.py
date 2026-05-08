"""Auditd check evaluators."""

from __future__ import annotations

import os
from pathlib import Path

from compliance_bootstrap.checks import Status
from compliance_bootstrap.checks.auditd import (
    AuditdEnabled,
    AuditdInstalled,
    AuditdLogDirMode,
    AuditdSudoersRules,
)


def _write(root: Path, rel: str, body: str) -> None:
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body, encoding="utf-8")


class TestInstalled:
    def test_pass_with_binary(self, ctx_with_root):
        ctx = ctx_with_root("audit_pass_bin")
        (ctx.root / "etc" / "audit").mkdir(parents=True, exist_ok=True)
        sbin = ctx.root / "sbin"
        sbin.mkdir(parents=True, exist_ok=True)
        (sbin / "auditd").write_text("#!/bin/true\n")
        assert AuditdInstalled().evaluate(ctx).status is Status.PASS

    def test_pass_with_binaries_set(self, ctx_with_root):
        ctx = ctx_with_root("audit_pass_set", binaries=("auditctl",))
        (ctx.root / "etc" / "audit").mkdir(parents=True, exist_ok=True)
        assert AuditdInstalled().evaluate(ctx).status is Status.PASS

    def test_fail_without_anything(self, ctx_with_root):
        ctx = ctx_with_root("audit_fail")
        assert AuditdInstalled().evaluate(ctx).status is Status.FAIL


class TestEnabled:
    def test_pass_e1(self, ctx_with_root):
        ctx = ctx_with_root("audit_e1")
        _write(ctx.root, "etc/audit/rules.d/99.rules", "-e 1\n")
        assert AuditdEnabled().evaluate(ctx).status is Status.PASS

    def test_pass_e2(self, ctx_with_root):
        ctx = ctx_with_root("audit_e2")
        _write(ctx.root, "etc/audit/rules.d/99.rules", "-e 2\n")
        assert AuditdEnabled().evaluate(ctx).status is Status.PASS

    def test_fail_no_e_directive(self, ctx_with_root):
        ctx = ctx_with_root("audit_no_e")
        _write(ctx.root, "etc/audit/rules.d/01.rules", "-w /etc/passwd -p wa\n")
        assert AuditdEnabled().evaluate(ctx).status is Status.FAIL

    def test_unavailable_when_no_rules(self, ctx_with_root):
        ctx = ctx_with_root("audit_no_rules")
        assert AuditdEnabled().evaluate(ctx).status is Status.UNAVAILABLE


class TestLogDirMode:
    def test_pass_0750(self, ctx_with_root):
        ctx = ctx_with_root("logdir_0750")
        d = ctx.root / "var" / "log" / "audit"
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o750)
        assert AuditdLogDirMode().evaluate(ctx).status is Status.PASS

    def test_fail_0755(self, ctx_with_root):
        ctx = ctx_with_root("logdir_0755")
        d = ctx.root / "var" / "log" / "audit"
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o755)
        result = AuditdLogDirMode().evaluate(ctx)
        assert result.status is Status.FAIL
        assert result.evidence["current"] == "0755"

    def test_unavailable_when_no_dir(self, ctx_with_root):
        ctx = ctx_with_root("logdir_missing")
        assert AuditdLogDirMode().evaluate(ctx).status is Status.UNAVAILABLE


class TestSudoersRules:
    def test_pass(self, ctx_with_root):
        ctx = ctx_with_root("watch_pass")
        _write(
            ctx.root,
            "etc/audit/rules.d/50-watches.rules",
            "-w /etc/sudoers -p wa -k scope\n-w /etc/passwd -p wa -k id\n",
        )
        assert AuditdSudoersRules().evaluate(ctx).status is Status.PASS

    def test_fail_only_sudoers(self, ctx_with_root):
        ctx = ctx_with_root("watch_partial")
        _write(ctx.root, "etc/audit/rules.d/50.rules", "-w /etc/sudoers -p wa\n")
        result = AuditdSudoersRules().evaluate(ctx)
        assert result.status is Status.FAIL
        assert "/etc/passwd" in result.evidence["missing"]

    def test_unavailable_when_no_rules(self, ctx_with_root):
        ctx = ctx_with_root("watch_unavail")
        assert AuditdSudoersRules().evaluate(ctx).status is Status.UNAVAILABLE
