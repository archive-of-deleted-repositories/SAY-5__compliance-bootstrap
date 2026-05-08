"""Kernel check evaluators."""

from __future__ import annotations

from pathlib import Path

from compliance_bootstrap.checks import Status
from compliance_bootstrap.checks.kernel import (
    KernelAslr,
    KernelKptrRestrict,
    KernelProtectedLinks,
)


def _set_proc(root: Path, key: str, value: str) -> None:
    rel = key.replace(".", "/")
    target = root / "proc" / "sys" / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(value + "\n", encoding="utf-8")


class TestAslr:
    def test_pass(self, ctx_with_root):
        ctx = ctx_with_root("aslr_pass")
        _set_proc(ctx.root, "kernel.randomize_va_space", "2")
        assert KernelAslr().evaluate(ctx).status is Status.PASS

    def test_fail_one(self, ctx_with_root):
        ctx = ctx_with_root("aslr_one")
        _set_proc(ctx.root, "kernel.randomize_va_space", "1")
        result = KernelAslr().evaluate(ctx)
        assert result.status is Status.FAIL
        assert result.evidence["current"] == 1

    def test_unavailable(self, ctx_with_root):
        ctx = ctx_with_root("aslr_unavail")
        assert KernelAslr().evaluate(ctx).status is Status.UNAVAILABLE


class TestKptrRestrict:
    def test_pass_one(self, ctx_with_root):
        ctx = ctx_with_root("kptr_one")
        _set_proc(ctx.root, "kernel.kptr_restrict", "1")
        assert KernelKptrRestrict().evaluate(ctx).status is Status.PASS

    def test_pass_two(self, ctx_with_root):
        ctx = ctx_with_root("kptr_two")
        _set_proc(ctx.root, "kernel.kptr_restrict", "2")
        assert KernelKptrRestrict().evaluate(ctx).status is Status.PASS

    def test_fail_zero(self, ctx_with_root):
        ctx = ctx_with_root("kptr_zero")
        _set_proc(ctx.root, "kernel.kptr_restrict", "0")
        assert KernelKptrRestrict().evaluate(ctx).status is Status.FAIL


class TestProtectedLinks:
    def test_pass(self, ctx_with_root):
        ctx = ctx_with_root("plink_pass")
        _set_proc(ctx.root, "fs.protected_hardlinks", "1")
        _set_proc(ctx.root, "fs.protected_symlinks", "1")
        assert KernelProtectedLinks().evaluate(ctx).status is Status.PASS

    def test_fail_one_off(self, ctx_with_root):
        ctx = ctx_with_root("plink_one_off")
        _set_proc(ctx.root, "fs.protected_hardlinks", "1")
        _set_proc(ctx.root, "fs.protected_symlinks", "0")
        assert KernelProtectedLinks().evaluate(ctx).status is Status.FAIL

    def test_unavailable(self, ctx_with_root):
        ctx = ctx_with_root("plink_unavail")
        assert KernelProtectedLinks().evaluate(ctx).status is Status.UNAVAILABLE
