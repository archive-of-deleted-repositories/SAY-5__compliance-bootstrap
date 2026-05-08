"""PAM check evaluators."""

from __future__ import annotations

from compliance_bootstrap.checks import Status
from compliance_bootstrap.checks.pam import (
    PamAccountLockout,
    PamPasswordClasses,
    PamPasswordMinlen,
    PamPasswordReuse,
)


def _write(root, rel, body):
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body, encoding="utf-8")


class TestPwQuality:
    def test_minlen_pass(self, ctx_with_root):
        ctx = ctx_with_root("minlen_pass")
        _write(ctx.root, "etc/security/pwquality.conf", "minlen = 14\n")
        assert PamPasswordMinlen().evaluate(ctx).status is Status.PASS

    def test_minlen_fail_below(self, ctx_with_root):
        ctx = ctx_with_root("minlen_below")
        _write(ctx.root, "etc/security/pwquality.conf", "minlen = 8\n")
        result = PamPasswordMinlen().evaluate(ctx)
        assert result.status is Status.FAIL
        assert result.evidence["current"] == 8

    def test_minlen_fail_missing(self, ctx_with_root):
        ctx = ctx_with_root("minlen_missing")
        _write(ctx.root, "etc/security/pwquality.conf", "# nothing\n")
        result = PamPasswordMinlen().evaluate(ctx)
        assert result.status is Status.FAIL

    def test_minlen_non_integer(self, ctx_with_root):
        ctx = ctx_with_root("minlen_bad")
        _write(ctx.root, "etc/security/pwquality.conf", "minlen = oops\n")
        assert PamPasswordMinlen().evaluate(ctx).status is Status.FAIL

    def test_minclass_pass(self, ctx_with_root):
        ctx = ctx_with_root("minclass_pass")
        _write(ctx.root, "etc/security/pwquality.conf", "minclass=4\n")
        assert PamPasswordClasses().evaluate(ctx).status is Status.PASS

    def test_minclass_fail(self, ctx_with_root):
        ctx = ctx_with_root("minclass_fail")
        _write(ctx.root, "etc/security/pwquality.conf", "minclass = 2\n")
        assert PamPasswordClasses().evaluate(ctx).status is Status.FAIL


class TestPasswordReuse:
    def test_pass_pwhistory(self, ctx_with_root):
        ctx = ctx_with_root("reuse_pass")
        _write(
            ctx.root,
            "etc/pam.d/common-password",
            "password required pam_pwhistory.so remember=5\npassword required pam_unix.so\n",
        )
        assert PamPasswordReuse().evaluate(ctx).status is Status.PASS

    def test_pass_pam_unix_remember(self, ctx_with_root):
        ctx = ctx_with_root("reuse_pam_unix")
        _write(
            ctx.root,
            "etc/pam.d/common-password",
            "password required pam_unix.so sha512 remember=10\n",
        )
        assert PamPasswordReuse().evaluate(ctx).status is Status.PASS

    def test_fail_low_remember(self, ctx_with_root):
        ctx = ctx_with_root("reuse_low")
        _write(
            ctx.root,
            "etc/pam.d/common-password",
            "password required pam_pwhistory.so remember=2\n",
        )
        result = PamPasswordReuse().evaluate(ctx)
        assert result.status is Status.FAIL
        assert result.evidence["current"] == 2

    def test_fail_no_directive(self, ctx_with_root):
        ctx = ctx_with_root("reuse_none")
        _write(ctx.root, "etc/pam.d/common-password", "password required pam_unix.so sha512\n")
        assert PamPasswordReuse().evaluate(ctx).status is Status.FAIL

    def test_unavailable_when_missing_stack(self, ctx_with_root):
        ctx = ctx_with_root("reuse_missing")
        assert PamPasswordReuse().evaluate(ctx).status is Status.UNAVAILABLE


class TestAccountLockout:
    def test_pass_faillock(self, ctx_with_root):
        ctx = ctx_with_root("lock_pass")
        _write(
            ctx.root,
            "etc/pam.d/common-auth",
            "auth required pam_faillock.so preauth silent deny=5 unlock_time=900\n",
        )
        assert PamAccountLockout().evaluate(ctx).status is Status.PASS

    def test_fail_high_deny(self, ctx_with_root):
        ctx = ctx_with_root("lock_high")
        _write(
            ctx.root,
            "etc/pam.d/common-auth",
            "auth required pam_faillock.so deny=20\n",
        )
        result = PamAccountLockout().evaluate(ctx)
        assert result.status is Status.FAIL
        assert result.evidence["current"] == 20

    def test_fail_no_directive(self, ctx_with_root):
        ctx = ctx_with_root("lock_none")
        _write(ctx.root, "etc/pam.d/common-auth", "auth required pam_unix.so\n")
        assert PamAccountLockout().evaluate(ctx).status is Status.FAIL
