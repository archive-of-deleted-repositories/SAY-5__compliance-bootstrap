"""SSH check evaluators."""

from __future__ import annotations

from pathlib import Path

from compliance_bootstrap.checks import Status
from compliance_bootstrap.checks.ssh_config import (
    SshBanner,
    SshClientAliveInterval,
    SshMaxAuthTries,
    SshMaxSessions,
    SshPasswordAuthentication,
    SshPermitRootLogin,
    SshProtocol2,
    SshX11Forwarding,
)


def _write_sshd(root: Path, body: str) -> None:
    (root / "etc" / "ssh").mkdir(parents=True, exist_ok=True)
    (root / "etc" / "ssh" / "sshd_config").write_text(body, encoding="utf-8")


def test_unavailable_when_no_sshd_config(ctx_with_root):
    ctx = ctx_with_root("ssh_unavail")
    assert SshPermitRootLogin().evaluate(ctx).status is Status.UNAVAILABLE


class TestPermitRootLogin:
    def test_pass(self, ctx_with_root):
        ctx = ctx_with_root("ssh_root_pass")
        _write_sshd(ctx.root, "PermitRootLogin no\n")
        assert SshPermitRootLogin().evaluate(ctx).status is Status.PASS

    def test_fail_default(self, ctx_with_root):
        ctx = ctx_with_root("ssh_root_default")
        _write_sshd(ctx.root, "# nothing\n")
        result = SshPermitRootLogin().evaluate(ctx)
        assert result.status is Status.FAIL
        assert result.evidence["current"] == "prohibit-password"

    def test_fail_yes(self, ctx_with_root):
        ctx = ctx_with_root("ssh_root_yes")
        _write_sshd(ctx.root, "PermitRootLogin yes\n")
        result = SshPermitRootLogin().evaluate(ctx)
        assert result.status is Status.FAIL
        assert result.remediation_id == "ssh_permit_root_login"


class TestPasswordAuth:
    def test_pass(self, ctx_with_root):
        ctx = ctx_with_root("ssh_pw_pass")
        _write_sshd(ctx.root, "PasswordAuthentication no\n")
        assert SshPasswordAuthentication().evaluate(ctx).status is Status.PASS

    def test_fail_default_yes(self, ctx_with_root):
        ctx = ctx_with_root("ssh_pw_default")
        _write_sshd(ctx.root, "\n")
        result = SshPasswordAuthentication().evaluate(ctx)
        assert result.status is Status.FAIL
        assert result.evidence["current"] == "yes"


class TestNumericDirectives:
    def test_max_auth_tries_pass(self, ctx_with_root):
        ctx = ctx_with_root("max_auth_pass")
        _write_sshd(ctx.root, "MaxAuthTries 3\n")
        assert SshMaxAuthTries().evaluate(ctx).status is Status.PASS

    def test_max_auth_tries_fail(self, ctx_with_root):
        ctx = ctx_with_root("max_auth_fail")
        _write_sshd(ctx.root, "MaxAuthTries 6\n")
        assert SshMaxAuthTries().evaluate(ctx).status is Status.FAIL

    def test_max_auth_tries_non_integer(self, ctx_with_root):
        ctx = ctx_with_root("max_auth_bad")
        _write_sshd(ctx.root, "MaxAuthTries abc\n")
        assert SshMaxAuthTries().evaluate(ctx).status is Status.FAIL

    def test_client_alive_pass(self, ctx_with_root):
        ctx = ctx_with_root("alive_pass")
        _write_sshd(ctx.root, "ClientAliveInterval 200\n")
        assert SshClientAliveInterval().evaluate(ctx).status is Status.PASS

    def test_client_alive_fail_zero(self, ctx_with_root):
        ctx = ctx_with_root("alive_zero")
        _write_sshd(ctx.root, "ClientAliveInterval 0\n")
        assert SshClientAliveInterval().evaluate(ctx).status is Status.FAIL

    def test_max_sessions_pass(self, ctx_with_root):
        ctx = ctx_with_root("sessions_pass")
        _write_sshd(ctx.root, "MaxSessions 5\n")
        assert SshMaxSessions().evaluate(ctx).status is Status.PASS

    def test_max_sessions_fail(self, ctx_with_root):
        ctx = ctx_with_root("sessions_fail")
        _write_sshd(ctx.root, "MaxSessions 25\n")
        assert SshMaxSessions().evaluate(ctx).status is Status.FAIL


class TestProtocolAndX11:
    def test_protocol_default_pass(self, ctx_with_root):
        ctx = ctx_with_root("proto_default")
        _write_sshd(ctx.root, "# default\n")
        assert SshProtocol2().evaluate(ctx).status is Status.PASS

    def test_protocol_explicit_2(self, ctx_with_root):
        ctx = ctx_with_root("proto_2")
        _write_sshd(ctx.root, "Protocol 2\n")
        assert SshProtocol2().evaluate(ctx).status is Status.PASS

    def test_protocol_1_fails(self, ctx_with_root):
        ctx = ctx_with_root("proto_1")
        _write_sshd(ctx.root, "Protocol 1\n")
        assert SshProtocol2().evaluate(ctx).status is Status.FAIL

    def test_x11_default(self, ctx_with_root):
        ctx = ctx_with_root("x11_default")
        _write_sshd(ctx.root, "# nothing\n")
        # X11Forwarding default is no.
        assert SshX11Forwarding().evaluate(ctx).status is Status.PASS

    def test_x11_yes_fails(self, ctx_with_root):
        ctx = ctx_with_root("x11_yes")
        _write_sshd(ctx.root, "X11Forwarding yes\n")
        assert SshX11Forwarding().evaluate(ctx).status is Status.FAIL


class TestBanner:
    def test_pass(self, ctx_with_root):
        ctx = ctx_with_root("banner_pass")
        banner = ctx.root / "etc" / "issue.net"
        banner.write_text("Authorized only.\n", encoding="utf-8")
        _write_sshd(ctx.root, "Banner /etc/issue.net\n")
        assert SshBanner().evaluate(ctx).status is Status.PASS

    def test_fail_none(self, ctx_with_root):
        ctx = ctx_with_root("banner_none")
        _write_sshd(ctx.root, "Banner none\n")
        assert SshBanner().evaluate(ctx).status is Status.FAIL

    def test_fail_missing_file(self, ctx_with_root):
        ctx = ctx_with_root("banner_missing")
        _write_sshd(ctx.root, "Banner /etc/issue.net\n")
        assert SshBanner().evaluate(ctx).status is Status.FAIL


def test_drop_in_overrides_main(ctx_with_root):
    """Last directive wins; drop-ins are loaded after the main file."""

    ctx = ctx_with_root("drop_in")
    _write_sshd(ctx.root, "PermitRootLogin yes\n")
    drop = ctx.root / "etc" / "ssh" / "sshd_config.d"
    drop.mkdir(parents=True, exist_ok=True)
    (drop / "20-cis.conf").write_text("PermitRootLogin no\n", encoding="utf-8")
    assert SshPermitRootLogin().evaluate(ctx).status is Status.PASS
