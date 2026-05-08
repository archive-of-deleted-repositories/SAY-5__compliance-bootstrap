"""Package check evaluators."""

from __future__ import annotations

from pathlib import Path

from compliance_bootstrap.checks import Status
from compliance_bootstrap.checks.packages import (
    PkgRequired,
    PkgSignatureVerification,
    PkgUnattendedUpgrades,
    PkgUnwantedAbsent,
)


def _write_dpkg_status(root: Path, packages: list[tuple[str, bool]]) -> None:
    """Each (name, installed) pair becomes a stanza in dpkg/status."""

    target = root / "var" / "lib" / "dpkg" / "status"
    target.parent.mkdir(parents=True, exist_ok=True)
    blocks = []
    for name, installed in packages:
        status = "install ok installed" if installed else "deinstall ok config-files"
        blocks.append(f"Package: {name}\nStatus: {status}\nVersion: 1.0\n")
    target.write_text("\n".join(blocks), encoding="utf-8")


class TestRequired:
    def test_pass(self, ctx_with_root):
        ctx = ctx_with_root("req_pass")
        _write_dpkg_status(
            ctx.root,
            [("auditd", True), ("ufw", True), ("openssh-server", True)],
        )
        assert PkgRequired().evaluate(ctx).status is Status.PASS

    def test_fail_missing(self, ctx_with_root):
        ctx = ctx_with_root("req_missing")
        _write_dpkg_status(ctx.root, [("auditd", True), ("ufw", False)])
        result = PkgRequired().evaluate(ctx)
        assert result.status is Status.FAIL
        assert "ufw" in result.evidence["missing"]
        assert "openssh-server" in result.evidence["missing"]

    def test_unavailable_no_dpkg(self, ctx_with_root):
        ctx = ctx_with_root("req_unavail")
        assert PkgRequired().evaluate(ctx).status is Status.UNAVAILABLE


class TestUnwanted:
    def test_pass(self, ctx_with_root):
        ctx = ctx_with_root("unw_pass")
        _write_dpkg_status(ctx.root, [("openssh-server", True)])
        assert PkgUnwantedAbsent().evaluate(ctx).status is Status.PASS

    def test_fail_telnet_present(self, ctx_with_root):
        ctx = ctx_with_root("unw_fail")
        _write_dpkg_status(ctx.root, [("telnet", True), ("openssh-server", True)])
        result = PkgUnwantedAbsent().evaluate(ctx)
        assert result.status is Status.FAIL
        assert "telnet" in result.evidence["installed"]


class TestUnattendedUpgrades:
    def test_pass(self, ctx_with_root):
        ctx = ctx_with_root("uu_pass")
        cfg = ctx.root / "etc" / "apt" / "apt.conf.d" / "20auto-upgrades"
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text(
            'APT::Periodic::Update-Package-Lists "1";\n' 'APT::Periodic::Unattended-Upgrade "1";\n',
            encoding="utf-8",
        )
        assert PkgUnattendedUpgrades().evaluate(ctx).status is Status.PASS

    def test_fail_disabled(self, ctx_with_root):
        ctx = ctx_with_root("uu_fail")
        cfg = ctx.root / "etc" / "apt" / "apt.conf.d" / "20auto-upgrades"
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text('APT::Periodic::Unattended-Upgrade "0";\n', encoding="utf-8")
        assert PkgUnattendedUpgrades().evaluate(ctx).status is Status.FAIL

    def test_fail_missing(self, ctx_with_root):
        ctx = ctx_with_root("uu_missing")
        assert PkgUnattendedUpgrades().evaluate(ctx).status is Status.FAIL


class TestSignatureVerification:
    def test_pass_default(self, ctx_with_root):
        ctx = ctx_with_root("sig_pass")
        (ctx.root / "etc" / "apt").mkdir(parents=True, exist_ok=True)
        assert PkgSignatureVerification().evaluate(ctx).status is Status.PASS

    def test_fail_when_relaxed(self, ctx_with_root):
        ctx = ctx_with_root("sig_fail")
        d = ctx.root / "etc" / "apt" / "apt.conf.d"
        d.mkdir(parents=True, exist_ok=True)
        (d / "99-allow.conf").write_text(
            'Acquire::AllowInsecureRepositories "true";\n',
            encoding="utf-8",
        )
        result = PkgSignatureVerification().evaluate(ctx)
        assert result.status is Status.FAIL
        assert result.evidence["offenders"]
