"""Filesystem check evaluators."""

from __future__ import annotations

from pathlib import Path

from compliance_bootstrap.checks import Status
from compliance_bootstrap.checks.filesystem import (
    TmpNoDev,
    TmpNoSuid,
    TmpSeparate,
    UsbStorageDisabled,
    VarLogSeparate,
)


def _write_mounts(root: Path, lines: list[str]) -> None:
    (root / "proc").mkdir(parents=True, exist_ok=True)
    (root / "proc" / "mounts").write_text("\n".join(lines) + "\n", encoding="utf-8")


class TestTmpSeparate:
    def test_pass_when_tmp_listed(self, ctx_with_root):
        ctx = ctx_with_root("tmp_pass")
        _write_mounts(
            ctx.root,
            ["/dev/sda1 / ext4 defaults 0 0", "tmpfs /tmp tmpfs nodev,nosuid 0 0"],
        )
        result = TmpSeparate().evaluate(ctx)
        assert result.status is Status.PASS
        assert result.evidence["fstype"] == "tmpfs"

    def test_fail_when_tmp_missing(self, ctx_with_root):
        ctx = ctx_with_root("tmp_fail")
        _write_mounts(ctx.root, ["/dev/sda1 / ext4 defaults 0 0"])
        result = TmpSeparate().evaluate(ctx)
        assert result.status is Status.FAIL
        assert result.remediation_id == "fs_tmp_separate"

    def test_unavailable_when_no_proc_mounts(self, ctx_with_root):
        ctx = ctx_with_root("tmp_unavail")
        # No proc/mounts written.
        result = TmpSeparate().evaluate(ctx)
        assert result.status is Status.UNAVAILABLE


class TestTmpOptions:
    def test_nodev_pass(self, ctx_with_root):
        ctx = ctx_with_root("opt_pass")
        _write_mounts(ctx.root, ["tmpfs /tmp tmpfs nodev,nosuid,noexec 0 0"])
        assert TmpNoDev().evaluate(ctx).status is Status.PASS
        assert TmpNoSuid().evaluate(ctx).status is Status.PASS

    def test_nodev_fail(self, ctx_with_root):
        ctx = ctx_with_root("opt_nodev_fail")
        _write_mounts(ctx.root, ["tmpfs /tmp tmpfs defaults 0 0"])
        result = TmpNoDev().evaluate(ctx)
        assert result.status is Status.FAIL
        assert "nodev" not in result.evidence["options"]

    def test_nodev_when_tmp_missing(self, ctx_with_root):
        ctx = ctx_with_root("opt_nodev_missing")
        _write_mounts(ctx.root, ["/dev/sda1 / ext4 defaults 0 0"])
        result = TmpNoDev().evaluate(ctx)
        assert result.status is Status.FAIL
        assert result.remediation_id == "fs_tmp_nodev"


class TestVarLogSeparate:
    def test_pass(self, ctx_with_root):
        ctx = ctx_with_root("varlog_pass")
        _write_mounts(
            ctx.root,
            ["/dev/sda1 / ext4 defaults 0 0", "/dev/sdb1 /var/log ext4 defaults 0 0"],
        )
        assert VarLogSeparate().evaluate(ctx).status is Status.PASS

    def test_fail(self, ctx_with_root):
        ctx = ctx_with_root("varlog_fail")
        _write_mounts(ctx.root, ["/dev/sda1 / ext4 defaults 0 0"])
        result = VarLogSeparate().evaluate(ctx)
        assert result.status is Status.FAIL


class TestUsbStorageDisabled:
    def test_pass_with_install_directive(self, ctx_with_root):
        ctx = ctx_with_root("usb_pass")
        d = ctx.root / "etc" / "modprobe.d"
        d.mkdir(parents=True, exist_ok=True)
        (d / "cis.conf").write_text("install usb-storage /bin/true\n", encoding="utf-8")
        assert UsbStorageDisabled().evaluate(ctx).status is Status.PASS

    def test_pass_with_blacklist_directive(self, ctx_with_root):
        ctx = ctx_with_root("usb_blacklist")
        d = ctx.root / "etc" / "modprobe.d"
        d.mkdir(parents=True, exist_ok=True)
        (d / "x.conf").write_text("blacklist usb-storage\n", encoding="utf-8")
        assert UsbStorageDisabled().evaluate(ctx).status is Status.PASS

    def test_fail_when_directory_empty(self, ctx_with_root):
        ctx = ctx_with_root("usb_fail")
        (ctx.root / "etc" / "modprobe.d").mkdir(parents=True, exist_ok=True)
        result = UsbStorageDisabled().evaluate(ctx)
        assert result.status is Status.FAIL

    def test_unavailable_when_directory_missing(self, ctx_with_root):
        ctx = ctx_with_root("usb_unavail")
        # ctx_with_root does not auto-create modprobe.d
        result = UsbStorageDisabled().evaluate(ctx)
        assert result.status is Status.UNAVAILABLE
