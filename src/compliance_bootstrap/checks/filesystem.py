"""Filesystem-related CIS checks.

CIS Ubuntu 22.04 §1.1.* covers separate filesystems for `/tmp` and
`/var/log`, mount-option hardening (`nodev`, `nosuid`, `noexec`), and
disabling unused removable-media kernel modules.
"""

from __future__ import annotations

from typing import ClassVar

from compliance_bootstrap.settings import HostContext

from ._base import (
    BaseCheck,
    CheckResult,
    failed,
    passed,
    register_check,
    unavailable,
)


def _read_proc_mounts(ctx: HostContext) -> list[tuple[str, str, str, str]]:
    """Return parsed `/proc/mounts` rows: (source, target, fstype, options).

    Falls back to an empty list if the file is unreadable; the caller
    maps that to `unavailable`.
    """

    path = ctx.root / "proc" / "mounts"
    if not path.is_file():
        return []
    rows: list[tuple[str, str, str, str]] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = raw.split()
        if len(parts) < 4:
            continue
        rows.append((parts[0], parts[1], parts[2], parts[3]))
    return rows


def _find_mount(
    rows: list[tuple[str, str, str, str]], target: str
) -> tuple[str, str, str, str] | None:
    for row in rows:
        if row[1] == target:
            return row
    return None


@register_check
class TmpSeparate(BaseCheck):
    check_id: ClassVar[str] = "fs.tmp_separate"
    category: ClassVar[str] = "filesystem"
    cis_ref: ClassVar[str] = "CIS 1.1.2.1"
    description: ClassVar[str] = "/tmp is mounted as a separate filesystem"

    def evaluate(self, ctx: HostContext) -> CheckResult:
        rows = _read_proc_mounts(ctx)
        if not rows:
            return unavailable(self.check_id, "/proc/mounts unreadable")
        mount = _find_mount(rows, "/tmp")
        if mount is None:
            return failed(
                self.check_id,
                "/tmp is not a separate filesystem",
                remediation_id="fs_tmp_separate",
                target="/tmp",
            )
        return passed(self.check_id, "/tmp mounted separately", source=mount[0], fstype=mount[2])


@register_check
class TmpNoDev(BaseCheck):
    check_id: ClassVar[str] = "fs.tmp_nodev"
    category: ClassVar[str] = "filesystem"
    cis_ref: ClassVar[str] = "CIS 1.1.2.2"
    description: ClassVar[str] = "/tmp mount has nodev option"

    def evaluate(self, ctx: HostContext) -> CheckResult:
        rows = _read_proc_mounts(ctx)
        if not rows:
            return unavailable(self.check_id, "/proc/mounts unreadable")
        mount = _find_mount(rows, "/tmp")
        if mount is None:
            return failed(
                self.check_id,
                "/tmp not separate; cannot enforce nodev",
                remediation_id="fs_tmp_nodev",
            )
        opts = set(mount[3].split(","))
        if "nodev" in opts:
            return passed(self.check_id, "/tmp has nodev")
        return failed(
            self.check_id,
            "/tmp missing nodev",
            remediation_id="fs_tmp_nodev",
            options=sorted(opts),
        )


@register_check
class TmpNoSuid(BaseCheck):
    check_id: ClassVar[str] = "fs.tmp_nosuid"
    category: ClassVar[str] = "filesystem"
    cis_ref: ClassVar[str] = "CIS 1.1.2.3"
    description: ClassVar[str] = "/tmp mount has nosuid option"

    def evaluate(self, ctx: HostContext) -> CheckResult:
        rows = _read_proc_mounts(ctx)
        if not rows:
            return unavailable(self.check_id, "/proc/mounts unreadable")
        mount = _find_mount(rows, "/tmp")
        if mount is None:
            return failed(
                self.check_id,
                "/tmp not separate; cannot enforce nosuid",
                remediation_id="fs_tmp_nosuid",
            )
        opts = set(mount[3].split(","))
        if "nosuid" in opts:
            return passed(self.check_id, "/tmp has nosuid")
        return failed(
            self.check_id,
            "/tmp missing nosuid",
            remediation_id="fs_tmp_nosuid",
            options=sorted(opts),
        )


@register_check
class VarLogSeparate(BaseCheck):
    check_id: ClassVar[str] = "fs.var_log_separate"
    category: ClassVar[str] = "filesystem"
    cis_ref: ClassVar[str] = "CIS 1.1.5.1"
    description: ClassVar[str] = "/var/log is mounted as a separate filesystem"

    def evaluate(self, ctx: HostContext) -> CheckResult:
        rows = _read_proc_mounts(ctx)
        if not rows:
            return unavailable(self.check_id, "/proc/mounts unreadable")
        if _find_mount(rows, "/var/log") is None:
            return failed(
                self.check_id,
                "/var/log is not a separate filesystem",
                remediation_id="fs_var_log_separate",
            )
        return passed(self.check_id, "/var/log mounted separately")


@register_check
class UsbStorageDisabled(BaseCheck):
    check_id: ClassVar[str] = "fs.usb_storage_disabled"
    category: ClassVar[str] = "filesystem"
    cis_ref: ClassVar[str] = "CIS 1.1.10"
    description: ClassVar[str] = "usb-storage kernel module disabled (loadable but blacklisted)"

    def evaluate(self, ctx: HostContext) -> CheckResult:
        modprobe_dir = ctx.root / "etc" / "modprobe.d"
        if not modprobe_dir.is_dir():
            return unavailable(self.check_id, "/etc/modprobe.d missing")
        for entry in sorted(modprobe_dir.iterdir()):
            if not entry.is_file():
                continue
            try:
                text = entry.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("install usb-storage /bin/true") or stripped.startswith(
                    "blacklist usb-storage"
                ):
                    return passed(
                        self.check_id,
                        "usb-storage disabled",
                        file=str(entry.relative_to(ctx.root)),
                    )
        return failed(
            self.check_id,
            "usb-storage not blacklisted in /etc/modprobe.d",
            remediation_id="fs_usb_storage_disabled",
        )
