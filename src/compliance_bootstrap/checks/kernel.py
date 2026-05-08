"""Kernel-parameter checks (CIS Ubuntu 22.04 §1.6.*).

ASLR, kptr_restrict, and protected_hardlinks/symlinks are mitigations
configured via sysctl. We read /proc/sys directly (the live kernel
state) rather than parsing /etc/sysctl.d, since "configured but never
applied" is itself a deviation.
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


def _read_int(ctx: HostContext, key: str) -> int | None:
    rel = key.replace(".", "/")
    path = ctx.root / "proc" / "sys" / rel
    if not path.is_file():
        return None
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


@register_check
class KernelAslr(BaseCheck):
    check_id: ClassVar[str] = "kernel.aslr"
    category: ClassVar[str] = "kernel"
    cis_ref: ClassVar[str] = "CIS 1.6.3"
    description: ClassVar[str] = "ASLR is at full randomization (kernel.randomize_va_space=2)"

    def evaluate(self, ctx: HostContext) -> CheckResult:
        value = _read_int(ctx, "kernel.randomize_va_space")
        if value is None:
            return unavailable(self.check_id, "randomize_va_space not exposed")
        if value == 2:
            return passed(self.check_id, "randomize_va_space=2")
        return failed(
            self.check_id,
            f"randomize_va_space={value}; expected 2",
            remediation_id="kernel_aslr",
            current=value,
            expected=2,
        )


@register_check
class KernelKptrRestrict(BaseCheck):
    check_id: ClassVar[str] = "kernel.kptr_restrict"
    category: ClassVar[str] = "kernel"
    cis_ref: ClassVar[str] = "CIS 1.6.4"
    description: ClassVar[str] = "kernel.kptr_restrict >= 1 (hide kernel pointers from non-root)"

    def evaluate(self, ctx: HostContext) -> CheckResult:
        value = _read_int(ctx, "kernel.kptr_restrict")
        if value is None:
            return unavailable(self.check_id, "kptr_restrict not exposed")
        if value >= 1:
            return passed(self.check_id, f"kptr_restrict={value}")
        return failed(
            self.check_id,
            f"kptr_restrict={value}; expected >= 1",
            remediation_id="kernel_kptr_restrict",
            current=value,
            expected=">= 1",
        )


@register_check
class KernelProtectedLinks(BaseCheck):
    check_id: ClassVar[str] = "kernel.protected_links"
    category: ClassVar[str] = "kernel"
    cis_ref: ClassVar[str] = "CIS 1.6.5"
    description: ClassVar[str] = "fs.protected_hardlinks and fs.protected_symlinks both = 1"

    def evaluate(self, ctx: HostContext) -> CheckResult:
        hard = _read_int(ctx, "fs.protected_hardlinks")
        sym = _read_int(ctx, "fs.protected_symlinks")
        if hard is None or sym is None:
            return unavailable(self.check_id, "protected_hardlinks/symlinks not exposed")
        if hard == 1 and sym == 1:
            return passed(self.check_id, "protected_hardlinks=1, protected_symlinks=1")
        return failed(
            self.check_id,
            f"protected_hardlinks={hard}, protected_symlinks={sym}; both must be 1",
            remediation_id="kernel_protected_links",
            protected_hardlinks=hard,
            protected_symlinks=sym,
        )
