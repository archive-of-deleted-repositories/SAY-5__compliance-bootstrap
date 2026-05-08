"""auditd checks (CIS Ubuntu 22.04 §4.1.*).

We do not invoke `auditctl` (would require root); we read the same files
the daemon reads at startup. That keeps the audit pull-based and the
check unit-testable from fixtures.
"""

from __future__ import annotations

from pathlib import Path
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


def _audit_rules_corpus(ctx: HostContext) -> str:
    """Concatenate every `*.rules` file under /etc/audit/rules.d, plus
    `/etc/audit/audit.rules`, into one searchable blob.
    """

    parts: list[str] = []
    base = ctx.root / "etc" / "audit"
    rules_d = base / "rules.d"
    if rules_d.is_dir():
        for entry in sorted(rules_d.glob("*.rules")):
            try:
                parts.append(entry.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
    extra = base / "audit.rules"
    if extra.is_file():
        try:
            parts.append(extra.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            pass
    return "\n".join(parts)


@register_check
class AuditdInstalled(BaseCheck):
    check_id: ClassVar[str] = "auditd.installed"
    category: ClassVar[str] = "auditd"
    cis_ref: ClassVar[str] = "CIS 4.1.1.1"
    description: ClassVar[str] = "auditd binary present and config dir exists"

    def evaluate(self, ctx: HostContext) -> CheckResult:
        config_dir = ctx.root / "etc" / "audit"
        binary = ctx.root / "sbin" / "auditd"
        # Detection is path-based so unit tests can construct a fake root.
        if config_dir.is_dir() and (binary.is_file() or ctx.has("auditctl")):
            return passed(self.check_id, "auditd present")
        return failed(
            self.check_id,
            "auditd not installed",
            remediation_id="auditd_installed",
        )


@register_check
class AuditdEnabled(BaseCheck):
    check_id: ClassVar[str] = "auditd.enabled"
    category: ClassVar[str] = "auditd"
    cis_ref: ClassVar[str] = "CIS 4.1.1.2"
    description: ClassVar[str] = "auditd is enabled in audit.rules (-e 1 or -e 2)"

    def evaluate(self, ctx: HostContext) -> CheckResult:
        corpus = _audit_rules_corpus(ctx)
        if not corpus.strip():
            return unavailable(self.check_id, "no audit rules found")
        for raw in corpus.splitlines():
            line = raw.strip()
            if line.startswith("-e "):
                try:
                    flag = int(line.split(None, 1)[1])
                except ValueError:
                    continue
                if flag in (1, 2):
                    return passed(self.check_id, f"-e {flag}")
        return failed(
            self.check_id,
            "no `-e 1` or `-e 2` directive in audit rules",
            remediation_id="auditd_enabled",
        )


@register_check
class AuditdLogDirMode(BaseCheck):
    check_id: ClassVar[str] = "auditd.log_dir_mode"
    category: ClassVar[str] = "auditd"
    cis_ref: ClassVar[str] = "CIS 4.1.3.1"
    description: ClassVar[str] = "/var/log/audit is mode 0750 or stricter"

    def evaluate(self, ctx: HostContext) -> CheckResult:
        log_dir = ctx.root / "var" / "log" / "audit"
        if not log_dir.is_dir():
            return unavailable(self.check_id, "/var/log/audit missing")
        try:
            mode = log_dir.stat().st_mode & 0o777
        except OSError as exc:
            return unavailable(self.check_id, f"stat() failed: {exc}")
        # 0750 means group and world bits beyond r-x for owner are off.
        # CIS says "0750 or more strict".
        if mode & 0o027 == 0:
            return passed(self.check_id, f"mode=0{mode:o}")
        return failed(
            self.check_id,
            f"mode=0{mode:o}; expected 0750 or stricter",
            remediation_id="auditd_log_dir_mode",
            current=f"0{mode:o}",
            expected="0750",
        )


@register_check
class AuditdSudoersRules(BaseCheck):
    check_id: ClassVar[str] = "auditd.sudoers_rules"
    category: ClassVar[str] = "auditd"
    cis_ref: ClassVar[str] = "CIS 4.1.3.6"
    description: ClassVar[str] = "audit rules monitor sudoers and passwd changes"

    def evaluate(self, ctx: HostContext) -> CheckResult:
        corpus = _audit_rules_corpus(ctx)
        if not corpus.strip():
            return unavailable(self.check_id, "no audit rules found")
        # Expect at least one watch on /etc/sudoers and one on /etc/passwd.
        sudoers_seen = False
        passwd_seen = False
        for raw in corpus.splitlines():
            line = raw.strip()
            if not line.startswith("-w "):
                continue
            target = line.split()[1] if len(line.split()) > 1 else ""
            if target == "/etc/sudoers":
                sudoers_seen = True
            elif target == "/etc/passwd":
                passwd_seen = True
        if sudoers_seen and passwd_seen:
            return passed(self.check_id, "watches present for sudoers and passwd")
        missing: list[str] = []
        if not sudoers_seen:
            missing.append("/etc/sudoers")
        if not passwd_seen:
            missing.append("/etc/passwd")
        return failed(
            self.check_id,
            f"missing watches: {', '.join(missing)}",
            remediation_id="auditd_sudoers_rules",
            missing=missing,
        )


# Module-level utility kept for tests of compose helpers.
def _path_exists(path: Path) -> bool:
    return path.exists()
