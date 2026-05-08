"""PAM / password-quality checks (CIS Ubuntu 22.04 §5.3.*).

These checks read `/etc/security/pwquality.conf`, the PAM stack
fragments under `/etc/pam.d/`, and `/etc/login.defs`. We do not parse
PAM stacks fully — the sequencing of `auth` lines matters, but for a
compliance audit we only need to confirm that the relevant module is
present with the relevant arguments.
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


def _parse_kv_file(path: Path) -> dict[str, str]:
    """Parse simple `key = value` configs (pwquality.conf, login.defs).

    Both formats accept `=` or whitespace as the separator and use `#`
    comments. We are tolerant of either form and ignore malformed lines.
    """

    out: dict[str, str] = {}
    if not path.is_file():
        return out
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for raw in text.splitlines():
        stripped = raw.split("#", 1)[0].strip()
        if not stripped:
            continue
        if "=" in stripped:
            key, _, value = stripped.partition("=")
        else:
            parts = stripped.split(None, 1)
            if len(parts) != 2:
                continue
            key, value = parts[0], parts[1]
        out[key.strip().lower()] = value.strip()
    return out


@register_check
class PamPasswordMinlen(BaseCheck):
    check_id: ClassVar[str] = "pam.password_minlen"
    category: ClassVar[str] = "pam"
    cis_ref: ClassVar[str] = "CIS 5.3.1"
    description: ClassVar[str] = "pwquality minlen is at least 14"

    def evaluate(self, ctx: HostContext) -> CheckResult:
        cfg = _parse_kv_file(ctx.root / "etc" / "security" / "pwquality.conf")
        if "minlen" not in cfg:
            return failed(
                self.check_id,
                "pwquality.conf missing minlen",
                remediation_id="pam_password_minlen",
                expected=">= 14",
            )
        try:
            minlen = int(cfg["minlen"])
        except ValueError:
            return failed(
                self.check_id,
                f"minlen={cfg['minlen']!r} is not an integer",
                remediation_id="pam_password_minlen",
                current=cfg["minlen"],
                expected=">= 14",
            )
        if minlen >= 14:
            return passed(self.check_id, f"minlen={minlen}")
        return failed(
            self.check_id,
            f"minlen={minlen}; expected >= 14",
            remediation_id="pam_password_minlen",
            current=minlen,
            expected=">= 14",
        )


@register_check
class PamPasswordClasses(BaseCheck):
    check_id: ClassVar[str] = "pam.password_classes"
    category: ClassVar[str] = "pam"
    cis_ref: ClassVar[str] = "CIS 5.3.2"
    description: ClassVar[str] = "pwquality minclass is at least 4"

    def evaluate(self, ctx: HostContext) -> CheckResult:
        cfg = _parse_kv_file(ctx.root / "etc" / "security" / "pwquality.conf")
        if "minclass" not in cfg:
            return failed(
                self.check_id,
                "pwquality.conf missing minclass",
                remediation_id="pam_password_classes",
                expected=">= 4",
            )
        try:
            minclass = int(cfg["minclass"])
        except ValueError:
            return failed(
                self.check_id,
                f"minclass={cfg['minclass']!r} is not an integer",
                remediation_id="pam_password_classes",
                current=cfg["minclass"],
                expected=">= 4",
            )
        if minclass >= 4:
            return passed(self.check_id, f"minclass={minclass}")
        return failed(
            self.check_id,
            f"minclass={minclass}; expected >= 4",
            remediation_id="pam_password_classes",
            current=minclass,
            expected=">= 4",
        )


@register_check
class PamPasswordReuse(BaseCheck):
    check_id: ClassVar[str] = "pam.password_reuse"
    category: ClassVar[str] = "pam"
    cis_ref: ClassVar[str] = "CIS 5.3.3"
    description: ClassVar[str] = "PAM blocks reuse of the last 5 passwords"

    def evaluate(self, ctx: HostContext) -> CheckResult:
        # The remember=N argument can live on either pam_pwhistory.so or
        # pam_unix.so. We scan the password stack, prefer pwhistory, and
        # accept either.
        stack = ctx.root / "etc" / "pam.d" / "common-password"
        if not stack.is_file():
            return unavailable(self.check_id, "/etc/pam.d/common-password missing")
        text = stack.read_text(encoding="utf-8", errors="replace")
        remember: int | None = None
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line.startswith("password"):
                continue
            tokens = line.split()
            if not any(tok.endswith(("pam_pwhistory.so", "pam_unix.so")) for tok in tokens):
                continue
            for tok in tokens:
                if tok.startswith("remember="):
                    try:
                        remember = int(tok.split("=", 1)[1])
                    except ValueError:
                        remember = None
        if remember is None:
            return failed(
                self.check_id,
                "no remember=N argument found in password stack",
                remediation_id="pam_password_reuse",
                expected=">= 5",
            )
        if remember >= 5:
            return passed(self.check_id, f"remember={remember}")
        return failed(
            self.check_id,
            f"remember={remember}; expected >= 5",
            remediation_id="pam_password_reuse",
            current=remember,
            expected=">= 5",
        )


@register_check
class PamAccountLockout(BaseCheck):
    check_id: ClassVar[str] = "pam.account_lockout"
    category: ClassVar[str] = "pam"
    cis_ref: ClassVar[str] = "CIS 5.3.2"
    description: ClassVar[str] = (
        "Account locks after at most 5 failed attempts (faillock or tally2)"
    )

    def evaluate(self, ctx: HostContext) -> CheckResult:
        # Ubuntu 22.04 ships pam_faillock; older systems use pam_tally2.
        # We accept either and look for `deny=N` with N <= 5.
        for stack_name in ("common-auth", "system-auth"):
            stack = ctx.root / "etc" / "pam.d" / stack_name
            if not stack.is_file():
                continue
            text = stack.read_text(encoding="utf-8", errors="replace")
            for raw in text.splitlines():
                line = raw.split("#", 1)[0].strip()
                if not line.startswith("auth"):
                    continue
                tokens = line.split()
                if not any(tok.endswith(("pam_faillock.so", "pam_tally2.so")) for tok in tokens):
                    continue
                for tok in tokens:
                    if tok.startswith("deny="):
                        try:
                            deny = int(tok.split("=", 1)[1])
                        except ValueError:
                            continue
                        if deny <= 5:
                            return passed(self.check_id, f"deny={deny}", source=stack_name)
                        return failed(
                            self.check_id,
                            f"deny={deny}; expected <= 5",
                            remediation_id="pam_account_lockout",
                            current=deny,
                            expected="<= 5",
                        )
        return failed(
            self.check_id,
            "no faillock/tally2 deny= directive found",
            remediation_id="pam_account_lockout",
            expected="<= 5",
        )
