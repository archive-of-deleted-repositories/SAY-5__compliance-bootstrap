"""SSH daemon configuration checks (CIS Ubuntu 22.04 §5.2.*).

The check parses `/etc/ssh/sshd_config` plus any `Include`d drop-in
files under `/etc/ssh/sshd_config.d/`. Last directive wins, matching
sshd semantics. Comments (lines starting with `#`) and blank lines are
ignored. Keywords are case-insensitive, values preserve case.
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


def _parse_sshd_config(ctx: HostContext) -> dict[str, str] | None:
    """Return last-directive-wins keyword -> value, or None if missing."""

    base = ctx.root / "etc" / "ssh" / "sshd_config"
    if not base.is_file():
        return None
    files: list[Path] = [base]
    drop_in = ctx.root / "etc" / "ssh" / "sshd_config.d"
    if drop_in.is_dir():
        files.extend(sorted(p for p in drop_in.glob("*.conf") if p.is_file()))
    config: dict[str, str] = {}
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            keyword, value = parts
            config[keyword.lower()] = value.strip()
    return config


@register_check
class SshProtocol2(BaseCheck):
    check_id: ClassVar[str] = "ssh.protocol_2"
    category: ClassVar[str] = "ssh"
    cis_ref: ClassVar[str] = "CIS 5.2.1"
    description: ClassVar[str] = "sshd is built for protocol 2 only (no Protocol 1 directive)"

    def evaluate(self, ctx: HostContext) -> CheckResult:
        cfg = _parse_sshd_config(ctx)
        if cfg is None:
            return unavailable(self.check_id, "/etc/ssh/sshd_config missing")
        # OpenSSH 7+ removed protocol 1 entirely. The check fails only if
        # someone explicitly forced Protocol 1 back in.
        protocol = cfg.get("protocol")
        if protocol is None or protocol.strip() == "2":
            return passed(self.check_id, "protocol 2 only")
        return failed(
            self.check_id,
            f"Protocol set to {protocol!r}; expected 2",
            remediation_id="ssh_protocol_2",
            current=protocol,
            expected="2",
        )


@register_check
class SshPermitRootLogin(BaseCheck):
    check_id: ClassVar[str] = "ssh.permit_root_login"
    category: ClassVar[str] = "ssh"
    cis_ref: ClassVar[str] = "CIS 5.2.8"
    description: ClassVar[str] = "PermitRootLogin is no"

    def evaluate(self, ctx: HostContext) -> CheckResult:
        cfg = _parse_sshd_config(ctx)
        if cfg is None:
            return unavailable(self.check_id, "/etc/ssh/sshd_config missing")
        # OpenSSH default is `prohibit-password`; CIS demands an explicit `no`.
        current = cfg.get("permitrootlogin", "prohibit-password")
        if current == "no":
            return passed(self.check_id, "PermitRootLogin=no")
        return failed(
            self.check_id,
            f"PermitRootLogin={current}; expected no",
            remediation_id="ssh_permit_root_login",
            current=current,
            expected="no",
        )


@register_check
class SshPasswordAuthentication(BaseCheck):
    check_id: ClassVar[str] = "ssh.password_authentication"
    category: ClassVar[str] = "ssh"
    cis_ref: ClassVar[str] = "CIS 5.2.10"
    description: ClassVar[str] = "PasswordAuthentication is no (key-based auth only)"

    def evaluate(self, ctx: HostContext) -> CheckResult:
        cfg = _parse_sshd_config(ctx)
        if cfg is None:
            return unavailable(self.check_id, "/etc/ssh/sshd_config missing")
        current = cfg.get("passwordauthentication", "yes")
        if current == "no":
            return passed(self.check_id, "PasswordAuthentication=no")
        return failed(
            self.check_id,
            f"PasswordAuthentication={current}; expected no",
            remediation_id="ssh_password_authentication",
            current=current,
            expected="no",
        )


@register_check
class SshMaxAuthTries(BaseCheck):
    check_id: ClassVar[str] = "ssh.max_auth_tries"
    category: ClassVar[str] = "ssh"
    cis_ref: ClassVar[str] = "CIS 5.2.7"
    description: ClassVar[str] = "MaxAuthTries is at most 4"

    def evaluate(self, ctx: HostContext) -> CheckResult:
        cfg = _parse_sshd_config(ctx)
        if cfg is None:
            return unavailable(self.check_id, "/etc/ssh/sshd_config missing")
        current_raw = cfg.get("maxauthtries", "6")
        try:
            current = int(current_raw)
        except ValueError:
            return failed(
                self.check_id,
                f"MaxAuthTries={current_raw!r} is not an integer",
                remediation_id="ssh_max_auth_tries",
                current=current_raw,
                expected="<= 4",
            )
        if current <= 4:
            return passed(self.check_id, f"MaxAuthTries={current}")
        return failed(
            self.check_id,
            f"MaxAuthTries={current}; expected <= 4",
            remediation_id="ssh_max_auth_tries",
            current=current,
            expected="<= 4",
        )


@register_check
class SshClientAliveInterval(BaseCheck):
    check_id: ClassVar[str] = "ssh.client_alive_interval"
    category: ClassVar[str] = "ssh"
    cis_ref: ClassVar[str] = "CIS 5.2.16"
    description: ClassVar[str] = "ClientAliveInterval is between 1 and 300 seconds"

    def evaluate(self, ctx: HostContext) -> CheckResult:
        cfg = _parse_sshd_config(ctx)
        if cfg is None:
            return unavailable(self.check_id, "/etc/ssh/sshd_config missing")
        current_raw = cfg.get("clientaliveinterval", "0")
        try:
            current = int(current_raw)
        except ValueError:
            return failed(
                self.check_id,
                f"ClientAliveInterval={current_raw!r} is not an integer",
                remediation_id="ssh_client_alive_interval",
                current=current_raw,
                expected="1..300",
            )
        if 1 <= current <= 300:
            return passed(self.check_id, f"ClientAliveInterval={current}")
        return failed(
            self.check_id,
            f"ClientAliveInterval={current}; expected 1..300",
            remediation_id="ssh_client_alive_interval",
            current=current,
            expected="1..300",
        )


@register_check
class SshX11Forwarding(BaseCheck):
    check_id: ClassVar[str] = "ssh.x11_forwarding"
    category: ClassVar[str] = "ssh"
    cis_ref: ClassVar[str] = "CIS 5.2.6"
    description: ClassVar[str] = "X11Forwarding is no"

    def evaluate(self, ctx: HostContext) -> CheckResult:
        cfg = _parse_sshd_config(ctx)
        if cfg is None:
            return unavailable(self.check_id, "/etc/ssh/sshd_config missing")
        current = cfg.get("x11forwarding", "no")
        if current == "no":
            return passed(self.check_id, "X11Forwarding=no")
        return failed(
            self.check_id,
            f"X11Forwarding={current}; expected no",
            remediation_id="ssh_x11_forwarding",
            current=current,
            expected="no",
        )


@register_check
class SshMaxSessions(BaseCheck):
    check_id: ClassVar[str] = "ssh.max_sessions"
    category: ClassVar[str] = "ssh"
    cis_ref: ClassVar[str] = "CIS 5.2.22"
    description: ClassVar[str] = "MaxSessions is at most 10"

    def evaluate(self, ctx: HostContext) -> CheckResult:
        cfg = _parse_sshd_config(ctx)
        if cfg is None:
            return unavailable(self.check_id, "/etc/ssh/sshd_config missing")
        current_raw = cfg.get("maxsessions", "10")
        try:
            current = int(current_raw)
        except ValueError:
            return failed(
                self.check_id,
                f"MaxSessions={current_raw!r} is not an integer",
                remediation_id="ssh_max_sessions",
                current=current_raw,
                expected="<= 10",
            )
        if current <= 10:
            return passed(self.check_id, f"MaxSessions={current}")
        return failed(
            self.check_id,
            f"MaxSessions={current}; expected <= 10",
            remediation_id="ssh_max_sessions",
            current=current,
            expected="<= 10",
        )


@register_check
class SshBanner(BaseCheck):
    check_id: ClassVar[str] = "ssh.banner"
    category: ClassVar[str] = "ssh"
    cis_ref: ClassVar[str] = "CIS 5.2.21"
    description: ClassVar[str] = "Banner directive points to a readable file"

    def evaluate(self, ctx: HostContext) -> CheckResult:
        cfg = _parse_sshd_config(ctx)
        if cfg is None:
            return unavailable(self.check_id, "/etc/ssh/sshd_config missing")
        current = cfg.get("banner", "none")
        if current.lower() in {"none", ""}:
            return failed(
                self.check_id,
                "Banner not configured",
                remediation_id="ssh_banner",
                current=current,
                expected="path to banner file",
            )
        # Banner path is an absolute file in real installs; resolve under
        # ctx.root to support fixture trees in tests.
        banner_path = (ctx.root / current.lstrip("/")).resolve()
        if banner_path.is_file():
            return passed(self.check_id, f"Banner={current}")
        return failed(
            self.check_id,
            f"Banner path {current!r} not readable",
            remediation_id="ssh_banner",
            current=current,
            expected="path to readable file",
        )
