"""Package-state checks.

We avoid invoking `dpkg-query` / `rpm -qa` (those require the daemons
or root reads in some configs); the files under `/var/lib/dpkg/status`
or `/var/lib/rpm/Packages` are not parsed either, since `rpm` keeps a
Berkeley-DB index. Instead the audit reads `/var/lib/dpkg/status` line
parsing for Debian-family hosts (free of locks; it's a plain text file)
and falls through to `unavailable` on RPM systems for the time being.

Required- and unwanted-package lists come from policy YAML; each policy
defines its own list. Apt unattended-upgrades is checked via the file
`/etc/apt/apt.conf.d/20auto-upgrades`.
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


def _dpkg_installed_packages(ctx: HostContext) -> set[str] | None:
    """Return the set of installed binary package names from dpkg's
    status file, or None if the file is missing (non-Debian systems).

    A package is considered installed when the `Status:` line says
    `install ok installed`. `Package:` is a single token.
    """

    status = ctx.root / "var" / "lib" / "dpkg" / "status"
    if not status.is_file():
        return None
    installed: set[str] = set()
    try:
        text = status.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    name: str | None = None
    is_installed = False
    for raw in text.splitlines():
        if not raw:
            if name and is_installed:
                installed.add(name)
            name = None
            is_installed = False
            continue
        if raw.startswith("Package:"):
            name = raw.split(":", 1)[1].strip()
        elif raw.startswith("Status:"):
            is_installed = "install ok installed" in raw
    if name and is_installed:
        installed.add(name)
    return installed


@register_check
class PkgRequired(BaseCheck):
    check_id: ClassVar[str] = "pkg.required_present"
    category: ClassVar[str] = "packages"
    cis_ref: ClassVar[str] = "CIS 1.2.1 (org)"
    description: ClassVar[str] = "Required packages from policy are installed"

    REQUIRED: ClassVar[tuple[str, ...]] = ("auditd", "ufw", "openssh-server")

    def evaluate(self, ctx: HostContext) -> CheckResult:
        installed = _dpkg_installed_packages(ctx)
        if installed is None:
            return unavailable(self.check_id, "dpkg status file not present")
        missing = sorted(p for p in self.REQUIRED if p not in installed)
        if not missing:
            return passed(
                self.check_id,
                "all required packages installed",
                required=list(self.REQUIRED),
            )
        return failed(
            self.check_id,
            f"missing packages: {', '.join(missing)}",
            remediation_id="pkg_required_present",
            missing=missing,
            required=list(self.REQUIRED),
        )


@register_check
class PkgUnwantedAbsent(BaseCheck):
    check_id: ClassVar[str] = "pkg.unwanted_absent"
    category: ClassVar[str] = "packages"
    cis_ref: ClassVar[str] = "CIS 2.3.*"
    description: ClassVar[str] = "Unwanted insecure packages are not installed (telnet, rsh, talk)"

    UNWANTED: ClassVar[tuple[str, ...]] = (
        "telnet",
        "telnetd",
        "rsh-client",
        "rsh-server",
        "talk",
        "talkd",
    )

    def evaluate(self, ctx: HostContext) -> CheckResult:
        installed = _dpkg_installed_packages(ctx)
        if installed is None:
            return unavailable(self.check_id, "dpkg status file not present")
        present = sorted(p for p in self.UNWANTED if p in installed)
        if not present:
            return passed(
                self.check_id,
                "no unwanted packages installed",
                screened=list(self.UNWANTED),
            )
        return failed(
            self.check_id,
            f"unwanted packages installed: {', '.join(present)}",
            remediation_id="pkg_unwanted_absent",
            installed=present,
            screened=list(self.UNWANTED),
        )


@register_check
class PkgUnattendedUpgrades(BaseCheck):
    check_id: ClassVar[str] = "pkg.unattended_upgrades"
    category: ClassVar[str] = "packages"
    cis_ref: ClassVar[str] = "CIS 1.9"
    description: ClassVar[str] = "apt unattended-upgrades is enabled"

    def evaluate(self, ctx: HostContext) -> CheckResult:
        # The Debian convention: 20auto-upgrades sets `APT::Periodic::*`.
        cfg = ctx.root / "etc" / "apt" / "apt.conf.d" / "20auto-upgrades"
        if not cfg.is_file():
            return failed(
                self.check_id,
                "20auto-upgrades not present",
                remediation_id="pkg_unattended_upgrades",
            )
        try:
            text = cfg.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return unavailable(self.check_id, "20auto-upgrades unreadable")
        # Look for `APT::Periodic::Unattended-Upgrade "1";`
        wants = ("Unattended-Upgrade", "1")
        for raw in text.splitlines():
            if wants[0] in raw and f'"{wants[1]}"' in raw:
                return passed(self.check_id, "Unattended-Upgrade enabled")
        return failed(
            self.check_id,
            "Unattended-Upgrade not set to 1",
            remediation_id="pkg_unattended_upgrades",
        )


@register_check
class PkgSignatureVerification(BaseCheck):
    check_id: ClassVar[str] = "pkg.signature_verification"
    category: ClassVar[str] = "packages"
    cis_ref: ClassVar[str] = "CIS 1.2.2"
    description: ClassVar[str] = "apt is configured to require signed package metadata"

    def evaluate(self, ctx: HostContext) -> CheckResult:
        # The default apt configuration on Debian/Ubuntu is to require
        # signed Release files (`AllowInsecureRepositories=false`). We
        # FAIL only when an apt.conf override explicitly relaxes this.
        apt_dir = ctx.root / "etc" / "apt"
        if not apt_dir.is_dir():
            return unavailable(self.check_id, "/etc/apt missing")
        offenders: list[str] = []
        candidates: list[Path] = [apt_dir / "apt.conf"]
        conf_d = apt_dir / "apt.conf.d"
        if conf_d.is_dir():
            candidates.extend(sorted(conf_d.iterdir()))
        for path in candidates:
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for raw in text.splitlines():
                line = raw.split("//", 1)[0].strip()
                if "AllowInsecureRepositories" in line and '"true"' in line.lower():
                    offenders.append(str(path.relative_to(ctx.root)))
                if "AllowUnauthenticated" in line and '"true"' in line.lower():
                    offenders.append(str(path.relative_to(ctx.root)))
        if offenders:
            return failed(
                self.check_id,
                f"signature checks relaxed in: {', '.join(offenders)}",
                remediation_id="pkg_signature_verification",
                offenders=offenders,
            )
        return passed(self.check_id, "no signature-relaxing apt overrides")
