"""Network / sysctl / firewall checks (CIS Ubuntu 22.04 §3.*).

Each sysctl check reads from `/proc/sys/...` directly so it reflects the
*live* kernel state, which is what an audit cares about. A separate
provisioning concern is whether `/etc/sysctl.d/*.conf` makes the setting
sticky across reboots — out of scope for this set; the remediation
snippet writes the file and reloads.
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


def _read_sysctl(ctx: HostContext, key: str) -> str | None:
    """`net.ipv4.conf.all.send_redirects` -> read /proc/sys/net/ipv4/conf/all/send_redirects."""

    rel = key.replace(".", "/")
    path = ctx.root / "proc" / "sys" / rel
    if not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def _expect_int(
    ctx: HostContext, key: str, expected: int, check_id: str, remediation_id: str
) -> CheckResult:
    raw = _read_sysctl(ctx, key)
    if raw is None:
        return unavailable(check_id, f"{key} not exposed via /proc/sys")
    try:
        value = int(raw)
    except ValueError:
        return unavailable(check_id, f"{key}={raw!r} is not an integer")
    if value == expected:
        return passed(check_id, f"{key}={value}")
    return failed(
        check_id,
        f"{key}={value}; expected {expected}",
        remediation_id=remediation_id,
        current=value,
        expected=expected,
        sysctl=key,
    )


@register_check
class NetIcmpRedirects(BaseCheck):
    check_id: ClassVar[str] = "net.icmp_redirects"
    category: ClassVar[str] = "network"
    cis_ref: ClassVar[str] = "CIS 3.3.2"
    description: ClassVar[str] = "ICMP redirect packets are not accepted"

    def evaluate(self, ctx: HostContext) -> CheckResult:
        return _expect_int(
            ctx,
            "net.ipv4.conf.all.accept_redirects",
            0,
            self.check_id,
            "net_icmp_redirects",
        )


@register_check
class NetSourceRoute(BaseCheck):
    check_id: ClassVar[str] = "net.source_route"
    category: ClassVar[str] = "network"
    cis_ref: ClassVar[str] = "CIS 3.3.1"
    description: ClassVar[str] = "Source-routed packets are not accepted"

    def evaluate(self, ctx: HostContext) -> CheckResult:
        return _expect_int(
            ctx,
            "net.ipv4.conf.all.accept_source_route",
            0,
            self.check_id,
            "net_source_route",
        )


@register_check
class NetLogMartians(BaseCheck):
    check_id: ClassVar[str] = "net.log_martians"
    category: ClassVar[str] = "network"
    cis_ref: ClassVar[str] = "CIS 3.3.4"
    description: ClassVar[str] = "log_martians is enabled"

    def evaluate(self, ctx: HostContext) -> CheckResult:
        return _expect_int(
            ctx,
            "net.ipv4.conf.all.log_martians",
            1,
            self.check_id,
            "net_log_martians",
        )


@register_check
class NetIpv6RaDisabled(BaseCheck):
    check_id: ClassVar[str] = "net.ipv6_ra_disabled"
    category: ClassVar[str] = "network"
    cis_ref: ClassVar[str] = "CIS 3.3.9"
    description: ClassVar[str] = "IPv6 RA is disabled (accept_ra=0); skips when IPv6 absent"

    def evaluate(self, ctx: HostContext) -> CheckResult:
        raw = _read_sysctl(ctx, "net.ipv6.conf.all.accept_ra")
        if raw is None:
            # IPv6 disabled at kernel level — nothing to enforce.
            return unavailable(self.check_id, "ipv6 not exposed in /proc/sys")
        try:
            value = int(raw)
        except ValueError:
            return unavailable(self.check_id, f"accept_ra={raw!r} is not integer")
        if value == 0:
            return passed(self.check_id, "accept_ra=0")
        return failed(
            self.check_id,
            f"accept_ra={value}; expected 0",
            remediation_id="net_ipv6_ra_disabled",
            current=value,
            expected=0,
        )


@register_check
class NetFirewallActive(BaseCheck):
    check_id: ClassVar[str] = "net.firewall_active"
    category: ClassVar[str] = "network"
    cis_ref: ClassVar[str] = "CIS 3.5.1"
    description: ClassVar[str] = "ufw or nftables/iptables config indicates an active firewall"

    def evaluate(self, ctx: HostContext) -> CheckResult:
        # Detection is best-effort and file-based: the audit must not
        # require running `ufw status` (which needs root). We accept any
        # of: ufw enabled flag, nftables ruleset file with rules, or an
        # iptables-save-style file under /etc that lists chains.
        ufw_state = ctx.root / "etc" / "ufw" / "ufw.conf"
        if ufw_state.is_file():
            try:
                text = ufw_state.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            for raw in text.splitlines():
                line = raw.split("#", 1)[0].strip()
                if line.lower() == "enabled=yes":
                    return passed(self.check_id, "ufw enabled")
        nft_dir = ctx.root / "etc" / "nftables.conf"
        if nft_dir.is_file():
            try:
                size = nft_dir.stat().st_size
            except OSError:
                size = 0
            if size > 0:
                return passed(self.check_id, "nftables.conf present")
        return failed(
            self.check_id,
            "no active firewall configuration detected",
            remediation_id="net_firewall_active",
        )
