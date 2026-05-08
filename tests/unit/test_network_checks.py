"""Network check evaluators."""

from __future__ import annotations

from pathlib import Path

from compliance_bootstrap.checks import Status
from compliance_bootstrap.checks.network import (
    NetFirewallActive,
    NetIcmpRedirects,
    NetIpv6RaDisabled,
    NetLogMartians,
    NetSourceRoute,
)


def _set_sysctl(root: Path, key: str, value: str) -> None:
    rel = key.replace(".", "/")
    target = root / "proc" / "sys" / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(value + "\n", encoding="utf-8")


class TestSysctlChecks:
    def test_icmp_redirects_pass(self, ctx_with_root):
        ctx = ctx_with_root("icmp_pass")
        _set_sysctl(ctx.root, "net.ipv4.conf.all.accept_redirects", "0")
        assert NetIcmpRedirects().evaluate(ctx).status is Status.PASS

    def test_icmp_redirects_fail(self, ctx_with_root):
        ctx = ctx_with_root("icmp_fail")
        _set_sysctl(ctx.root, "net.ipv4.conf.all.accept_redirects", "1")
        assert NetIcmpRedirects().evaluate(ctx).status is Status.FAIL

    def test_icmp_redirects_unavailable(self, ctx_with_root):
        ctx = ctx_with_root("icmp_unavail")
        assert NetIcmpRedirects().evaluate(ctx).status is Status.UNAVAILABLE

    def test_source_route_pass(self, ctx_with_root):
        ctx = ctx_with_root("src_route_pass")
        _set_sysctl(ctx.root, "net.ipv4.conf.all.accept_source_route", "0")
        assert NetSourceRoute().evaluate(ctx).status is Status.PASS

    def test_log_martians_fail(self, ctx_with_root):
        ctx = ctx_with_root("martians_fail")
        _set_sysctl(ctx.root, "net.ipv4.conf.all.log_martians", "0")
        assert NetLogMartians().evaluate(ctx).status is Status.FAIL


class TestIpv6Ra:
    def test_pass(self, ctx_with_root):
        ctx = ctx_with_root("ra_pass")
        _set_sysctl(ctx.root, "net.ipv6.conf.all.accept_ra", "0")
        assert NetIpv6RaDisabled().evaluate(ctx).status is Status.PASS

    def test_fail(self, ctx_with_root):
        ctx = ctx_with_root("ra_fail")
        _set_sysctl(ctx.root, "net.ipv6.conf.all.accept_ra", "1")
        assert NetIpv6RaDisabled().evaluate(ctx).status is Status.FAIL

    def test_unavailable_when_ipv6_off(self, ctx_with_root):
        ctx = ctx_with_root("ra_unavail")
        assert NetIpv6RaDisabled().evaluate(ctx).status is Status.UNAVAILABLE


class TestFirewall:
    def test_pass_ufw_enabled(self, ctx_with_root):
        ctx = ctx_with_root("fw_pass_ufw")
        cfg = ctx.root / "etc" / "ufw" / "ufw.conf"
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text("ENABLED=yes\n", encoding="utf-8")
        assert NetFirewallActive().evaluate(ctx).status is Status.PASS

    def test_pass_nftables(self, ctx_with_root):
        ctx = ctx_with_root("fw_pass_nft")
        cfg = ctx.root / "etc" / "nftables.conf"
        cfg.write_text(
            "table inet filter { chain input { type filter hook input priority 0; } }\n",
            encoding="utf-8",
        )
        assert NetFirewallActive().evaluate(ctx).status is Status.PASS

    def test_fail_no_firewall(self, ctx_with_root):
        ctx = ctx_with_root("fw_fail")
        assert NetFirewallActive().evaluate(ctx).status is Status.FAIL

    def test_fail_ufw_disabled(self, ctx_with_root):
        ctx = ctx_with_root("fw_disabled")
        cfg = ctx.root / "etc" / "ufw" / "ufw.conf"
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text("ENABLED=no\n", encoding="utf-8")
        assert NetFirewallActive().evaluate(ctx).status is Status.FAIL
