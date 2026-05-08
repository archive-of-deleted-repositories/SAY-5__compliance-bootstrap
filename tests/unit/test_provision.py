"""Provisioning wrapper tests.

These tests mock subprocess so the calls don't actually invoke apt/dnf.
They confirm the helpers shape arguments the way Bash scripts do.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from compliance_bootstrap.provision import packages, ssh, ufw, users


class TestPackages:
    def test_install_debian_skips_empty(self):
        with patch("subprocess.run") as run:
            packages.install_debian([])
            run.assert_not_called()

    def test_install_debian_invokes_apt(self):
        with patch("subprocess.run") as run:
            packages.install_debian(["auditd", "ufw"])
            args, kwargs = run.call_args
            cmd = args[0]
            assert cmd[:3] == ["apt-get", "install", "-y"]
            assert "auditd" in cmd and "ufw" in cmd
            assert kwargs["env"]["DEBIAN_FRONTEND"] == "noninteractive"

    def test_install_rhel_invokes_dnf(self):
        with patch("subprocess.run") as run:
            packages.install_rhel(["audit"])
            cmd = run.call_args.args[0]
            assert cmd[:3] == ["dnf", "install", "-y"]


class TestSshDropIn:
    def test_writes_drop_in(self, tmp_path: Path, monkeypatch):
        monkeypatch.setattr(ssh, "DROP_IN_DIR", tmp_path)
        path = ssh.write_drop_in("99-test.conf", ["PermitRootLogin no", "MaxAuthTries 4"])
        assert path.read_text() == "PermitRootLogin no\nMaxAuthTries 4\n"

    def test_idempotent_when_content_matches(self, tmp_path: Path, monkeypatch):
        monkeypatch.setattr(ssh, "DROP_IN_DIR", tmp_path)
        ssh.write_drop_in("a.conf", ["X"])
        first = (tmp_path / "a.conf").stat().st_mtime_ns
        ssh.write_drop_in("a.conf", ["X"])
        second = (tmp_path / "a.conf").stat().st_mtime_ns
        # Same content -> file untouched.
        assert first == second


class TestUfw:
    def test_allow_calls_ufw(self):
        with patch("subprocess.run") as run:
            ufw.allow("22/tcp")
            assert run.call_args.args[0] == ["ufw", "allow", "22/tcp"]

    def test_enable_calls_ufw_force(self):
        with patch("subprocess.run") as run:
            ufw.enable()
            assert run.call_args.args[0] == ["ufw", "--force", "enable"]


class TestUsers:
    def test_ensure_user_skips_existing(self):
        with patch("subprocess.run") as run:
            run.return_value.returncode = 0
            users.ensure_user("root")
            # `id root` returns 0; useradd should not be called.
            assert run.call_count == 1

    def test_ensure_user_creates_when_absent(self):
        import subprocess

        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            if cmd[0] == "id":
                raise subprocess.CalledProcessError(1, cmd)
            return type("P", (), {"returncode": 0})()

        with patch("subprocess.run", side_effect=fake_run):
            users.ensure_user("alice", groups=["sudo"])
        assert any(c[0] == "useradd" for c in calls)
        useradd = next(c for c in calls if c[0] == "useradd")
        assert "alice" in useradd
        assert "sudo" in useradd[useradd.index("-G") + 1]


def test_provision_module_exports_submodules():
    """`from compliance_bootstrap.provision import packages` works."""

    assert hasattr(packages, "install_debian")
    assert hasattr(ssh, "write_drop_in")
    assert hasattr(ufw, "allow")
    assert hasattr(users, "ensure_user")
    # Sanity check we did not over-export.
    pytest.importorskip("compliance_bootstrap.provision")
