"""HostContext detection against a fixture root."""

from __future__ import annotations

from pathlib import Path

from compliance_bootstrap.settings import HostContext, env_truthy


def test_detect_reads_os_release(tmp_path: Path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "os-release").write_text(
        'ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n',
        encoding="utf-8",
    )
    ctx = HostContext.detect(root=tmp_path)
    assert ctx.os_id == "debian"
    assert ctx.os_version == "12"
    assert "Debian" in ctx.os_pretty


def test_detect_handles_missing_os_release(tmp_path: Path):
    ctx = HostContext.detect(root=tmp_path)
    assert ctx.os_id == "unknown"
    assert ctx.os_version == ""


def test_to_meta_uses_pretty_name(tmp_path: Path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "os-release").write_text(
        'ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04 LTS"\n',
        encoding="utf-8",
    )
    ctx = HostContext.detect(root=tmp_path)
    meta = ctx.to_meta()
    assert meta["os"] == "Ubuntu 24.04 LTS"


def test_env_truthy(monkeypatch):
    monkeypatch.setenv("FOO", "1")
    assert env_truthy("FOO")
    monkeypatch.setenv("FOO", "no")
    assert not env_truthy("FOO")
    monkeypatch.delenv("FOO")
    assert not env_truthy("FOO")
