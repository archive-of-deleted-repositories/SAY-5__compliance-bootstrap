"""Shared test fixtures."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from compliance_bootstrap.settings import HostContext


def _ctx_with_root(root: Path, *, binaries: tuple[str, ...] = ()) -> HostContext:
    return HostContext(
        hostname="test-host",
        os_id="ubuntu",
        os_version="22.04",
        os_pretty="Ubuntu 22.04 LTS",
        kernel="6.1.0-test",
        arch="x86_64",
        root=root,
        binaries=frozenset(binaries),
    )


@pytest.fixture
def make_root(tmp_path: Path):
    """Return a factory that creates a fresh fake root under tmp_path."""

    def _factory(suffix: str = "root") -> Path:
        root = tmp_path / suffix
        for d in ("etc", "proc", "sys", "var/log", "var/lib"):
            (root / d).mkdir(parents=True, exist_ok=True)
        # Provide a default os-release so HostContext.detect-style code
        # works against the fixture root.
        (root / "etc" / "os-release").write_text(
            'ID=ubuntu\nVERSION_ID="22.04"\nPRETTY_NAME="Ubuntu 22.04 LTS"\n',
            encoding="utf-8",
        )
        return root

    return _factory


@pytest.fixture
def ctx_with_root(make_root):
    """Build a HostContext bound to a fresh fake root."""

    def _factory(suffix: str = "root", *, binaries: tuple[str, ...] = ()) -> HostContext:
        root = make_root(suffix)
        return _ctx_with_root(root, binaries=binaries)

    return _factory


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch):
    """Drop env vars that production code might inadvertently consult."""

    for key in ("RUN_INTEGRATION", "DEBIAN_FRONTEND"):
        monkeypatch.delenv(key, raising=False)


def pytest_collection_modifyitems(config, items):
    if os.environ.get("RUN_INTEGRATION") == "1":
        return
    skip = pytest.mark.skip(reason="set RUN_INTEGRATION=1 to run")
    for item in items:
        if "integration" in str(item.fspath):
            item.add_marker(skip)
