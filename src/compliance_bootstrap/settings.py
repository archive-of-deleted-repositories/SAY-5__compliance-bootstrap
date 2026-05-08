"""Runtime settings and host context."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class HostContext:
    """Read-only snapshot of the host the audit is running against.

    Tests construct this directly with mock data; production code uses
    `HostContext.detect()` which reads `/etc/os-release`, `uname`, and
    a couple of well-known files.
    """

    hostname: str
    os_id: str
    os_version: str
    os_pretty: str
    kernel: str
    arch: str
    root: Path
    """Filesystem root used for path lookups; always `/` outside tests."""

    binaries: frozenset[str] = field(default_factory=frozenset)
    """Set of CLI binaries discovered on PATH at detection time."""

    @classmethod
    def detect(cls, root: Path | None = None) -> HostContext:
        root = root or Path("/")
        os_id, os_version, os_pretty = _read_os_release(root)
        try:
            kernel = subprocess.check_output(["uname", "-r"], text=True).strip()
        except (OSError, subprocess.CalledProcessError):
            kernel = platform.release() or "unknown"
        try:
            hostname = subprocess.check_output(["hostname"], text=True).strip()
        except (OSError, subprocess.CalledProcessError):
            hostname = platform.node() or "unknown"
        binaries = frozenset(
            name
            for name in (
                "sshd",
                "auditctl",
                "ufw",
                "iptables",
                "sysctl",
                "systemctl",
                "apt",
                "dpkg",
                "dnf",
                "rpm",
                "lsmod",
                "findmnt",
            )
            if shutil.which(name) is not None
        )
        return cls(
            hostname=hostname,
            os_id=os_id,
            os_version=os_version,
            os_pretty=os_pretty,
            kernel=kernel,
            arch=platform.machine() or "unknown",
            root=root,
            binaries=binaries,
        )

    def has(self, binary: str) -> bool:
        """Whether the named binary was on PATH at detection time."""

        return binary in self.binaries

    def to_meta(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "os": self.os_pretty or f"{self.os_id} {self.os_version}".strip(),
            "kernel": self.kernel,
            "arch": self.arch,
        }


def _read_os_release(root: Path) -> tuple[str, str, str]:
    path = root / "etc" / "os-release"
    if not path.is_file():
        return ("unknown", "", "")
    fields: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in raw or raw.startswith("#"):
            continue
        key, _, value = raw.partition("=")
        fields[key.strip()] = value.strip().strip('"')
    return (
        fields.get("ID", "unknown"),
        fields.get("VERSION_ID", ""),
        fields.get("PRETTY_NAME", ""),
    )


def env_truthy(name: str) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    return raw in {"1", "true", "yes", "on"}
