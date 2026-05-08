"""Package install helpers.

Apt and dnf are addressed through their non-interactive modes; we never
invoke an interactive prompt or pull in `dialog`-style upgrades.
"""

from __future__ import annotations

import subprocess
from collections.abc import Sequence


def install_debian(packages: Sequence[str]) -> None:
    """Idempotent: already-installed packages are a no-op for apt-get."""

    if not packages:
        return
    cmd = ["apt-get", "install", "-y", "--no-install-recommends", *packages]
    subprocess.run(
        cmd,
        check=True,
        env={"DEBIAN_FRONTEND": "noninteractive", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
    )


def install_rhel(packages: Sequence[str]) -> None:
    if not packages:
        return
    cmd = ["dnf", "install", "-y", *packages]
    subprocess.run(cmd, check=True)
