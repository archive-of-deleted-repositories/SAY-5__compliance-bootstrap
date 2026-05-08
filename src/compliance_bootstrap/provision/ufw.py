"""ufw provisioning helpers."""

from __future__ import annotations

import subprocess


def allow(rule: str) -> None:
    """Idempotent — ufw `allow` returns 0 when the rule already exists."""

    subprocess.run(["ufw", "allow", rule], check=True)


def enable() -> None:
    """Enable ufw if it isn't already; --force avoids the y/N prompt."""

    subprocess.run(["ufw", "--force", "enable"], check=True)
