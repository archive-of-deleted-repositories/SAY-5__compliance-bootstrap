"""sshd_config drop-in helpers used by provisioning paths."""

from __future__ import annotations

from pathlib import Path

DROP_IN_DIR = Path("/etc/ssh/sshd_config.d")


def write_drop_in(filename: str, lines: list[str]) -> Path:
    """Write a single sshd_config.d file. Idempotent — content-based."""

    DROP_IN_DIR.mkdir(parents=True, exist_ok=True)
    body = "\n".join(lines).rstrip() + "\n"
    target = DROP_IN_DIR / filename
    if target.exists() and target.read_text(encoding="utf-8") == body:
        return target
    target.write_text(body, encoding="utf-8")
    return target
