"""User and sudoers helpers."""

from __future__ import annotations

import subprocess


def ensure_user(username: str, *, groups: list[str] | None = None) -> None:
    """Create a system user if it does not already exist.

    `useradd -r` creates a system account (UID < 1000); we keep this
    thin so the operator's existing identity-management workflow stays
    authoritative.
    """

    try:
        subprocess.run(["id", username], check=True, capture_output=True)
        return  # exists
    except subprocess.CalledProcessError:
        pass
    cmd = ["useradd", "-r", "-m", "-s", "/bin/bash"]
    if groups:
        cmd += ["-G", ",".join(groups)]
    cmd.append(username)
    subprocess.run(cmd, check=True)


def write_sudoers_drop_in(name: str, body: str) -> None:
    """Drop a file under /etc/sudoers.d with mode 0440. visudo-validated."""

    import os
    from pathlib import Path

    target = Path("/etc/sudoers.d") / name
    target.write_text(body if body.endswith("\n") else body + "\n", encoding="utf-8")
    os.chmod(target, 0o440)
    subprocess.run(["visudo", "-cf", str(target)], check=True)
