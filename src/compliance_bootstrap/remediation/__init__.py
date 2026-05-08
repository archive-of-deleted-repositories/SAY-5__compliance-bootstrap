"""Remediation snippets — one Bash file per failing check.

The `remediate` CLI looks up the snippet by `remediation_id` (the same
identifier each Check returns alongside a `fail`), shells out to
`/bin/bash` with `set -euo pipefail`, and captures stdout/stderr.

Snippets are idempotent by construction — running them twice produces
no further change. The integration tests assert that property.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

_SNIPPETS_DIR = Path(__file__).parent / "snippets"


def snippet_path(remediation_id: str) -> Path | None:
    """Return absolute path to the Bash snippet, or None if missing."""

    candidate = _SNIPPETS_DIR / f"{remediation_id}.sh"
    return candidate if candidate.is_file() else None


def remediation_snippet(remediation_id: str) -> str | None:
    """Return the snippet body as text, or None if no snippet is registered."""

    path = snippet_path(remediation_id)
    if path is None:
        return None
    return path.read_text(encoding="utf-8")


def remediation_text(remediation_id: str) -> str:
    """One-line human-readable remediation summary, derived from the
    snippet's `# summary:` header (first match wins). Used in JSON
    reports where a multi-line snippet would clutter the output.
    """

    snippet = remediation_snippet(remediation_id)
    if snippet is None:
        return f"(no snippet for {remediation_id})"
    for raw in snippet.splitlines()[:20]:
        line = raw.strip()
        if line.startswith("# summary:"):
            return line[len("# summary:") :].strip()
    return f"see remediation/snippets/{remediation_id}.sh"


def snippet_hash(remediation_id: str) -> str | None:
    """SHA-256 of the snippet body, used by `remediate` for an audit trail."""

    snippet = remediation_snippet(remediation_id)
    if snippet is None:
        return None
    return hashlib.sha256(snippet.encode("utf-8")).hexdigest()


def list_snippet_ids() -> list[str]:
    """Every remediation id we ship a snippet for."""

    if not _SNIPPETS_DIR.is_dir():
        return []
    return sorted(p.stem for p in _SNIPPETS_DIR.glob("*.sh") if p.is_file())
