"""Policy loader.

A policy is a YAML file (see policies/README.md) that names which
checks to run. Loading is fail-loud: an enabled `check_id` that is not
registered is a user error, not a silent skip.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .checks import get_registered

_PACKAGE_POLICIES_DIR = Path(__file__).parent / "policies"


@dataclass(frozen=True)
class Policy:
    name: str
    description: str
    enabled: tuple[str, ...]
    disabled: tuple[str, ...] = field(default_factory=tuple)
    overrides: dict[str, Any] = field(default_factory=dict)


def load_policy(name: str, *, search_dirs: list[Path] | None = None) -> Policy:
    paths = list(search_dirs or [])
    paths.append(_PACKAGE_POLICIES_DIR)
    paths.append(Path("policies"))
    seen: set[Path] = set()
    for d in paths:
        if d in seen:
            continue
        seen.add(d)
        candidate = d / f"{name}.yaml"
        if candidate.is_file():
            return _parse_policy(candidate)
    raise FileNotFoundError(f"policy {name!r} not found in {[str(p) for p in paths]}")


def _parse_policy(path: Path) -> Policy:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"policy {path} is not a mapping")
    name = str(raw.get("name") or path.stem)
    description = str(raw.get("description") or "")
    enabled_list = raw.get("enabled") or []
    if not isinstance(enabled_list, list) or not all(isinstance(x, str) for x in enabled_list):
        raise ValueError(f"policy {path}: 'enabled' must be a list of strings")
    enabled = tuple(enabled_list)

    registered = get_registered()
    unknown = [cid for cid in enabled if cid not in registered]
    if unknown:
        raise ValueError(
            f"policy {path}: unknown check_ids {unknown!r}; registered: {sorted(registered)}"
        )

    disabled_list = raw.get("disabled") or []
    if not isinstance(disabled_list, list):
        raise ValueError(f"policy {path}: 'disabled' must be a list")
    disabled = tuple(str(x) for x in disabled_list)

    overrides_raw = raw.get("overrides") or {}
    if not isinstance(overrides_raw, dict):
        raise ValueError(f"policy {path}: 'overrides' must be a mapping")

    return Policy(
        name=name,
        description=description,
        enabled=enabled,
        disabled=disabled,
        overrides=dict(overrides_raw),
    )
