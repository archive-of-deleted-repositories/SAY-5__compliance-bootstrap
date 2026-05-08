"""Compliance check registry and built-in checks.

Importing this package registers every built-in check via
`@register_check`. CLI code calls `get_registered()` to enumerate them.
"""

from __future__ import annotations

from . import (  # noqa: F401  (import side-effects register checks)
    auditd,
    filesystem,
    kernel,
    network,
    packages,
    pam,
    ssh_config,
)
from ._base import (
    Check,
    CheckResult,
    Status,
    get_registered,
    register_check,
)

__all__ = [
    "Check",
    "CheckResult",
    "Status",
    "get_registered",
    "register_check",
]
