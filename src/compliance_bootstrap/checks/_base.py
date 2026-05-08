"""Check protocol, four-state result model, and global registry."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, ClassVar, Protocol, runtime_checkable

__all__ = [
    "BaseCheck",
    "Check",
    "CheckResult",
    "Status",
    "failed",
    "get_registered",
    "passed",
    "register_check",
    "reset_registry_for_tests",
    "skipped",
    "unavailable",
]

from compliance_bootstrap.settings import HostContext


class Status(str, enum.Enum):
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class CheckResult:
    """Outcome of a single check evaluation.

    `status` is the four-state result (pass / fail / skip / unavailable —
    the same model used by `hw-preflight` and deliberately *not* collapsed,
    since "we have no auditd binary" is meaningfully different from
    "auditd is installed but disabled").

    `evidence` is a small JSON-serialisable dict with the actual measurement
    so reports can show *why* the check fired. `remediation_id` names the
    Bash snippet shipped under `remediation/snippets/` that fixes the
    deviation when applied; `None` when the result is pass / skip /
    unavailable.
    """

    check_id: str
    status: Status
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.check_id,
            "status": self.status.value,
            "summary": self.summary,
            "evidence": self.evidence,
            "remediation_id": self.remediation_id,
        }


@runtime_checkable
class Check(Protocol):
    """The thing every check implements.

    A `Check` is a callable producing a `CheckResult` from a host context.
    It carries identifying metadata (`check_id`, `category`, `cis_ref`,
    short `description`) used in reports.
    """

    check_id: ClassVar[str]
    category: ClassVar[str]
    cis_ref: ClassVar[str]
    description: ClassVar[str]

    def evaluate(self, ctx: HostContext) -> CheckResult: ...


class BaseCheck:
    """Convenience base — concrete checks set the four metadata strings."""

    check_id: ClassVar[str] = ""
    category: ClassVar[str] = ""
    cis_ref: ClassVar[str] = ""
    description: ClassVar[str] = ""


_REGISTRY: dict[str, Check] = {}


def register_check(target: Any) -> Any:
    """Register a check class or instance under its `check_id`.

    When used as a class decorator the class is instantiated with no
    arguments and the instance is recorded; the class is returned
    unchanged so it can still be referenced by callers (and by tests
    that want to construct it independently). When called with an
    already-built instance, the instance is registered directly.
    """

    if isinstance(target, type):
        instance = target()
    else:
        instance = target
    check_id = getattr(instance, "check_id", None)
    if not check_id:
        raise ValueError(f"register_check: missing check_id on {target!r}")
    if check_id in _REGISTRY:
        raise ValueError(f"duplicate check_id: {check_id}")
    _REGISTRY[check_id] = instance
    return target


def get_registered() -> dict[str, Check]:
    """Return a copy of the live registry, keyed by `check_id`."""

    return dict(_REGISTRY)


def reset_registry_for_tests() -> None:
    """Test-only: clear the registry. Production code never calls this."""

    _REGISTRY.clear()


# Helpers used by check implementations -----------------------------------


def passed(check_id: str, summary: str, **evidence: Any) -> CheckResult:
    return CheckResult(check_id, Status.PASS, summary, evidence=dict(evidence))


def failed(
    check_id: str,
    summary: str,
    *,
    remediation_id: str | None,
    **evidence: Any,
) -> CheckResult:
    return CheckResult(
        check_id,
        Status.FAIL,
        summary,
        evidence=dict(evidence),
        remediation_id=remediation_id,
    )


def skipped(check_id: str, summary: str, **evidence: Any) -> CheckResult:
    return CheckResult(check_id, Status.SKIP, summary, evidence=dict(evidence))


def unavailable(check_id: str, summary: str, **evidence: Any) -> CheckResult:
    return CheckResult(check_id, Status.UNAVAILABLE, summary, evidence=dict(evidence))
