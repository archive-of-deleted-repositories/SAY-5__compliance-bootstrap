"""Audit runner — executes the checks an enabled policy selects."""

from __future__ import annotations

import logging
import time
from collections.abc import Iterable

import structlog

from .checks import CheckResult, Status, get_registered
from .policy import Policy
from .settings import HostContext

logger = structlog.get_logger(__name__)


def configure_logging(verbose: bool) -> None:
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.DEBUG if verbose else logging.INFO
        ),
        processors=[
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.add_log_level,
            structlog.dev.ConsoleRenderer(colors=False),
        ],
    )


def run_audit(policy: Policy, ctx: HostContext) -> list[CheckResult]:
    """Execute every enabled check, in registration order, against ctx.

    Each check is wrapped — an unhandled exception inside an evaluator
    becomes a `fail` result tagged `check_runner_exception`, never a
    crash of the runner.
    """

    registered = get_registered()
    results: list[CheckResult] = []
    for cid in policy.enabled:
        check = registered[cid]
        started = time.monotonic()
        try:
            result = check.evaluate(ctx)
        except Exception as exc:
            logger.error("check_exception", check_id=cid, error=str(exc))
            result = CheckResult(
                check_id=cid,
                status=Status.FAIL,
                summary=f"runner exception: {exc!s}",
                evidence={"error": str(exc), "type": type(exc).__name__},
                remediation_id=None,
            )
        elapsed_ms = (time.monotonic() - started) * 1000
        if (
            policy.overrides.get("treat_unavailable_as_fail")
            and result.status is Status.UNAVAILABLE
        ):
            result = CheckResult(
                check_id=result.check_id,
                status=Status.FAIL,
                summary=result.summary + " (strict: unavailable promoted to fail)",
                evidence=result.evidence,
                remediation_id=result.remediation_id,
            )
        logger.info(
            "check_done",
            check_id=cid,
            status=result.status.value,
            elapsed_ms=round(elapsed_ms, 2),
        )
        results.append(result)
    return results


def summarise(results: Iterable[CheckResult]) -> dict[str, int]:
    counts: dict[str, int] = {s.value: 0 for s in Status}
    counts["total"] = 0
    for r in results:
        counts[r.status.value] += 1
        counts["total"] += 1
    return counts
