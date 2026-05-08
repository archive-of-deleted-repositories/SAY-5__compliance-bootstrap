"""Runner + policy loader tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from compliance_bootstrap.checks import Status, get_registered
from compliance_bootstrap.policy import Policy, load_policy
from compliance_bootstrap.runner import run_audit, summarise
from compliance_bootstrap.settings import HostContext


def _ctx() -> HostContext:
    return HostContext(
        hostname="h",
        os_id="ubuntu",
        os_version="22.04",
        os_pretty="Ubuntu 22.04",
        kernel="6.1",
        arch="x86_64",
        root=Path("/nonexistent-fake-root-for-tests"),
        binaries=frozenset(),
    )


def test_registry_has_thirty_or_more_checks():
    """Sanity: the README cites 30+ checks; the registry must back that up."""

    assert len(get_registered()) >= 30


def test_load_policy_from_packaged_dir():
    policy = load_policy("cis-ubuntu-22")
    assert policy.name == "cis-ubuntu-22"
    assert "ssh.permit_root_login" in policy.enabled


def test_load_policy_unknown_check_raises(tmp_path: Path):
    # Write a malformed local policy and confirm it fails loud.
    policies_dir = tmp_path / "policies"
    policies_dir.mkdir()
    (policies_dir / "bad.yaml").write_text(
        "name: bad\nenabled: [does.not.exist]\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unknown check_ids"):
        load_policy("bad", search_dirs=[policies_dir])


def test_load_policy_missing_raises():
    with pytest.raises(FileNotFoundError):
        load_policy("does-not-exist")


def test_run_audit_returns_one_result_per_enabled_check():
    policy = Policy(
        name="tiny",
        description="",
        enabled=("ssh.permit_root_login", "kernel.aslr"),
    )
    results = run_audit(policy, _ctx())
    assert {r.check_id for r in results} == {"ssh.permit_root_login", "kernel.aslr"}


def test_runner_promotes_unavailable_to_fail_in_strict_mode():
    policy = Policy(
        name="strict-mini",
        description="",
        enabled=("kernel.aslr",),
        overrides={"treat_unavailable_as_fail": True},
    )
    results = run_audit(policy, _ctx())
    # /proc/sys/kernel/randomize_va_space does not exist under our fake
    # root, so the check would normally return UNAVAILABLE — strict
    # mode must turn that into FAIL.
    assert results[0].status is Status.FAIL


def test_summarise_counts():
    policy = Policy(name="t", description="", enabled=("kernel.aslr",))
    results = run_audit(policy, _ctx())
    counts = summarise(results)
    assert counts["total"] == 1
    assert counts["unavailable"] == 1
