"""Remediation registry tests."""

from __future__ import annotations

import re

from compliance_bootstrap.checks import get_registered
from compliance_bootstrap.remediation import (
    list_snippet_ids,
    remediation_snippet,
    remediation_text,
    snippet_hash,
    snippet_path,
)


def test_every_check_remediation_id_has_a_snippet():
    """Every fail-path remediation_id used in the registered checks
    must resolve to a Bash file under remediation/snippets."""

    referenced = set()
    # Walk the checks/ source files for `remediation_id="..."`.
    import inspect

    for check in get_registered().values():
        src = inspect.getsource(type(check))
        referenced.update(re.findall(r'remediation_id="([a-z0-9_]+)"', src))
    # Add the network helper IDs which are referenced positionally.
    referenced.update({"net_icmp_redirects", "net_source_route", "net_log_martians"})
    available = set(list_snippet_ids())
    missing = referenced - available
    assert not missing, f"missing snippets: {sorted(missing)}"


def test_snippet_hash_stable_for_same_id():
    h1 = snippet_hash("ssh_permit_root_login")
    h2 = snippet_hash("ssh_permit_root_login")
    assert h1 == h2 and h1 is not None
    assert len(h1) == 64  # sha256 hex


def test_snippet_path_returns_none_for_unknown():
    assert snippet_path("does_not_exist") is None
    assert remediation_snippet("does_not_exist") is None


def test_remediation_text_uses_summary_header():
    # The ssh_permit_root_login snippet has `# summary: Set PermitRootLogin to no...`
    text = remediation_text("ssh_permit_root_login")
    assert "PermitRootLogin" in text


def test_every_snippet_starts_with_set_euo_pipefail():
    for rid in list_snippet_ids():
        body = remediation_snippet(rid) or ""
        assert "set -euo pipefail" in body, f"{rid} missing set -euo pipefail"
