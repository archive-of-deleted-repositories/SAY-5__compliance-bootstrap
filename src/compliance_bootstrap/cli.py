"""Click-based CLI entry point.

Subcommands:

* `audit`       — run a policy and emit JSON+Markdown reports
* `report`      — re-render a previously emitted JSON as Markdown
* `remediate`   — apply Bash snippets for failing checks
* `provision`   — defer to the Bash bootstrap scripts under `scripts/`

Exit codes:

* 0 — every enabled check passed (or skipped/unavailable)
* 1 — at least one check failed
* 2 — invocation error (bad policy, unknown CLI flag, etc.)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import click

from .checks import Status
from .policy import load_policy
from .remediation import remediation_snippet, snippet_hash, snippet_path
from .reports import build_report, emit_json, emit_markdown
from .reports.markdown import render_markdown
from .runner import configure_logging, run_audit
from .settings import HostContext


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("-v", "--verbose", is_flag=True, help="Verbose log output.")
@click.pass_context
def main(ctx: click.Context, verbose: bool) -> None:
    """compliance-bootstrap — Linux compliance audit + remediation runner."""

    configure_logging(verbose)
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose


@main.command()
@click.option(
    "--policy",
    "policy_name",
    default="cis-ubuntu-22",
    show_default=True,
    help="Policy to evaluate.",
)
@click.option(
    "--policies-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path("policies"),
    show_default=True,
)
@click.option(
    "--json",
    "json_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=Path("out") / "audit.json",
    show_default=True,
)
@click.option(
    "--md",
    "md_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=Path("out") / "audit.md",
    show_default=True,
)
@click.option(
    "--root",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Pretend this path is /. Useful for testing against fixture trees.",
)
def audit(
    policy_name: str,
    policies_dir: Path,
    json_path: Path,
    md_path: Path,
    root: Path | None,
) -> None:
    """Run compliance checks and emit JSON+Markdown reports."""

    policy = load_policy(policy_name, search_dirs=[policies_dir])
    ctx = HostContext.detect(root=root)
    results = run_audit(policy, ctx)
    report = build_report(ctx=ctx, policy=policy.name, results=results)
    emit_json(report, json_path)
    emit_markdown(report, md_path)
    summary = report["summary"]
    click.echo(
        f"audit: {summary['pass']} pass / {summary['fail']} fail / "
        f"{summary['skip']} skip / {summary['unavailable']} unavailable "
        f"({summary['total']} total)"
    )
    click.echo(f"json: {json_path}")
    click.echo(f"md:   {md_path}")
    if summary["fail"] > 0:
        sys.exit(1)


@main.command()
@click.argument("json_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def report(json_path: Path) -> None:
    """Re-render an existing JSON audit as Markdown to stdout."""

    data = json.loads(json_path.read_text(encoding="utf-8"))
    click.echo(render_markdown(data), nl=False)


@main.command()
@click.option(
    "--policy",
    "policy_name",
    default="cis-ubuntu-22",
    show_default=True,
)
@click.option(
    "--policies-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path("policies"),
    show_default=True,
)
@click.option(
    "--apply",
    is_flag=True,
    help="Actually run the snippets. Without --apply this is a dry run.",
)
@click.option(
    "--root",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
)
def remediate(policy_name: str, policies_dir: Path, apply: bool, root: Path | None) -> None:
    """Run remediation snippets for every failing check.

    By default this is a dry run that prints what *would* be applied.
    Use `--apply` to actually invoke the Bash snippets via /bin/bash.
    """

    policy = load_policy(policy_name, search_dirs=[policies_dir])
    ctx = HostContext.detect(root=root)
    results = run_audit(policy, ctx)

    fails = [r for r in results if r.status is Status.FAIL and r.remediation_id]
    if not fails:
        click.echo("nothing to remediate")
        return

    snippet_failures = 0
    for result in fails:
        rid = result.remediation_id or ""
        path = snippet_path(rid)
        if path is None:
            click.echo(f"[skip] {result.check_id}: no snippet for {rid!r}")
            continue
        h = snippet_hash(rid)
        if not apply:
            click.echo(f"[dry-run] {result.check_id} -> {rid} (sha256={h})")
            continue
        click.echo(f"[apply] {result.check_id} -> {rid} (sha256={h})")
        proc = subprocess.run(
            ["/bin/bash", str(path)],
            check=False,
            capture_output=True,
            text=True,
            env={**os.environ, "LC_ALL": "C"},
        )
        click.echo(proc.stdout, nl=False)
        if proc.returncode != 0:
            click.echo(proc.stderr, err=True, nl=False)
            click.echo(f"[fail] {rid} exited {proc.returncode}", err=True)
            snippet_failures += 1
            # We deliberately continue: a missing apt index or systemctl
            # binary should not block the dozen other snippets that have
            # nothing to do with apt or systemd.

    if apply:
        # Re-audit and exit with the new state's code.
        results2 = run_audit(policy, ctx)
        s = sum(1 for r in results2 if r.status is Status.FAIL)
        click.echo(
            f"post-remediation: {s} fail(s) remaining "
            f"({snippet_failures} snippet(s) errored during apply)"
        )
        if s > 0 or snippet_failures > 0:
            sys.exit(1)


@main.command()
@click.option(
    "--distro",
    type=click.Choice(["debian", "rhel", "amzn2"]),
    required=True,
    help="Which bootstrap script to invoke.",
)
def provision(distro: str) -> None:
    """Run the matching scripts/bootstrap-<distro>.sh provisioning script."""

    repo_root = Path(__file__).resolve().parents[2]
    script = repo_root / "scripts" / f"bootstrap-{distro}.sh"
    if not script.is_file():
        click.echo(f"missing script: {script}", err=True)
        sys.exit(2)
    proc = subprocess.run(["/bin/bash", str(script)], check=False)
    sys.exit(proc.returncode)


@main.command()
def list_checks() -> None:
    """List every registered check (id, category, CIS ref)."""

    from .checks import get_registered

    for cid, check in sorted(get_registered().items()):
        click.echo(f"{cid:36s} {check.category:11s} {check.cis_ref:14s} {check.description}")


@main.command()
def list_remediations() -> None:
    """List every remediation snippet shipped with the package."""

    from .remediation import list_snippet_ids

    for rid in list_snippet_ids():
        body = remediation_snippet(rid) or ""
        summary = ""
        for line in body.splitlines()[:10]:
            stripped = line.strip()
            if stripped.startswith("# summary:"):
                summary = stripped[len("# summary:") :].strip()
                break
        click.echo(f"{rid:32s} {summary}")


if __name__ == "__main__":  # pragma: no cover
    main()
