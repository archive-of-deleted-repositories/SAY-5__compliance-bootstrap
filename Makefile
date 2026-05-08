.PHONY: dev test test-unit test-integration lint typecheck shellcheck audit provision report container-test clean

PY := python3

dev:
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -e ".[dev]"

lint:
	$(PY) -m ruff check src tests
	$(PY) -m black --check src tests

typecheck:
	$(PY) -m mypy

shellcheck:
	@find scripts src/compliance_bootstrap/remediation/snippets -type f -name '*.sh' -print0 \
		| xargs -0 shellcheck -x

test-unit:
	$(PY) -m pytest tests/unit -v --cov=src/compliance_bootstrap --cov-report=term-missing --cov-fail-under=80

test-integration:
	RUN_INTEGRATION=1 $(PY) -m pytest tests/integration -v

test: test-unit

audit:
	$(PY) -m compliance_bootstrap.cli audit --policy cis-ubuntu-22 \
		--json out/audit.json --md out/audit.md

provision:
	@echo "Provisioning is distro-specific. Run scripts/bootstrap-debian.sh, bootstrap-rhel.sh, or bootstrap-amzn2.sh."

report:
	@cat out/audit.md

container-test:
	docker compose build target
	docker compose run --rm tool bash -lc "compliance-bootstrap audit --policy cis-ubuntu-22 --json /tmp/a.json --md /tmp/a.md || true; head -50 /tmp/a.md"

clean:
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage out
