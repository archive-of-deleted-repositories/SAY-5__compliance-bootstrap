# Multi-stage:
#   - `tool`: minimal image containing the compliance-bootstrap CLI
#   - `target`: a fresh debian:bookworm host the tool can audit and
#     remediate against (used by the `remediation-smoke` CI job and the
#     local `make container-test` flow)
#
# The two stages share a layer cache for apt-installed packages.

FROM python:3.12-slim-bookworm AS tool

WORKDIR /opt/compliance-bootstrap
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY policies ./policies
COPY scripts ./scripts

RUN python -m pip install --upgrade pip \
    && python -m pip install --no-cache-dir .

ENV PATH="/usr/local/bin:${PATH}"
CMD ["compliance-bootstrap", "--help"]


FROM debian:bookworm AS target

# A "fresh" Debian — almost every CIS check fails by default, which is
# exactly what we want for the remediation-smoke test.
RUN apt-get update -y \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        coreutils \
        procps \
    && rm -rf /var/lib/apt/lists/*

# Copy the tool *and* its Python 3.12 interpreter from the `tool` stage
# so the `compliance-bootstrap` console script (shebang
# `#!/usr/local/bin/python`) can actually execute. Debian bookworm only
# ships Python 3.11 system-wide; the site-packages we copy are 3.12, so
# we need the matching interpreter or every invocation fails with
# "cannot execute: required file not found".
COPY --from=tool /usr/local/bin/python3.12 /usr/local/bin/python3.12
COPY --from=tool /usr/local/bin/python3 /usr/local/bin/python3
COPY --from=tool /usr/local/bin/python /usr/local/bin/python
COPY --from=tool /usr/local/lib/python3.12 /usr/local/lib/python3.12
COPY --from=tool /usr/local/lib/libpython3.12.so.1.0 /usr/local/lib/libpython3.12.so.1.0
COPY --from=tool /usr/local/bin/compliance-bootstrap /usr/local/bin/compliance-bootstrap
COPY --from=tool /opt/compliance-bootstrap /opt/compliance-bootstrap
RUN ldconfig

WORKDIR /opt/compliance-bootstrap
CMD ["bash"]
