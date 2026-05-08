# Multi-stage:
#   - `tool`: minimal image containing the compliance-bootstrap CLI
#   - `target`: a fresh debian:bookworm host the tool can audit and
#     remediate against (used by the `remediation-smoke` CI job and the
#     local `make container-test` flow)
#
# The two stages share a layer cache for apt-installed packages.

FROM python:3.12-slim AS tool

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

# Copy the tool into the target image so a single container can run
# both the audit and the remediation snippets against itself.
COPY --from=tool /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=tool /usr/local/bin/compliance-bootstrap /usr/local/bin/compliance-bootstrap
COPY --from=tool /opt/compliance-bootstrap /opt/compliance-bootstrap
RUN apt-get update -y \
    && apt-get install -y --no-install-recommends python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/compliance-bootstrap
CMD ["bash"]
