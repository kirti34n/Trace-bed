# Tracebed API (:8110). The runtime image contains an installed wheel only:
# source code and the checkout-only migrations directory never cross stages.

FROM python@sha256:83ff1d245a3d57d04152252d3ef9cb361494d0b3395abd65a5ebe91c401c8e83 AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN pip install --no-cache-dir uv==0.11.21

WORKDIR /build
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY migrations ./migrations
# The explicit local-demo overlay loads this checked-in, public evidence
# manifest from the installed wheel. Keep its build input beside the matching
# Hatch force-include so a container image cannot omit the runtime asset.
COPY demo ./demo

# Resolve the application dependency graph only from the checked ``uv.lock``.
# The locally built wheel is installed with no dependency resolution so a
# registry cannot alter a runtime dependency after the lock was reviewed.  The
# minimal runtime supplies /usr/bin/python, so its Compose-overridable console
# scripts receive that explicit interpreter rather than a builder-only path.
RUN uv venv /opt/venv --python 3.14 \
 && VIRTUAL_ENV=/opt/venv uv sync --active --locked --no-dev --no-install-project \
 && uv build --wheel \
 && VIRTUAL_ENV=/opt/venv uv pip install --no-deps /build/dist/*.whl \
 && find /opt/venv/bin -maxdepth 1 -type f -name 'tracebed-*' \
      -exec sed -i '1s|^#!.*|#!/usr/bin/python|' {} +

FROM cgr.dev/chainguard/python@sha256:ee37f5e4fb445732409626797dccb6f2a6337872def2bab48729ee61b335fa77 AS runtime

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONPATH="/opt/venv/lib/python3.14/site-packages" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY --from=build /opt/venv /opt/venv

WORKDIR /app
USER nonroot

EXPOSE 8110

ENTRYPOINT ["/usr/bin/python", "-c", "from tracebed.api.main import run; run()"]
