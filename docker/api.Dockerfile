# Tracebed API (:8110)
#
# Two stages so the shipped image carries no build toolchain and no dev dependencies —
# the licence gate covers the runtime tree, and a smaller tree is a smaller tree to clear.

FROM python:3.13-slim AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN pip install --no-cache-dir uv

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src

RUN uv venv /opt/venv --python 3.13 \
 && VIRTUAL_ENV=/opt/venv uv pip install --no-cache .

FROM python:3.13-slim AS runtime

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Tracebed holds trace payloads and subject keys. It does not run as root.
RUN groupadd --system --gid 10001 tracebed \
 && useradd --system --uid 10001 --gid tracebed --no-create-home tracebed

COPY --from=build /opt/venv /opt/venv
COPY migrations /app/migrations
COPY scripts /app/scripts

WORKDIR /app
USER tracebed

EXPOSE 8110

# No healthcheck curl: the image ships no shell utilities beyond the base. The API's
# own readiness endpoint is polled by the orchestrator instead.
ENTRYPOINT ["uvicorn", "tracebed.api.main:app", "--host", "0.0.0.0", "--port", "8110"]
