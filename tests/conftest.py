"""Shared, root-level test fixtures (chunk domain-config).

CONTRACT NOTE (reported as a contract_gap, not silently deviated on):
PHASE0-CONTRACT.md §13.1 names `tests/phase0/conftest.py` "the ONLY
conftest" and assigns it to chunk `harness`, with fixtures `pg_dsn` /
`pg_pool` / `repo` / `work_queue` / etc. This chunk's task list instead
specifies a root `tests/conftest.py` owned by domain-config, providing
`fake_clock`, `settings`, a tmp-path tracestore root, and a Postgres
integration-skip fixture. Both can co-exist (pytest layers conftests; a
fixture defined here is overridable by a same-named fixture in
`tests/phase0/conftest.py`), but the two fixture surfaces overlap in intent
and should be reconciled at merge time — see this chunk's contract_gaps.

Kept deliberately small and generic: other chunks' test modules import
these fixtures by name (pytest autodiscovery), never by importing this
module directly.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tracebed.domain.clock import FakeClock
from tracebed.domain.config import EmbeddingConfig, StorageConfig, TracebedSettings

PHASE0_EPOCH: datetime = datetime(2026, 1, 1, tzinfo=UTC)
"""The fixed instant every Phase 0 FakeClock starts from (§13.1)."""


@contextmanager
def without_tb_env() -> Iterator[None]:
    """Run a block with every ``TB_``-prefixed env var temporarily removed.

    `TracebedSettings` is a `BaseSettings`: constructing one reads the ambient
    environment for every declared field. A developer machine or CI runner
    that exports, say, `TB_RETRIEVAL__TOTAL_BUDGET_MS` would silently change
    what the `settings` fixture means, turning assertions about documented
    defaults into assertions about that machine — a Phase 0 gate that passes
    or fails depending on the shell it ran in is not a gate. Restores the
    saved values immediately on exit so a later fixture (`pg`) still sees the
    real environment.
    """
    saved = {key: value for key, value in os.environ.items() if key.startswith("TB_")}
    for key in saved:
        del os.environ[key]
    try:
        yield
    finally:
        os.environ.update(saved)


@pytest.fixture
def fake_clock() -> FakeClock:
    """A `FakeClock` pinned to the Phase 0 epoch. Time only moves via `.advance()`."""
    return FakeClock(PHASE0_EPOCH)


@pytest.fixture
def settings() -> TracebedSettings:
    """A connection-safe `TracebedSettings` for tests that need config but no I/O.

    Built with the ambient `TB_` environment suppressed, so every field is
    either the documented default or one of the two explicit arguments below
    — see `without_tb_env`. `pg_dsn` deliberately points at a DSN nothing
    should ever dial: fixtures/tests that use this must stay pure. Tests that
    need a live database ask for the `pg` fixture instead, which resolves a
    real, reachable DSN or skips.
    """
    with without_tb_env():
        return TracebedSettings(
            storage=StorageConfig(pg_dsn="postgresql://unused@unused/unused"),
            embedding=EmbeddingConfig(model_version="test"),
        )


@pytest.fixture
def tracestore_root(tmp_path: Path) -> Path:
    """A fresh, empty directory for tests exercising the filesystem trace-store driver."""
    root = tmp_path / "tracestore"
    root.mkdir()
    return root


@pytest.fixture
def pg() -> Iterator[str]:
    """A reachable Postgres DSN, or a clean `pytest.skip`.

    ENVIRONMENT CONSTRAINT: there is no Docker/Postgres on this build
    machine. Every test that needs a live database asks for this fixture
    instead of reading `TB_STORAGE__PG_DSN` itself, so "no database
    available" is one uniform skip message instead of N different failure
    modes, and — per §12 — the test never errors at collection time, only
    at fixture setup.
    """
    dsn = os.environ.get("TB_STORAGE__PG_DSN")
    if not dsn:
        pytest.skip("TB_STORAGE__PG_DSN is not set — no Postgres available")

    try:
        import psycopg
    except ImportError:  # pragma: no cover - psycopg is a hard dependency
        pytest.skip("psycopg is not importable — no Postgres available")

    try:
        with psycopg.connect(dsn, connect_timeout=1):
            pass
    except Exception as exc:
        # Never echo the DSN: it carries the database password, and a skip
        # message lands verbatim in the gate report and in CI logs. The
        # exception text is enough to diagnose "wrong host / refused / auth".
        pytest.skip(f"Postgres unreachable (TB_STORAGE__PG_DSN): {exc}")

    yield dsn
