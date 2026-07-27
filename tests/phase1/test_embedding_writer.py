"""Tests for `workers.embedder` -- the embedding writer (FIDELITY-AUDIT.md M8).

Entirely offline: a fake `EmbeddingPort`, a fake `EmbeddingRepoPort`, a fake `SpendRecorderPort`,
`FakeClock`. No Postgres, no live embedding endpoint (PHASE0-CONTRACT.md section 12).
"""

from __future__ import annotations

import dataclasses
from collections.abc import Sequence
from uuid import uuid4

import pytest

from tracebed.adapters.embedding.pinning import (
    EmbeddingDimensionMismatch,
    EmbeddingPinMismatch,
    ModelPin,
)
from tracebed.domain.clock import FakeClock
from tracebed.domain.errors import EmbeddingTimeout, TracebedError
from tracebed.domain.ids import MemoryId, ProjectId
from tracebed.domain.state_machine import RETRIEVABLE_STATUSES, Status
from tracebed.workers.embedder import (
    ChunkFailure,
    Embedder,
    EmbeddingCandidateRow,
    EmbeddingRunResult,
)

pytestmark = pytest.mark.phase1

_PRICE = 0.0001  # non-zero, mirrors tests/phase3/test_distiller.py's rationale for _PRICE_IN/_OUT


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #


class _FakeEmbeddingPort:
    """Records every `embed()` call's input batch and answers deterministically from a
    `content -> vector` table, or raises a queued exception -- one entry consumed per call."""

    def __init__(
        self,
        *,
        vector_for: dict[str, list[float]],
        model_id: str = "gemini-embedding-2",
        model_version: str = "v1",
        raise_sequence: Sequence[Exception | None] = (),
        clock: FakeClock | None = None,
        elapsed_seconds: int = 0,
        drop_last_vector: bool = False,
    ) -> None:
        self._vector_for = vector_for
        # Public and mutable so a test can re-pin a LIVE driver after construction -- the
        # per-chunk half of the driver/pin guard is only reachable that way.
        self.model_id = model_id
        self.model_version = model_version
        self._raise_sequence = list(raise_sequence)
        # Time passes inside `embed()`, not around it: the only way a FakeClock-driven test can
        # tell `finished_at` was read after the work from `finished_at = started_at`.
        self._clock = clock
        self._elapsed_seconds = elapsed_seconds
        self._drop_last_vector = drop_last_vector
        self.calls: list[list[str]] = []

    def embed(self, texts: Sequence[str], *, timeout_ms: int) -> list[list[float]]:
        assert timeout_ms > 0
        self.calls.append(list(texts))
        if self._clock is not None and self._elapsed_seconds:
            self._clock.advance(seconds=self._elapsed_seconds)
        if self._raise_sequence:
            outcome = self._raise_sequence.pop(0)
            if outcome is not None:
                raise outcome
        vectors = [list(self._vector_for[text]) for text in texts]
        if self._drop_last_vector:
            vectors.pop()
        return vectors


class _FakeRepo:
    """An in-memory `memory_item` projection. `select_needing_embedding`'s predicate mirrors
    the one the port's own docstring specifies: `status = ANY(RETRIEVABLE_STATUSES) AND
    (embedding IS NULL OR embedding_model_id <> model_id OR embedding_model_version <>
    model_version)`.
    """

    def __init__(
        self,
        rows: Sequence[EmbeddingCandidateRow],
        *,
        broken_scope: bool = False,
        broken_status_filter: bool = False,
    ) -> None:
        self._content: dict[MemoryId, EmbeddingCandidateRow] = {row.id: row for row in rows}
        self._embedded: dict[MemoryId, tuple[str, str, tuple[float, ...]]] = {}
        self.writes: list[tuple[ProjectId, MemoryId, tuple[float, ...], str, str]] = []
        # Simulates a repository query that lost its `project_id` scope (invariant 4's
        # defence-in-depth test) -- a correct implementation always filters below.
        self._broken_scope = broken_scope
        # Simulates the same query having lost its retrievability conjunct.
        self._broken_status_filter = broken_status_filter

    def select_needing_embedding(
        self, project_id: ProjectId, *, model_id: str, model_version: str, limit: int
    ) -> Sequence[EmbeddingCandidateRow]:
        out = []
        # Insertion order, not sorted by id: deterministic for these tests (a dict already
        # preserves it), and lets tests control chunk composition precisely via row order --
        # a real `ORDER BY id` would be equally deterministic in production.
        for memory_id, row in self._content.items():
            if row.project_id != project_id and not self._broken_scope:
                continue
            if row.status not in RETRIEVABLE_STATUSES and not self._broken_status_filter:
                continue
            stamped = self._embedded.get(memory_id)
            if stamped is not None and stamped[0] == model_id and stamped[1] == model_version:
                continue
            out.append(row)
            if len(out) >= limit:
                break
        return out

    def write_embedding(
        self,
        project_id: ProjectId,
        memory_id: MemoryId,
        embedding: Sequence[float],
        *,
        model_id: str,
        model_version: str,
    ) -> None:
        vec = tuple(embedding)
        self._embedded[memory_id] = (model_id, model_version, vec)
        self.writes.append((project_id, memory_id, vec, model_id, model_version))

    def inject_row(self, row: EmbeddingCandidateRow) -> None:
        """Adds a row the constructor's predicate would otherwise have kept out -- used with
        `broken_scope`/`broken_status_filter` for the defence-in-depth tests."""
        self._content[row.id] = row


class _FakeSpend:
    def __init__(self) -> None:
        self.calls: list[tuple[ProjectId, str, str, int, int, float]] = []

    def add(
        self,
        project_id: ProjectId,
        worker: str,
        model_id: str,
        tokens_in: int,
        tokens_out: int,
        cost_usd: float,
    ) -> None:
        self.calls.append((project_id, worker, model_id, tokens_in, tokens_out, cost_usd))


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _row(
    project_id: ProjectId, content: str, *, status: Status = Status.VALIDATED
) -> EmbeddingCandidateRow:
    return EmbeddingCandidateRow(
        project_id=project_id, id=MemoryId(uuid4()), status=status, content=content
    )


def _vector(index: int, dim: int = 3) -> list[float]:
    """A distinguishable vector: every component encodes `index`, so an order-scrambling bug
    (wrong vector attributed to a row) is detectable by comparing components, not just length."""
    return [float(index * 10 + component) for component in range(dim)]


def _pin(*, model_version: str = "v1", dim: int = 3) -> ModelPin:
    return ModelPin(model_id="gemini-embedding-2", model_version=model_version, dim=dim)


def _embedder(
    *,
    port: _FakeEmbeddingPort,
    repo: _FakeRepo,
    spend: _FakeSpend | None = None,
    clock: FakeClock | None = None,
    pin: ModelPin | None = None,
    max_batch: int = 10,
    timeout_ms: int = 5_000,
) -> Embedder:
    return Embedder(
        clock=clock if clock is not None else FakeClock(),
        embedding_port=port,
        repo=repo,
        spend=spend if spend is not None else _FakeSpend(),
        pin=pin if pin is not None else _pin(),
        usd_per_1k_tokens=_PRICE,
        timeout_ms=timeout_ms,
        max_batch=max_batch,
    )


# --------------------------------------------------------------------------- #
# EmbeddingCandidateRow
# --------------------------------------------------------------------------- #


def test_candidate_row_rejects_empty_content() -> None:
    with pytest.raises(ValueError, match="empty content"):
        EmbeddingCandidateRow(
            project_id=ProjectId(uuid4()),
            id=MemoryId(uuid4()),
            status=Status.VALIDATED,
            content="",
        )


# --------------------------------------------------------------------------- #
# Construction validation
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("timeout_ms", [0, -1])
def test_rejects_non_positive_timeout(timeout_ms: int) -> None:
    with pytest.raises(ValueError, match="timeout_ms"):
        _embedder(
            port=_FakeEmbeddingPort(vector_for={}),
            repo=_FakeRepo([]),
            timeout_ms=timeout_ms,
        )


@pytest.mark.parametrize("max_batch", [0, -1])
def test_rejects_non_positive_max_batch(max_batch: int) -> None:
    with pytest.raises(ValueError, match="max_batch"):
        _embedder(port=_FakeEmbeddingPort(vector_for={}), repo=_FakeRepo([]), max_batch=max_batch)


@pytest.mark.parametrize("price", [-1.0, float("nan")])
def test_rejects_negative_or_nan_price(price: float) -> None:
    with pytest.raises(ValueError, match="usd_per_1k_tokens"):
        Embedder(
            clock=FakeClock(),
            embedding_port=_FakeEmbeddingPort(vector_for={}),
            repo=_FakeRepo([]),
            spend=_FakeSpend(),
            pin=_pin(),
            usd_per_1k_tokens=price,
            timeout_ms=1_000,
            max_batch=10,
        )


def test_run_rejects_non_positive_limit() -> None:
    embedder = _embedder(port=_FakeEmbeddingPort(vector_for={}), repo=_FakeRepo([]))
    with pytest.raises(ValueError, match="limit"):
        embedder.run(ProjectId(uuid4()), limit=0)


# --------------------------------------------------------------------------- #
# No candidates
# --------------------------------------------------------------------------- #


def test_no_candidates_makes_zero_port_calls() -> None:
    project_id = ProjectId(uuid4())
    port = _FakeEmbeddingPort(vector_for={})
    embedder = _embedder(port=port, repo=_FakeRepo([]))

    result = embedder.run(project_id, limit=50)

    assert result.candidates_considered == 0
    assert result.embedded_count == 0
    assert result.port_calls == 0
    assert result.failures == ()
    assert port.calls == []


# --------------------------------------------------------------------------- #
# Batching
# --------------------------------------------------------------------------- #


def test_batching_counts_port_calls_not_rows() -> None:
    project_id = ProjectId(uuid4())
    rows = [_row(project_id, f"content-{i}") for i in range(5)]
    vector_for = {row.content: _vector(i) for i, row in enumerate(rows)}
    port = _FakeEmbeddingPort(vector_for=vector_for)
    repo = _FakeRepo(rows)
    embedder = _embedder(port=port, repo=repo, max_batch=2)

    result = embedder.run(project_id, limit=50)

    # 5 rows at max_batch=2 -> 3 embed() calls (2, 2, 1), never 5.
    assert result.port_calls == 3
    assert len(port.calls) == 3
    assert result.embedded_count == 5
    assert result.candidates_considered == 5
    assert result.failures == ()


# --------------------------------------------------------------------------- #
# Vectors land on the right rows
# --------------------------------------------------------------------------- #


def test_vectors_land_on_the_right_rows() -> None:
    project_id = ProjectId(uuid4())
    rows = [_row(project_id, f"content-{i}") for i in range(7)]
    vector_for = {row.content: _vector(i) for i, row in enumerate(rows)}
    port = _FakeEmbeddingPort(vector_for=vector_for)
    repo = _FakeRepo(rows)
    embedder = _embedder(port=port, repo=repo, max_batch=3)

    embedder.run(project_id, limit=50)

    assert len(repo.writes) == 7
    written_by_id = {memory_id: vec for _, memory_id, vec, _, _ in repo.writes}
    for i, row in enumerate(rows):
        assert written_by_id[row.id] == tuple(_vector(i)), (
            f"row {row.id} (content={row.content!r}) got the wrong vector -- an "
            "order-scrambling bug would corrupt every ANN result for this row"
        )


# --------------------------------------------------------------------------- #
# The pin is stamped
# --------------------------------------------------------------------------- #


def test_pin_is_stamped_on_every_written_row() -> None:
    project_id = ProjectId(uuid4())
    rows = [_row(project_id, f"content-{i}") for i in range(3)]
    vector_for = {row.content: _vector(i) for i, row in enumerate(rows)}
    # Driver and pin agree, because they must: `_assert_driver_matches_pin` refuses to
    # construct an `Embedder` whose driver serves a different model than the configured pin,
    # which is what makes "stamped the pin" and "stamped the driver's identity" the same
    # statement rather than two behaviours a test has to choose between.
    port = _FakeEmbeddingPort(
        vector_for=vector_for, model_id="gemini-embedding-2", model_version="2026-07-01"
    )
    repo = _FakeRepo(rows)
    pin = _pin(model_version="2026-07-01")
    embedder = _embedder(port=port, repo=repo, pin=pin)

    embedder.run(project_id, limit=50)

    assert len(repo.writes) == 3
    for _, _, _, model_id, model_version in repo.writes:
        assert model_id == "gemini-embedding-2"
        assert model_version == "2026-07-01"


# --------------------------------------------------------------------------- #
# Dimension mismatch raises and writes nothing
# --------------------------------------------------------------------------- #


def test_dimension_mismatch_raises_and_writes_nothing_for_that_chunk() -> None:
    project_id = ProjectId(uuid4())
    good_row = _row(project_id, "good")
    bad_row = _row(project_id, "bad")
    # `good` gets a valid 3-dim vector; `bad` gets a 2-dim vector against a pin configured
    # for dim=3 -- refused rather than truncated or padded.
    vector_for = {"good": _vector(0, dim=3), "bad": [1.0, 2.0]}
    port = _FakeEmbeddingPort(vector_for=vector_for)
    repo = _FakeRepo([good_row, bad_row])
    # max_batch=1 -> two separate chunks/port calls, so the FIRST (good) chunk's write must
    # survive even though the SECOND (bad) chunk raises.
    embedder = _embedder(port=port, repo=repo, max_batch=1, pin=_pin(dim=3))

    with pytest.raises(EmbeddingDimensionMismatch):
        embedder.run(project_id, limit=50)

    assert len(repo.writes) == 1
    assert repo.writes[0][1] == good_row.id
    assert bad_row.id not in {w[1] for w in repo.writes}


def test_dimension_mismatch_single_chunk_writes_nothing() -> None:
    project_id = ProjectId(uuid4())
    rows = [_row(project_id, "ok"), _row(project_id, "wrong-dim")]
    vector_for = {"ok": _vector(0, dim=3), "wrong-dim": [9.0, 9.0]}
    port = _FakeEmbeddingPort(vector_for=vector_for)
    repo = _FakeRepo(rows)
    # Both rows in ONE chunk (max_batch=10 >= 2 rows): the whole chunk's write must be zero.
    embedder = _embedder(port=port, repo=repo, max_batch=10, pin=_pin(dim=3))

    with pytest.raises(EmbeddingDimensionMismatch):
        embedder.run(project_id, limit=50)

    assert repo.writes == []


# --------------------------------------------------------------------------- #
# Idempotent re-run
# --------------------------------------------------------------------------- #


def test_second_run_reembeds_nothing() -> None:
    project_id = ProjectId(uuid4())
    rows = [_row(project_id, f"content-{i}") for i in range(4)]
    vector_for = {row.content: _vector(i) for i, row in enumerate(rows)}
    port = _FakeEmbeddingPort(vector_for=vector_for)
    repo = _FakeRepo(rows)
    embedder = _embedder(port=port, repo=repo)

    first = embedder.run(project_id, limit=50)
    assert first.embedded_count == 4

    second = embedder.run(project_id, limit=50)

    assert second.candidates_considered == 0
    assert second.embedded_count == 0
    assert second.port_calls == 0
    assert len(port.calls) == 1  # unchanged since the first run
    assert len(repo.writes) == 4  # unchanged since the first run


# --------------------------------------------------------------------------- #
# Changing the pin makes every row eligible again
# --------------------------------------------------------------------------- #


def test_changing_the_pin_makes_every_row_eligible_again() -> None:
    project_id = ProjectId(uuid4())
    rows = [_row(project_id, f"content-{i}") for i in range(3)]
    vector_for = {row.content: _vector(i) for i, row in enumerate(rows)}
    repo = _FakeRepo(rows)

    port_v1 = _FakeEmbeddingPort(vector_for=vector_for)
    embedder_v1 = _embedder(port=port_v1, repo=repo, pin=_pin(model_version="v1"))
    first = embedder_v1.run(project_id, limit=50)
    assert first.embedded_count == 3

    # Same rows, no config change -> nothing eligible.
    assert embedder_v1.run(project_id, limit=50).candidates_considered == 0

    # An explicit, versioned pin change (PLAN.md section 10) -- a NEW Embedder instance wired
    # against the new configured pin AND the driver that actually serves it. Re-pinning the
    # config alone, leaving the old driver in place, is the silent swap
    # `test_a_driver_pinned_to_another_model_is_refused_at_construction` covers.
    port_v2 = _FakeEmbeddingPort(vector_for=vector_for, model_version="v2")
    embedder_v2 = dataclasses.replace(
        embedder_v1, embedding_port=port_v2, pin=_pin(model_version="v2")
    )

    second = embedder_v2.run(project_id, limit=50)

    assert second.candidates_considered == 3
    assert second.embedded_count == 3
    written_versions = {w[4] for w in repo.writes if w[1] in {r.id for r in rows}}
    assert "v2" in written_versions


# --------------------------------------------------------------------------- #
# Timeout leaves rows unembedded and retryable
# --------------------------------------------------------------------------- #


def test_timeout_leaves_the_row_unembedded_and_retryable() -> None:
    project_id = ProjectId(uuid4())
    rows = [_row(project_id, f"content-{i}") for i in range(2)]
    vector_for = {row.content: _vector(i) for i, row in enumerate(rows)}
    failing_port = _FakeEmbeddingPort(
        vector_for=vector_for, raise_sequence=[EmbeddingTimeout("embedding endpoint stalled")]
    )
    repo = _FakeRepo(rows)
    embedder = _embedder(port=failing_port, repo=repo, max_batch=10)

    result = embedder.run(project_id, limit=50)

    # Not raised past run() -- a transient failure is a routine, retryable outcome.
    assert result.embedded_count == 0
    assert result.port_calls == 1
    assert len(result.failures) == 1
    failure = result.failures[0]
    assert isinstance(failure, ChunkFailure)
    assert set(failure.memory_ids) == {row.id for row in rows}
    assert "EmbeddingTimeout" in failure.reason
    assert repo.writes == []  # half-written is exactly what must not happen

    # Retryable: a second run against a healthy port still sees both rows, and now embeds them.
    healthy_port = _FakeEmbeddingPort(vector_for=vector_for)
    retry_embedder = dataclasses.replace(embedder, embedding_port=healthy_port)
    retry_result = retry_embedder.run(project_id, limit=50)

    assert retry_result.candidates_considered == 2
    assert retry_result.embedded_count == 2
    assert len(repo.writes) == 2


def test_spend_is_recorded_even_when_the_call_fails() -> None:
    """Mirrors `workers.distiller`'s rationale: the request was already sent by the time
    `embed()` raises, so a timing-out endpoint must not be free, unmetered spend."""
    project_id = ProjectId(uuid4())
    rows = [_row(project_id, "content-0")]
    failing_port = _FakeEmbeddingPort(
        vector_for={"content-0": _vector(0)},
        raise_sequence=[EmbeddingTimeout("stalled")],
    )
    repo = _FakeRepo(rows)
    spend = _FakeSpend()
    embedder = _embedder(port=failing_port, repo=repo, spend=spend)

    embedder.run(project_id, limit=50)

    assert len(spend.calls) == 1
    _, worker, model_id, tokens_in, tokens_out, cost_usd = spend.calls[0]
    assert worker == "embedder"
    assert model_id == "gemini-embedding-2"
    assert tokens_in > 0
    assert tokens_out == 0
    assert cost_usd > 0.0


# --------------------------------------------------------------------------- #
# Invariant 4 -- defence in depth against a scope-losing repo
# --------------------------------------------------------------------------- #


def test_foreign_project_row_raises_rather_than_writing() -> None:
    project_id = ProjectId(uuid4())
    other_project_id = ProjectId(uuid4())
    repo = _FakeRepo([_row(project_id, "mine")], broken_scope=True)
    repo.inject_row(_row(other_project_id, "not-mine"))
    port = _FakeEmbeddingPort(vector_for={"mine": _vector(0), "not-mine": _vector(1)})
    embedder = _embedder(port=port, repo=repo)

    with pytest.raises(TracebedError, match="another project"):
        embedder.run(project_id, limit=50)

    assert repo.writes == []


# --------------------------------------------------------------------------- #
# Invariant 7 -- a non-retrievable row never receives a vector
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "status", [Status.QUARANTINED, Status.TOMBSTONED, Status.RETIRED, Status.SUPERSEDED]
)
def test_non_retrievable_row_never_gets_a_vector(status: Status) -> None:
    """A quarantined row that holds no vector cannot be reached by an ANN scan even if
    `vector_arm`'s predicate is ever weakened -- quarantine enforced in the data, not only in
    the query text."""
    project_id = ProjectId(uuid4())
    clean = _row(project_id, "clean")
    poison = _row(project_id, "poison", status=status)
    repo = _FakeRepo([clean, poison])
    port = _FakeEmbeddingPort(vector_for={"clean": _vector(0), "poison": _vector(1)})
    embedder = _embedder(port=port, repo=repo)

    result = embedder.run(project_id, limit=50)

    assert result.candidates_considered == 1
    assert [w[1] for w in repo.writes] == [clean.id]


def test_a_repo_that_lost_its_status_filter_raises_rather_than_writing() -> None:
    project_id = ProjectId(uuid4())
    repo = _FakeRepo([_row(project_id, "clean")], broken_status_filter=True)
    repo.inject_row(_row(project_id, "poison", status=Status.QUARANTINED))
    port = _FakeEmbeddingPort(vector_for={"clean": _vector(0), "poison": _vector(1)})
    embedder = _embedder(port=port, repo=repo)

    with pytest.raises(TracebedError, match="not retrievable"):
        embedder.run(project_id, limit=50)

    assert repo.writes == []


def test_pinned_rows_are_eligible_even_though_the_ann_arm_excludes_them() -> None:
    """`stores.pg.search` narrows further than `RETRIEVABLE_STATUSES` for reasons of its own;
    this worker deliberately does not re-encode that narrowing (a second author of "what is
    retrievable" is D-118's defect). A superset is wasted spend, never a leak."""
    project_id = ProjectId(uuid4())
    repo = _FakeRepo([_row(project_id, "preference", status=Status.PINNED)])
    port = _FakeEmbeddingPort(vector_for={"preference": _vector(0)})
    embedder = _embedder(port=port, repo=repo)

    assert embedder.run(project_id, limit=50).embedded_count == 1


# --------------------------------------------------------------------------- #
# The driver and the configured pin must be the same model
# --------------------------------------------------------------------------- #


def test_a_driver_pinned_to_another_model_is_refused_at_construction() -> None:
    """The silent swap PLAN.md section 10 forbids: re-pin `EmbeddingConfig` to a new version
    without redeploying the driver and every row gets the NEW stamp over an OLD model's vector
    -- which nothing downstream can ever detect, because `assert_pin_matches` compares the row's
    stamp to the configured pin and they agree."""
    with pytest.raises(EmbeddingPinMismatch):
        _embedder(
            port=_FakeEmbeddingPort(vector_for={}, model_version="v1"),
            repo=_FakeRepo([]),
            pin=_pin(model_version="v2"),
        )


def test_a_driver_that_changes_its_model_mid_sweep_writes_nothing_further() -> None:
    project_id = ProjectId(uuid4())
    rows = [_row(project_id, f"content-{i}") for i in range(2)]
    vector_for = {row.content: _vector(i) for i, row in enumerate(rows)}
    port = _FakeEmbeddingPort(vector_for=vector_for)
    repo = _FakeRepo(rows)
    embedder = _embedder(port=port, repo=repo, max_batch=1)

    # A gateway driver that re-resolves "whatever the endpoint serves now" between chunks.
    port.model_id = "some-other-model"

    with pytest.raises(EmbeddingPinMismatch):
        embedder.run(project_id, limit=50)

    assert repo.writes == []
    assert port.calls == []  # refused before the request, so neither budget nor spend is burnt


@pytest.mark.parametrize("dim", [0, -1])
def test_rejects_a_pin_with_a_non_positive_dim(dim: int) -> None:
    with pytest.raises(ValueError, match=r"pin\.dim"):
        _embedder(port=_FakeEmbeddingPort(vector_for={}), repo=_FakeRepo([]), pin=_pin(dim=dim))


@pytest.mark.parametrize(("model_id", "model_version"), [("", "v1"), ("m", "")])
def test_rejects_a_pin_with_an_empty_identity(model_id: str, model_version: str) -> None:
    with pytest.raises(ValueError, match="non-empty"):
        _embedder(
            port=_FakeEmbeddingPort(vector_for={}, model_id=model_id, model_version=model_version),
            repo=_FakeRepo([]),
            pin=ModelPin(model_id=model_id, model_version=model_version, dim=3),
        )


# --------------------------------------------------------------------------- #
# A malformed response is refused, never written
# --------------------------------------------------------------------------- #


def test_a_short_vector_batch_is_a_caught_failure_that_writes_nothing() -> None:
    """`validate_batch`'s count check raises `EmbeddingProviderError`, which `run()` classifies
    as transient. What must not happen is a partial write: with one vector missing, a writer
    that zipped without `strict=True` would attribute vectors to the wrong rows and silently
    drop the last one."""
    project_id = ProjectId(uuid4())
    rows = [_row(project_id, f"content-{i}") for i in range(3)]
    vector_for = {row.content: _vector(i) for i, row in enumerate(rows)}
    port = _FakeEmbeddingPort(vector_for=vector_for, drop_last_vector=True)
    repo = _FakeRepo(rows)
    embedder = _embedder(port=port, repo=repo, max_batch=10)

    result = embedder.run(project_id, limit=50)

    assert repo.writes == []
    assert result.embedded_count == 0
    assert len(result.failures) == 1
    assert "EmbeddingProviderError" in result.failures[0].reason


def test_a_non_finite_component_is_never_written() -> None:
    """A single NaN poisons every ANN distance the vector ever participates in, and unlike a
    wrong dimension nothing downstream would raise on it."""
    project_id = ProjectId(uuid4())
    rows = [_row(project_id, "content-0")]
    port = _FakeEmbeddingPort(vector_for={"content-0": [1.0, float("nan"), 3.0]})
    repo = _FakeRepo(rows)
    embedder = _embedder(port=port, repo=repo)

    result = embedder.run(project_id, limit=50)

    assert repo.writes == []
    assert len(result.failures) == 1
    # Still eligible on the next sweep: nothing was stamped.
    assert embedder.run(project_id, limit=50).candidates_considered == 1


def test_earlier_chunks_stay_written_when_a_later_chunk_fails() -> None:
    project_id = ProjectId(uuid4())
    rows = [_row(project_id, f"content-{i}") for i in range(3)]
    vector_for = {row.content: _vector(i) for i, row in enumerate(rows)}
    port = _FakeEmbeddingPort(
        vector_for=vector_for, raise_sequence=[None, EmbeddingTimeout("stalled"), None]
    )
    repo = _FakeRepo(rows)
    embedder = _embedder(port=port, repo=repo, max_batch=1)

    result = embedder.run(project_id, limit=50)

    assert result.port_calls == 3
    assert result.embedded_count == 2
    assert [w[1] for w in repo.writes] == [rows[0].id, rows[2].id]
    assert result.failures[0].memory_ids == (rows[1].id,)

    # Exactly the failed row -- and only it -- comes back on the next sweep.
    healthy = dataclasses.replace(
        embedder, embedding_port=_FakeEmbeddingPort(vector_for=vector_for)
    )
    retry = healthy.run(project_id, limit=50)
    assert retry.candidates_considered == 1
    assert [w[1] for w in repo.writes] == [rows[0].id, rows[2].id, rows[1].id]


# --------------------------------------------------------------------------- #
# Clock is honoured, not `datetime.now()`
# --------------------------------------------------------------------------- #


def test_result_timestamps_come_from_the_injected_clock() -> None:
    """`started_at` and `finished_at` must be two READS of the injected clock taken around the
    work, not one read used twice: a fake port that advances the clock inside `embed()` is the
    only way a FakeClock-driven test can tell those apart (a `finished_at = started_at`
    mutation passes every assertion that does not make time pass during the sweep)."""
    project_id = ProjectId(uuid4())
    rows = [_row(project_id, "content-0")]
    clock = FakeClock()
    port = _FakeEmbeddingPort(vector_for={"content-0": _vector(0)}, clock=clock, elapsed_seconds=7)
    repo = _FakeRepo(rows)
    embedder = _embedder(port=port, repo=repo, clock=clock)

    before = clock.now()
    clock.advance(seconds=5)
    started = clock.now()
    result = embedder.run(project_id, limit=50)

    assert isinstance(result, EmbeddingRunResult)
    assert result.started_at == started
    assert result.started_at > before
    assert result.finished_at == clock.now()
    assert (result.finished_at - result.started_at).total_seconds() == 7.0
    assert result.started_at.tzinfo is not None
