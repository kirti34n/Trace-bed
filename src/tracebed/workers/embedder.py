"""The embedding writer -- turns `memory_item.embedding` from permanently-NULL into a real
column (PLAN.md section 5 DDL; FIDELITY-AUDIT.md M8; chunk `embedding-writer`).

THE GAP THIS CLOSES: `stores.pg.repo.Repo.insert_memory_item` writes no `embedding` column
(confirmed by grep: zero `UPDATE memory_item SET embedding` anywhere in `src/`), so
`stores.pg.search.vector_arm`'s `WHERE embedding IS NOT NULL` predicate never matches a row.
"Hybrid retrieval" is lexical-only in production today, silently. `stores.vector.pgvector
.PgVectorStore.upsert` already names this precisely and raises `VectorStoreWriteUnavailable`
rather than inventing SQL outside `stores/pg/` -- this module is the fix that upsert's own
docstring says must land in `stores/pg/` before it can serve writes. This chunk does not touch
`stores/pg/` (outside its file list); it defines the write primitive it needs as a Protocol and
reports the concrete implementation as a contract_gap, exactly as `workers.invalidator`'s
`MemoryLifecycleRepoPort` and `workers.distiller`'s `KnownDistillationPort` already do for their
own missing `Repo` methods.

WHY A WORKER, NOT AN INSERT-TIME CALL (task description, restated because it is the load-bearing
design decision this whole module exists to honour): embedding is a network call. Making
`insert_memory_item` await one would (a) hold a `memory_item` row lock across a round trip to a
remote endpoint, (b) turn "the embedding provider is briefly down" into "no memory can be
written", and (c) put a provider client one import away from code `scripts/purity_check.py`
protects -- `EmbeddingPort` is permitted on the hot path under its own 200ms sub-budget for
QUERY embedding (PLAN.md invariant 1), never as a synchronous dependency of a write. Asynchronous
is correct, not a workaround: this worker runs as a periodic sweep (see `workers.scheduler`),
independent of the write path, and a memory is fully insertable, retrievable via BM25, and usable
in every governance transition (quarantine, promotion, retirement -- none of which read
`embedding`) before it is ever embedded.

IDEMPOTENCY IS THE MIGRATION PATH (task description; `adapters.embedding.pinning`'s module
docstring, step 1-5): `select_needing_embedding`'s predicate is `embedding IS NULL OR
embedding_model_id <> :model_id OR embedding_model_version <> :model_version`, evaluated against
THIS worker's configured `pin` on every call, not cached. Re-running with an unchanged pin
re-embeds nothing (every row already satisfies the predicate's negation). Changing
`EmbeddingConfig.model_id`/`model_version` and redeploying makes EVERY existing row satisfy the
predicate again on the very next sweep -- that re-selection, not a special "backfill mode", IS
the explicit versioned re-embedding migration PLAN.md section 10 requires ("swap the embedding
model silently" is refused by construction: there is no code path that changes a row's stamped
pin without also writing a new, validated vector produced under it).

THE DRIVER'S OWN IDENTITY IS CHECKED AGAINST THE PIN, at construction AND again before every
`embed()` call. `EmbeddingPort` advertises `model_id`/`model_version` (`adapters.ports`), and
this worker is the first code in the tree that stamps those columns -- so it is the first place
where "the pin this deployment CONFIGURED" and "the model that actually produced this vector"
can silently disagree. They disagree in exactly the shape PLAN.md section 10 forbids: point
`EmbeddingConfig` at a new `model_version` (the documented migration's step 2) without
redeploying the driver, and every row is stamped with the NEW pin while holding a vector from
the OLD model. Nothing downstream can ever detect that -- `assert_pin_matches` compares a row's
stamp against the configured pin and would pass, and the re-embed predicate below considers the
row done, so it is never revisited. The vectors then sit in the ANN arm in the wrong vector
space, permanently, with a correct-looking label. `_assert_driver_matches_pin` is therefore not
belt-and-braces: it is the only place in the system where that swap is observable, and it is
FIDELITY-AUDIT.md S16's "the embedding-pin guard is never called" gaining its first production
call site.

ONLY RETRIEVABLE ROWS ARE EMBEDDED. `select_needing_embedding` carries `status = ANY(
RETRIEVABLE_STATUSES)` and `_assert_eligible` re-checks it on the way back, against
`domain.state_machine.RETRIEVABLE_STATUSES` itself -- the domain constant, not a copy. This is
the same fail-closed discipline `stores.pg.search.assert_dynamically_retrievable` applies on read
and for the same reason its docstring gives ("the SQL predicate is the control; this is the
assertion that the control held"), but it buys something the read-side assertion cannot: a
quarantined row that never receives a vector cannot be returned by an ANN scan even if a future
edit to `vector_arm`'s predicate drops a conjunct. Quarantine is enforced in the DATA, not only
in the query text. Note the deliberate asymmetry with `stores.pg.search`, which narrows further
(it excludes `pinned` and Tier-B `candidate` rows): that narrowing is the reader's, for reasons
specific to slotting and trust labelling, and re-encoding it here would make this module a
second author of "what is retrievable" -- the D-118 defect. A superset is safe: a `pinned` row
holding an unused vector is wasted spend, never a leak.

TWO FAILURE CLASSES, TWO RESPONSES, and the distinction is deliberate rather than uniform
error-handling laziness:

  * `EmbeddingTimeout` / `EmbeddingProviderError` (`adapters.embedding.pinning` and
    `domain.errors`) are transport/transient: the endpoint was slow, dropped a connection, or
    answered with a malformed body. `run()` catches these PER CHUNK, records the failure, and
    moves on to the next chunk -- the failed chunk's rows are simply left exactly as they were
    (still `embedding IS NULL`), which is what makes them retryable rather than half-written:
    nothing about a caught failure ever calls `write_embedding`.
  * `EmbeddingDimensionMismatch` (task description: "refuse a dimension mismatch ... rather than
    truncating or padding") means the configured `pin.dim` disagrees with what the driver
    actually produced -- a static misconfiguration that will not resolve itself on the next
    sweep with the same pin. `run()` does NOT catch it: it propagates out of the whole call,
    stopping this project's sweep loudly rather than burning the timeout/spend budget on every
    remaining chunk repeating the identical, unfixable failure. `validate_batch` (shared with
    both `EmbeddingPort` drivers) runs before a single `write_embedding` call for the chunk it
    rejects, so "raises" and "writes nothing for that chunk" are the same property: the write
    loop is unreachable code once `validate_batch` has raised. Chunks already written earlier in
    the same `run()` call stay written -- there is nothing wrong with their vectors, only with
    the chunk that failed.

SPEND: mirrors `workers.distiller`'s already-established pattern exactly, including the
CONTRACT GAP it already documents (`domain.config.SpendConfig` has `daily_llm_cap_usd` and no
price table, so `usd_per_1k_tokens` is an injected, REQUIRED constructor field, and
`_estimate_tokens` reuses the identical chars-per-4 heuristic
`workers.extractors.base._estimate_token_count` / `workers.distiller._estimate_tokens` already
document as a gap -- no canonical tokenizer exists anywhere in this codebase and
`EmbeddingPort.embed` returns no usage payload to read a real count from). Also mirrored: THIS
MODULE DOES NOT WIRE A `workers.spend_enforce.SpendEnforcer` ITSELF. `spend_enforce.py`'s own
module docstring names its integration point explicitly -- "a distiller, judge, or
shadow-validator batch loop wraps its per-project unit of ... costing work in this call" -- and
an embedding sweep is the same shape of unit. `Embedder.run(project_id, ...)` is exactly the
callable a caller wraps in `SpendEnforcer.run_guarded(project_id, lambda: embedder.run(...))` to
get "pause on cap" for free; baking a second enforcement point in here would duplicate that
guard rather than compose with it, and every LLM-costing worker in this tree (`distiller.py`)
already keeps the same separation.

CONTRACT GAP (reported, not deviated on): no field in `domain.config` governs a background
embedding call's timeout or per-call batch size. `RetrievalConfig.embed_timeout_ms` (200ms) is
explicitly the HOT PATH's query-embedding sub-budget (PLAN.md invariant 1's own text: "Query
embedding is permitted only through EmbeddingPort with its own sub-budget (200ms)") -- reusing
it here would starve a background batch of many texts to a budget sized for one query string.
`QueueConfig.batch_size` governs `work_queue` claims, not embedding-port call sizing. `timeout_ms`
and `max_batch` are therefore required, no-default constructor fields (the same shape
`Distiller.max_tokens`/`usd_per_1k_tokens_in` already use for an identically undeclared value),
reported here for whoever adds an `EmbeddingWorkerConfig`-shaped section to `domain/config.py`.
"""

from __future__ import annotations

import math
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol, runtime_checkable

from tracebed.adapters.embedding.pinning import (
    EmbeddingProviderError,
    ModelPin,
    assert_pin_matches,
    validate_batch,
)
from tracebed.adapters.ports import EmbeddingPort
from tracebed.domain.clock import Clock
from tracebed.domain.errors import EmbeddingTimeout, TracebedError
from tracebed.domain.ids import MemoryId, ProjectId
from tracebed.domain.state_machine import RETRIEVABLE_STATUSES, Status

__all__ = [
    "ChunkFailure",
    "Embedder",
    "EmbeddingCandidateRow",
    "EmbeddingRepoPort",
    "EmbeddingRunResult",
    "SpendRecorderPort",
]


def _estimate_tokens(text: str) -> int:
    """Same heuristic as `workers.distiller._estimate_tokens` -- see module docstring's SPEND
    section for why no real tokenizer is available here either."""
    return max(1, len(text) // 4)


def _chunked(
    rows: Sequence[EmbeddingCandidateRow], size: int
) -> Iterator[Sequence[EmbeddingCandidateRow]]:
    """Splits `rows` into groups of at most `size`, preserving order -- the property that makes
    `zip(chunk, vectors)` in `Embedder._embed_chunk` a correct row-to-vector pairing rather than
    a silent scramble."""
    for start in range(0, len(rows), size):
        yield rows[start : start + size]


@dataclass(frozen=True, slots=True)
class EmbeddingCandidateRow:
    """One `memory_item` row eligible for (re-)embedding under the currently configured pin --
    the projection `EmbeddingRepoPort.select_needing_embedding` returns.

    Deliberately smaller than `stores.pg.rows.MemoryItemRow`: this worker never reasons about
    provenance, trust tier, or any scoring field -- embedding a row is not a state-machine
    transition (PLAN.md section 5's table has no row for it), so nothing here needs them.

    `status` is the one governance field that IS carried, and only because it decides
    eligibility rather than being decided: a row outside `RETRIEVABLE_STATUSES` must not receive
    a vector at all (module docstring's ONLY RETRIEVABLE ROWS section). Carrying it is what lets
    `Embedder._assert_eligible` re-check the repository's predicate instead of trusting it; the
    same reason `stores.vector.base.VectorStorePort.upsert` already carries `status` on the
    platform's other vector-write primitive.
    """

    project_id: ProjectId
    id: MemoryId
    status: Status
    content: str

    def __post_init__(self) -> None:
        if not self.content:
            raise ValueError(
                f"EmbeddingCandidateRow {self.id}: empty content -- a repository query that "
                "returns a row with nothing to embed is a query bug, not a routine case this "
                "worker should silently paper over"
            )


@dataclass(frozen=True, slots=True)
class ChunkFailure:
    """One `EmbeddingPort.embed` call (covering `EmbeddingRunResult`'s `port_calls` counter's
    worth of one increment) that could not be turned into writes -- see module docstring's
    two-failure-classes note for which exceptions land here versus propagate out of `run()`."""

    memory_ids: tuple[MemoryId, ...]
    reason: str


@dataclass(frozen=True, slots=True)
class EmbeddingRunResult:
    """What one `Embedder.run()` call did for one project -- enough to audit and to feed a
    scheduler's logs without a store round trip."""

    project_id: ProjectId
    started_at: datetime
    finished_at: datetime
    candidates_considered: int
    embedded_count: int
    port_calls: int
    failures: tuple[ChunkFailure, ...] = field(default_factory=tuple)


@runtime_checkable
class EmbeddingRepoPort(Protocol):
    """What `Embedder` needs from a memory store (CONTRACT GAP: no `Repo` method satisfies this
    today -- module docstring's opening paragraph). Declared locally, the same pattern
    `workers.invalidator.MemoryLifecycleRepoPort` and `workers.distiller.KnownDistillationPort`
    already use, so this worker is fully testable with zero Postgres.
    """

    def select_needing_embedding(
        self, project_id: ProjectId, *, model_id: str, model_version: str, limit: int
    ) -> Sequence[EmbeddingCandidateRow]:
        """Every row where

            status = ANY(:retrievable)                      -- values of RETRIEVABLE_STATUSES
            AND (embedding IS NULL
                 OR embedding_model_id <> :model_id
                 OR embedding_model_version <> :model_version)

        capped at `limit`, in a deterministic order (e.g. `ORDER BY id`). See the module
        docstring's IDEMPOTENCY note for why the second conjunct, evaluated fresh against the
        CALLER's `model_id`/`model_version` on every call rather than against a stored "already
        tried" flag, is what makes both idempotent re-runs and a pin change's re-embedding
        migration work from the same query; and its ONLY RETRIEVABLE ROWS note for the first,
        which an implementation must derive from `domain.state_machine.RETRIEVABLE_STATUSES`
        rather than re-listing statuses in SQL. Scoped to `project_id` (RLS-backed) like every
        other repository read (PLAN.md invariant 4/hard rule 6).

        `Embedder` re-checks both the project scope and the status of every returned row
        (`_assert_eligible`) and raises rather than writing if either predicate was missing --
        an implementation that drops one fails loudly on its first sweep, not silently for the
        lifetime of the deployment.

        KNOWN LIVENESS GAP, stated because the deterministic order makes it structural rather
        than unlucky: a row whose text the provider rejects on every attempt (a permanent
        `EmbeddingProviderError`, which `run()` classifies as retryable) is re-selected in the
        same position forever. Rows AFTER it still progress -- the failing chunk is skipped, not
        the sweep -- but if at least `limit` such rows sort ahead of everything else, no other
        row is ever selected again. Closing this needs an attempt counter or a dead-letter
        column on `memory_item`; PLAN.md section 5's DDL has neither, and inventing one in a
        Protocol nothing implements yet would be a guess. Reported, not papered over.
        """
        ...

    def write_embedding(
        self,
        project_id: ProjectId,
        memory_id: MemoryId,
        embedding: Sequence[float],
        *,
        model_id: str,
        model_version: str,
    ) -> None:
        """Sets `embedding`, `embedding_model_id`, `embedding_model_version` on exactly this
        row, scoped to `project_id`. Touches no other column -- `lexemes`, `status`, `q_value`
        and every governance field are owned by other write paths, never by this one.

        ALL THREE COLUMNS IN ONE STATEMENT, and this is a correctness requirement rather than a
        style preference. Split across two statements, a crash (or a lost race) between them
        leaves a row stamped with the new pin while still holding the old vector -- which the
        re-embed predicate above then treats as done, forever. `migrations/0002_partitioned.sql`
        already refuses the split at the storage layer (`CHECK ((embedding IS NULL AND
        embedding_model_id IS NULL AND embedding_model_version IS NULL) OR (embedding IS NOT
        NULL AND ...))`), so a two-statement implementation fails on the first one rather than
        corrupting the row; that CHECK is the reason concurrent sweeps under different pins are
        safe here at all -- whichever writer lands last leaves a consistent triple, never a
        vector wearing another model's label. `dim` is
        deliberately not a parameter: PLAN.md section 5's DDL has no separate `dim` column
        (`adapters.embedding.pinning.assert_pin_matches`'s docstring already establishes why --
        the `halfvec(dim)` column type fixes it for the whole partition), so `Embedder` validates
        `dim` against the returned vector (`validate_batch`) but never stamps it as a value.
        """
        ...


@runtime_checkable
class SpendRecorderPort(Protocol):
    """Exactly `workers.spend.SpendMeter.add`'s signature. Declared locally rather than imported
    from `workers.distiller` (identical shape there) so this chunk depends on no sibling worker
    module -- the same reasoning `workers.spend_enforce.SpendCapCheckPort`'s docstring gives for
    not depending on the concrete `SpendMeter` class."""

    def add(
        self,
        project_id: ProjectId,
        worker: str,
        model_id: str,
        tokens_in: int,
        tokens_out: int,
        cost_usd: float,
    ) -> None: ...


@dataclass(slots=True)
class Embedder:
    """The embedding writer (PLAN.md section 5 DDL; FIDELITY-AUDIT.md M8; module docstring).

    Every dependency is a `Protocol` or an injectable primitive (`Clock`, `ModelPin`), so this
    worker runs fully offline against fakes (no Postgres/live embedding endpoint on the build
    machine). `pin` is the deployment's configured `(model_id, model_version, dim)` -- the same
    triple `adapters.embedding.gemini.GeminiEmbeddingClient`/`OnnxLocalEmbeddingClient` are
    constructed with, so a correctly wired deployment's driver and this worker always agree on
    what "the current pin" means without either reading it off the other.
    """

    clock: Clock
    embedding_port: EmbeddingPort
    repo: EmbeddingRepoPort
    spend: SpendRecorderPort
    pin: ModelPin
    usd_per_1k_tokens: float
    timeout_ms: int
    max_batch: int
    worker_name: str = "embedder"

    def __post_init__(self) -> None:
        if not self.worker_name:
            raise ValueError("Embedder.worker_name must not be empty")
        if self.timeout_ms <= 0:
            raise ValueError(f"Embedder.timeout_ms must be positive, got {self.timeout_ms}")
        if self.max_batch <= 0:
            raise ValueError(f"Embedder.max_batch must be positive, got {self.max_batch}")
        # A NaN/negative price makes SpendMeter.add raise on every call (see its own docstring),
        # which would turn "misconfigured price" into "this worker cannot write anything",
        # rather than the named-at-construction failure `Distiller.__post_init__` prefers for
        # the identical hazard.
        if not math.isfinite(self.usd_per_1k_tokens) or self.usd_per_1k_tokens < 0.0:
            raise ValueError(
                f"Embedder.usd_per_1k_tokens must be finite and non-negative, got "
                f"{self.usd_per_1k_tokens}; a negative or NaN price silently disables the "
                "daily spend cap"
            )
        # `ModelPin` is a bare dataclass with no validation of its own (adapters/embedding/
        # pinning.py, outside this chunk's file list), and every one of these three fields is
        # written to a row by this worker: `dim <= 0` makes `validate_batch` accept only an
        # EMPTY vector, which `stores.pg.search._embedding_literal` then refuses at query time
        # -- a write-time misconfiguration surfacing as a read-time crash on someone else's
        # request. An empty `model_id`/`model_version` stamps an empty identity that satisfies
        # the re-embed predicate's negation just as well as a real one, permanently marking the
        # row embedded under a pin no `embedding_model` row can ever match.
        if self.pin.dim <= 0:
            raise ValueError(f"Embedder.pin.dim must be positive, got {self.pin.dim}")
        if not self.pin.model_id or not self.pin.model_version:
            raise ValueError(
                "Embedder.pin.model_id and .model_version must both be non-empty; they are "
                "stamped verbatim on every row this worker writes"
            )
        # Named at wiring time rather than on the first sweep: see the module docstring's
        # THE DRIVER'S OWN IDENTITY section for what a mismatch does if it is allowed to write.
        self._assert_driver_matches_pin()

    def run(self, project_id: ProjectId, *, limit: int) -> EmbeddingRunResult:
        """Embeds up to `limit` rows for `project_id` that need it under the configured `pin`.

        One project per call, matching every other batch worker in this tree (PLAN.md section
        10: a worker batch must never mix projects) -- a scheduler iterates known projects and
        calls this once per project, exactly as `workers.scheduler`'s module docstring describes
        for its own jobs.
        """
        if limit <= 0:
            raise ValueError(f"Embedder.run limit must be positive, got {limit}")

        started_at = self.clock.now()
        candidates = tuple(
            self.repo.select_needing_embedding(
                project_id,
                model_id=self.pin.model_id,
                model_version=self.pin.model_version,
                limit=limit,
            )
        )
        self._assert_eligible(project_id, candidates)

        embedded_count = 0
        port_calls = 0
        failures: list[ChunkFailure] = []
        for chunk in _chunked(candidates, self.max_batch):
            port_calls += 1
            try:
                self._embed_chunk(project_id, chunk)
            except (EmbeddingTimeout, EmbeddingProviderError) as exc:
                # Transient/transport failure: the chunk's rows were never written (see module
                # docstring's two-failure-classes note), so they remain selectable -- retryable,
                # not half-written -- on the next call with an unchanged predicate.
                failures.append(
                    ChunkFailure(
                        memory_ids=tuple(row.id for row in chunk),
                        reason=f"{type(exc).__name__}: {exc}",
                    )
                )
                continue
            embedded_count += len(chunk)

        return EmbeddingRunResult(
            project_id=project_id,
            started_at=started_at,
            finished_at=self.clock.now(),
            candidates_considered=len(candidates),
            embedded_count=embedded_count,
            port_calls=port_calls,
            failures=tuple(failures),
        )

    # ---------------------------------------------------------------- internals ----------

    def _embed_chunk(self, project_id: ProjectId, chunk: Sequence[EmbeddingCandidateRow]) -> None:
        """One `EmbeddingPort.embed` call for up to `max_batch` rows, then one `write_embedding`
        per row. `EmbeddingDimensionMismatch` from `validate_batch` is INTENTIONALLY not caught
        here -- see module docstring -- so it propagates to `run()`'s caller rather than to
        `run()`'s own per-chunk except clause, which only names the two transient exceptions.
        """
        # Re-checked per chunk, not only at construction: `embedding_port` is a Protocol, and
        # `model_id`/`model_version` are properties a driver is free to compute per call (both
        # shipped drivers read them off an injected `ModelPin`, but a gateway driver resolving
        # "whatever model the endpoint currently serves" is exactly the deployment this guard
        # exists for). Checked BEFORE `embed()` so a mismatched driver costs neither a request
        # nor a ledger entry.
        self._assert_driver_matches_pin()
        texts = [row.content for row in chunk]
        try:
            vectors = self.embedding_port.embed(texts, timeout_ms=self.timeout_ms)
        finally:
            # The request was already on the wire (or the attempt to put it there already spent
            # the input tokens it carried) by the time embed() returns OR raises -- identical
            # rationale to workers.distiller._record_spend's finally-equivalent placement, so a
            # timing-out or malformed-response endpoint does not become free, unmetered spend
            # that workers.spend_enforce.SpendEnforcer can never see.
            self._record_spend(project_id, texts)

        # Raises EmbeddingDimensionMismatch / EmbeddingProviderError (count, non-finite) before
        # a single write happens -- "refuse a dimension mismatch rather than truncating or
        # padding" (task description) and "writes nothing" are the same property here: the loop
        # below is unreachable once this has raised.
        validate_batch(vectors, expected=len(chunk), configured=self.pin)

        for row, vector in zip(chunk, vectors, strict=True):
            self.repo.write_embedding(
                project_id,
                row.id,
                vector,
                model_id=self.pin.model_id,
                model_version=self.pin.model_version,
            )

    def _record_spend(self, project_id: ProjectId, texts: Sequence[str]) -> None:
        """Records one actual `embed()` invocation against `spend_ledger`. `tokens_out=0` always
        -- embedding produces a vector, not text, so there is no output-token count to charge
        (unlike `Distiller`, which prices both `_in` and `_out`)."""
        tokens_in = sum(_estimate_tokens(text) for text in texts)
        cost_usd = tokens_in * self.usd_per_1k_tokens / 1000.0
        self.spend.add(project_id, self.worker_name, self.pin.model_id, tokens_in, 0, cost_usd)

    def _assert_driver_matches_pin(self) -> None:
        """The configured pin and the wired driver must be the same model (module docstring's
        THE DRIVER'S OWN IDENTITY section).

        Delegates to `adapters.embedding.pinning.assert_pin_matches` rather than comparing the
        two strings here, so the comparison that decides "is this the pin we committed to" has
        exactly one author (D-118's defect is two). Its `EmbeddingPinMismatch` message says
        "row embedded under X" -- read as "the vectors this driver produces would be embedded
        under X", which is precisely what would land on every row of this sweep.

        `EmbeddingPinMismatch` is a `TracebedError` and NOT one of the two exceptions `run()`
        catches per chunk, so it aborts the sweep the same way `EmbeddingDimensionMismatch`
        does, and for the same reason: a wiring mismatch is static and reproduces identically on
        every remaining chunk.
        """
        assert_pin_matches(
            self.embedding_port.model_id, self.embedding_port.model_version, self.pin
        )

    @staticmethod
    def _assert_eligible(project_id: ProjectId, rows: Sequence[EmbeddingCandidateRow]) -> None:
        """Re-checks BOTH predicates `select_needing_embedding` is contracted to apply, against
        rows it has already returned.

        Scope, mirroring `workers.distiller._read_trace_index`'s identical foreign-row refusal:
        invariant 4 is a property a correctly scoped `EmbeddingRepoPort` must never violate in
        the first place, and a fake or a future `Repo` implementation that ignored the
        `project_id` it was called with is a bug this worker must not launder into a
        cross-project vector write.

        Retrievability, mirroring `stores.pg.search.assert_dynamically_retrievable`'s refusal on
        the read side (module docstring's ONLY RETRIEVABLE ROWS section): a quarantined or
        tombstoned row that never receives a vector cannot be reached by an ANN scan at all, so
        the guarantee survives an edit to `vector_arm`'s predicate. Compared against
        `domain.state_machine.RETRIEVABLE_STATUSES` -- the constant, not a copy of its contents.
        Deliberately NOT delegated to `assert_dynamically_retrievable` itself: that function is
        the dynamic ARM's rule (it additionally excludes `pinned` and Tier-B `candidate` rows),
        and a writer that adopted it would inherit a read-side narrowing it has no business
        enforcing -- while a worker importing `stores.pg.search` for a pure predicate would
        couple this module to a query surface it never issues.

        Both sweep the whole list before raising (not the first match) for the same reason
        `Distiller._find_duplicate`'s docstring gives: a detector that stops at the first bad
        row would miss the rest of exactly the calls where the predicate has already broken.
        Raising costs one sweep and leaves every row exactly as it was; not raising costs the
        isolation or quarantine guarantee silently, for as long as the bug survives.
        """
        foreign = [row for row in rows if row.project_id != project_id]
        if foreign:
            raise TracebedError(
                f"select_needing_embedding for project {project_id} returned {len(foreign)} "
                f"row(s) belonging to another project (first: memory {foreign[0].id} in "
                f"project {foreign[0].project_id}) -- invariant 4 requires every repository "
                "query to be scoped server-side"
            )
        unretrievable = [row for row in rows if row.status not in RETRIEVABLE_STATUSES]
        if unretrievable:
            raise TracebedError(
                f"select_needing_embedding for project {project_id} returned "
                f"{len(unretrievable)} row(s) whose status is not retrievable (first: memory "
                f"{unretrievable[0].id}, status {unretrievable[0].status.value!r}) -- embedding "
                "one would put a vector for non-retrievable content in the ANN arm's reach"
            )
