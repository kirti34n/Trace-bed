"""Postgres implementations of the two learning-plane worker ports that had none
(FIDELITY-AUDIT.md M3/M6/M8; PLAN.md §11.1).

`workers/embedder.py` and `workers/corroboration.py` each declared the store primitive it
needed as a local `Protocol` and reported the concrete implementation as a contract_gap,
because neither chunk's file list reached `stores/pg/`. The result was two complete,
mutation-tested workers whose only implementations were test fakes — the same shape as M1's
`persist_status`, and the same consequence: a repair nobody constructs is not a repair.
This module is those two implementations.

WHAT IS HERE AND WHAT IS NOT. Two classes, `EmbeddingRepo` and `CorroborationRepo`, each
satisfying its worker's Protocol structurally (never by inheritance — the Protocols live in
`workers/`, and `stores/pg/` importing a worker module for a base class would invert the
dependency direction every other store in this package keeps). The other eight ports M3
enumerates (`ScorerRepoPort`, `ShadowValidatorRepoPort`, `PromotionRepoPort`,
`KillswitchStorePort`, `DerivedStateStorePort`, `ForensicsRepoPort`, `MemoryEditRepoPort`,
`ReviewQueueRepoPort`, `EpochStorePort`) are NOT here and are still open — see PLAN.md §11.

INVARIANT 4 ON EVERY STATEMENT. Every method takes `ProjectId` first, opens its own
`scoped()` transaction (which issues the `tracebed.project_id` GUC as the transaction's first
statement), and carries `project_id = %(project_id)s` in the statement's own predicate. The
GUC and the predicate are not redundant: RLS is the backstop for a statement that forgot the
predicate, and the predicate is the control for a connection whose GUC was never set. Both
halves are asserted structurally by `tests/phase1/test_learning_repos.py`, which parses each
statement rather than trusting this docstring, and executed end to end by that file's
`@pytest.mark.integration` tests.

NO STATUS COLUMN IS WRITTEN HERE. `EmbeddingRepo.write_embedding` touches exactly three
columns and `CorroborationRepo.append_confirming_run` touches exactly one; neither can move a
memory between statuses. That is hard rule 5 held at the store layer: the only statement in
`src/` that writes `memory_item.status` is `stores.pg.lifecycle.LifecycleWriter`'s, and it
runs only on a `(from, to)` pair `domain.state_machine` recognises. `append_confirming_run`
READS `status` (its eligibility conjunct) and never assigns it — recording evidence is not a
transition, and the transition it eventually justifies is `workers.shadow_validator`'s to
decide.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Final

from psycopg.rows import DictRow, dict_row
from psycopg_pool import ConnectionPool

from tracebed.domain.errors import TracebedError
from tracebed.domain.ids import MemoryId, ProjectId, RunId
from tracebed.domain.memory import Provenance
from tracebed.domain.state_machine import RETRIEVABLE_STATUSES, Status
from tracebed.stores.pg.pool import scoped
from tracebed.workers.corroboration import (
    AppendOutcome,
    QuarantinedMemoryForCorroboration,
)
from tracebed.workers.embedder import EmbeddingCandidateRow

__all__ = ["CorroborationRepo", "EmbeddingRepo"]


# Derived from the domain constant, never re-listed as SQL literals: `workers.embedder`'s own
# port docstring requires "an implementation must derive this from
# `domain.state_machine.RETRIEVABLE_STATUSES` rather than re-listing statuses in SQL", and a
# re-listed copy is exactly the second-author defect D-118 records. `sorted` only so the bound
# array has a stable order in a query log.
_RETRIEVABLE_STATUS_VALUES: Final[tuple[str, ...]] = tuple(
    sorted(status.value for status in RETRIEVABLE_STATUSES)
)


def _embedding_literal(embedding: Sequence[float]) -> str:
    """pgvector's text input format for a `halfvec`: `[v1,v2,...]`.

    Deliberately NOT imported from `stores.pg.search._embedding_literal`: that one is a
    private helper of the READ path, and a write path reaching into another module's
    underscore-prefixed name couples the two in a direction neither documents. The rendering
    rule is pgvector's, not this repository's, so having it stated in both places is not two
    authors of one governing decision — it is two call sites of one external format. What this
    copy does NOT do is re-validate the components: `adapters.embedding.pinning.validate_batch`
    has already refused a non-finite component before `Embedder` calls `write_embedding`, and a
    second refusal here would be a second author of "what is a usable vector". `repr()` on a
    Python `float` can only ever produce a decimal/scientific literal, so nothing caller-shaped
    reaches the statement text.
    """
    if not embedding:
        raise ValueError("embedding must not be empty")
    return "[" + ",".join(repr(float(v)) for v in embedding) + "]"


# --------------------------------------------------------------------------- #
# Embedding (FIDELITY-AUDIT.md M8)
# --------------------------------------------------------------------------- #

_SELECT_NEEDING_EMBEDDING_SQL: Final[str] = """
SELECT id, project_id, status, content
FROM memory_item
WHERE project_id = %(project_id)s
  AND status = ANY(%(statuses)s)
  AND (embedding IS NULL
       OR embedding_model_id <> %(model_id)s
       OR embedding_model_version <> %(model_version)s)
ORDER BY id
LIMIT %(limit)s
""".strip()

_WRITE_EMBEDDING_SQL: Final[str] = """
UPDATE memory_item
   SET embedding = %(embedding)s::halfvec,
       embedding_model_id = %(model_id)s,
       embedding_model_version = %(model_version)s
 WHERE project_id = %(project_id)s AND id = %(memory_id)s
""".strip()


class EmbeddingRepo:
    """`workers.embedder.EmbeddingRepoPort` over Postgres.

    Satisfies the Protocol structurally; `tests/phase1/test_learning_repos.py` asserts the
    `isinstance` against the `runtime_checkable` Protocol so a signature drift on either side
    fails a test rather than a deployment.
    """

    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    def select_needing_embedding(
        self, project_id: ProjectId, *, model_id: str, model_version: str, limit: int
    ) -> Sequence[EmbeddingCandidateRow]:
        """The port's contracted predicate, verbatim (`workers/embedder.py`).

        `ORDER BY id` is the deterministic order the port asks for, and is also the reason
        that port documents a KNOWN LIVENESS GAP: a row the provider permanently rejects is
        re-selected in the same position forever. This implementation does not close that gap
        — closing it needs an attempt counter or a dead-letter column, and PLAN.md §5's DDL has
        neither — it inherits it, and says so here rather than letting the reader assume a real
        store fixed what the fake could not.
        """
        if limit <= 0:
            raise ValueError(f"limit must be positive, got {limit}")
        with scoped(self._pool, project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                _SELECT_NEEDING_EMBEDDING_SQL,
                {
                    "project_id": project_id,
                    "statuses": list(_RETRIEVABLE_STATUS_VALUES),
                    "model_id": model_id,
                    "model_version": model_version,
                    "limit": limit,
                },
            )
            rows = cur.fetchall()
        return [_row_to_embedding_candidate(row) for row in rows]

    def write_embedding(
        self,
        project_id: ProjectId,
        memory_id: MemoryId,
        embedding: Sequence[float],
        *,
        model_id: str,
        model_version: str,
    ) -> None:
        """All three columns in ONE statement, which the port's docstring makes a correctness
        requirement rather than a style preference: split across two, a crash between them
        leaves a row stamped with the new pin while holding the old vector, and the re-embed
        predicate above then treats that row as done forever.

        A zero-row result is not raised on, deliberately. The `WHERE` has no status conjunct,
        so the only ways to match nothing are "the memory was deleted" and "it belongs to
        another project" — the second is impossible here (`_assert_eligible` has already
        refused a foreign row before this is called, and RLS refuses it again), and the first
        is an ordinary race with a crypto-shred tombstone. Raising would abort a whole sweep
        over one row that no longer exists.
        """
        # Rendered BEFORE the transaction is opened, deliberately: a refusal inside `scoped()`
        # would have already taken a pooled connection and issued the GUC statement, so "a
        # refused write issues no SQL" would be false by one statement. It costs nothing to
        # validate first and it keeps that property exactly true.
        literal = _embedding_literal(embedding)
        with scoped(self._pool, project_id) as conn:
            conn.execute(
                _WRITE_EMBEDDING_SQL,
                {
                    "embedding": literal,
                    "model_id": model_id,
                    "model_version": model_version,
                    "project_id": project_id,
                    "memory_id": memory_id,
                },
            )


def _row_to_embedding_candidate(row: DictRow) -> EmbeddingCandidateRow:
    """Parse one row, refusing anything the predicate should have excluded.

    The same fail-loud discipline `stores.pg.search._row_to_arm_hit` applies on the read side:
    the SQL predicate is the control, and this is the assertion that the control held.
    `EmbeddingCandidateRow.__post_init__` already refuses empty content; the status check is
    here rather than only in `Embedder._assert_eligible` so that a caller who reaches this repo
    without going through `Embedder` gets the same refusal.
    """
    status = Status(row["status"])
    if status not in RETRIEVABLE_STATUSES:  # pragma: no cover - predicate holds; see docstring
        raise TracebedError(
            f"select_needing_embedding returned memory {row['id']} with non-retrievable "
            f"status {status.value!r}: the status conjunct has been lost from the statement"
        )
    return EmbeddingCandidateRow(
        project_id=ProjectId(row["project_id"]),
        id=MemoryId(row["id"]),
        status=status,
        content=str(row["content"]),
    )


# --------------------------------------------------------------------------- #
# Shadow confirmation (FIDELITY-AUDIT.md M6)
# --------------------------------------------------------------------------- #

_SELECT_QUARANTINED_SQL: Final[str] = """
SELECT id, project_id, status, provenance, shadow_confirm_runs
FROM memory_item
WHERE project_id = %(project_id)s AND status = %(quarantined)s
ORDER BY created_at, id
""".strip()

# Exactly the statement `CorroborationRepoPort.append_confirming_run`'s docstring prescribes,
# including the `FOR NO KEY UPDATE` lock that makes the three answers isolation-level
# independent. Reproduced rather than paraphrased: the port docstring is the specification and
# a divergence between it and the statement is the defect the whole three-valued outcome exists
# to prevent. `tests/phase1/test_learning_repos.py` asserts the two agree.
_APPEND_CONFIRMING_RUN_SQL: Final[str] = """
WITH locked AS (
    SELECT id, status, shadow_confirm_runs
      FROM memory_item
     WHERE project_id = %(project_id)s AND id = %(memory_id)s
       FOR NO KEY UPDATE
), updated AS (
    UPDATE memory_item m
       SET shadow_confirm_runs = array_append(m.shadow_confirm_runs, %(run_id)s)
      FROM locked l
     WHERE m.project_id = %(project_id)s AND m.id = l.id
       AND l.status = %(quarantined)s
       AND NOT (%(run_id)s = ANY(l.shadow_confirm_runs))
    RETURNING m.id
)
SELECT EXISTS (SELECT 1 FROM updated)          AS appended,
       %(run_id)s = ANY(l.shadow_confirm_runs) AS already_present,
       l.status = %(quarantined)s              AS eligible
  FROM locked l
""".strip()


class CorroborationRepo:
    """`workers.corroboration.CorroborationRepoPort` over Postgres.

    `shadow_confirm_runs` is the only non-human route out of quarantine, so this is the one
    store method in the tree an attacker-influenced input can grow. Two bounds hold it: the
    statement's own membership predicate (distinctness, PLAN.md §5) and
    `CorroborationWriter`'s `MAX_CONFIRMATIONS_CONSIDERED` cap, which is enforced in the
    worker rather than here because the bound belongs beside the constant that states it.
    """

    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    def select_quarantined(
        self, project_id: ProjectId
    ) -> Sequence[QuarantinedMemoryForCorroboration]:
        """Indexed `(project_id, status)` — `stores.pg.ddl`'s `memory_item` partition carries a
        btree on `status`, which is the index this predicate uses. Never a trace scan.

        Unpaginated, matching `ShadowValidatorRepoPort.select_quarantined`'s own shape: the
        quarantined set is bounded by `lifecycle.quarantine_ttl_days` (the TTL sweep archives
        anything older), so it is a working set rather than an accumulating one. If that ever
        stops being true the pagination belongs in both selects at once, not in this one alone.
        """
        with scoped(self._pool, project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                _SELECT_QUARANTINED_SQL,
                {"project_id": project_id, "quarantined": Status.QUARANTINED.value},
            )
            rows = cur.fetchall()
        return [_row_to_quarantined(row) for row in rows]

    def append_confirming_run(
        self, project_id: ProjectId, memory_id: MemoryId, run_id: RunId
    ) -> AppendOutcome:
        """The three-valued append (D-125). An empty result set — no `locked` row at all — is
        `ROW_NOT_ELIGIBLE`: the memory is gone or is another project's. That is the case a bare
        `UPDATE`'s row count cannot distinguish from "already present", which is why the
        outcome has three values and why this method returns rather than raises for it.
        """
        with scoped(self._pool, project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                _APPEND_CONFIRMING_RUN_SQL,
                {
                    "project_id": project_id,
                    "memory_id": memory_id,
                    "run_id": run_id,
                    "quarantined": Status.QUARANTINED.value,
                },
            )
            row = cur.fetchone()
        return _append_outcome(row)


def _append_outcome(row: DictRow | None) -> AppendOutcome:
    """Map the statement's three booleans onto the enum, in the one order that is safe.

    `appended` is checked first and `eligible` last on purpose. If a future edit ever made the
    three disagree, the reading that over-reports a write is the dangerous one: `APPENDED`
    claimed for a row that received nothing is a governance lie, while `ROW_NOT_ELIGIBLE`
    reported for a row that was in fact appended costs one redundant offer on the next sweep.
    So the order is "did the UPDATE actually return a row" before either advisory flag.
    """
    if row is None:
        return AppendOutcome.ROW_NOT_ELIGIBLE
    if bool(row["appended"]):
        return AppendOutcome.APPENDED
    if not bool(row["eligible"]):
        return AppendOutcome.ROW_NOT_ELIGIBLE
    if bool(row["already_present"]):
        return AppendOutcome.ALREADY_PRESENT
    # Eligible, not already present, and yet nothing was appended. The statement makes this
    # unreachable (those are exactly the `updated` CTE's own two conjuncts), so reaching it
    # means the statement and this mapping have drifted apart — refuse rather than pick one of
    # the three answers, because every one of them would be a guess about a governance write.
    raise TracebedError(  # pragma: no cover - unreachable unless the statement drifts
        "append_confirming_run: the row was eligible and did not already carry the run, but "
        "no append was reported -- the statement and its outcome mapping have diverged"
    )


def _row_to_quarantined(row: DictRow) -> QuarantinedMemoryForCorroboration:
    """Parse one row, refusing a status the predicate should have excluded.

    `CorroborationWriter._require_row` re-checks this too. Both are kept: this one protects
    any caller reaching the repo directly, that one protects the worker against any repo.
    """
    status = Status(row["status"])
    if status is not Status.QUARANTINED:  # pragma: no cover - predicate holds
        raise TracebedError(
            f"select_quarantined returned memory {row['id']} with status {status.value!r}: "
            "the status conjunct has been lost from the statement"
        )
    provenance_json: Any = row["provenance"]
    return QuarantinedMemoryForCorroboration(
        id=MemoryId(row["id"]),
        project_id=ProjectId(row["project_id"]),
        status=status,
        provenance=Provenance.from_json(provenance_json),
        confirming_run_ids=tuple(RunId(value) for value in (row["shadow_confirm_runs"] or ())),
    )
