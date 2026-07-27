"""`stores.pg.promotion.PromotionRepo` — the Postgres half of
`workers.promotion.PromotionRepoPort` (FIDELITY-AUDIT.md M3; PLAN.md §5 rows 6/12, §11 M3).

`PromotionWorker` drives two governed edges — `candidate -> validated` (promotion) and
`validated -> retired` (retirement, D-021) — through ONE repo object. This store is that
object. It mirrors `stores.pg.lifecycle.ForensicsRepo`/`MemoryEditRepo` structurally: it takes
`(pool, repo, lifecycle)` and COMPOSES rather than reimplements —

  * `persist` builds a `workers.edit_ops.MemoryStatusWrite` and delegates to
    `LifecycleWriter.persist_status`, so the ONE `UPDATE memory_item SET status` statement in
    `src/` stays in `lifecycle.py` (hard rule 5 / PLAN.md §10: a second status UPDATE is the
    admin-bypass this forbids). The `_Vault.persist` contract the harness validated against —
    "raise on a cross-project write, raise on a stale `from_status`, else move the row and log
    it" (`harness/closed_loop.py:362-378`) — is EXACTLY `persist_status`'s semantics: its
    `WHERE project_id = %(project_id)s AND id = %(memory_id)s AND status = %(expected_from)s`
    matches zero rows both when the row moved and when it belongs to another project (RLS +
    the predicate hide it), and zero rows raises `StaleStatusTransition` (a `TracebedError`,
    the same base the fake's "stale transition"/"cross-project status write" raises use).

  * `insert_review_item` delegates verbatim to `Repo.insert_review_item` — the production
    method whose signature `tests/phase3/test_promotion.py::
    test_review_write_matches_the_real_repo_method_signature` pins the port against. Keeping
    the delegate's signature character-for-character identical is why no adapter is needed.

BLOCKED — the two `select_*` methods (reported, NOT faked; contract RISK 2 / FIDELITY-AUDIT
M3). Both `CandidateMemoryRow` and `ValidatedMemoryRow` carry pre-aggregated *governance
evidence* that has no backing schema in migrations 0001-0005, so there is no honest SELECT to
write — and a SELECT that GUESSES silently promotes or retires (retirement is a
memory-destruction primitive, D-021) on invented evidence, which is a far worse failure than a
method that refuses to run:

  * `select_candidates_for_promotion`: `promotion_outcomes` /
    `promotion_distinct_principals` / `outcome_consistent` require an
    `outcome_event ⋈ injection_log` aggregation whose "scored"/"agree per mem_type" predicate
    is specified NOWHERE (composition.py:171-173 says this join "is written nowhere");
    `scan_repass` has NO column (only the ORIGINAL `scan_verdict_id` is persisted, never a
    periodic re-pass); `open_contradiction`'s direction and "open" semantics are undefined
    (`memory_link` has no resolved/closed column).
  * `select_validated_for_retirement`: every field EXCEPT `distinct_scoring_principals` exists
    on `memory_item`, but that one is the D-021 K-floor — distinct principals over the scored
    Q-update ledger (`memory_q_update`), which migration 0006 (`ScorerRepoPort`, RISK 4) has
    not yet created. Sourcing the single most safety-critical field from nothing is the
    catastrophic case.

Both raise `NotImplementedError` with the exact missing schema named, so the store
structurally satisfies the runtime-checkable Protocol (all four methods present) and its WRITE
surface (`persist`, `insert_review_item`) is fully usable and isolation-proven now, while the
worker does not RUN end-to-end until the promotion-evidence and Q-ledger schema decisions land.
"""

from __future__ import annotations

from collections.abc import Sequence

from psycopg_pool import ConnectionPool

from tracebed.domain.ids import MemoryId, ProjectId
from tracebed.stores.pg.lifecycle import LifecycleWriter
from tracebed.stores.pg.repo import Repo
from tracebed.workers.edit_ops import MemoryStatusWrite
from tracebed.workers.promotion import (
    CandidateMemoryRow,
    PromotionTransitionWrite,
    ValidatedMemoryRow,
)

__all__ = ["PromotionRepo"]


class PromotionRepo:
    """`workers.promotion.PromotionRepoPort` over Postgres. Satisfied structurally (the
    Protocol lives in `workers/` and stores must not import it as a base — the
    `learning.py`/`lifecycle.py` convention)."""

    def __init__(self, pool: ConnectionPool, repo: Repo, lifecycle: LifecycleWriter) -> None:
        self._pool = pool
        self._repo = repo
        self._lifecycle = lifecycle

    def persist(self, project_id: ProjectId, write: PromotionTransitionWrite) -> None:
        """Commit the ONE status write `write` describes, via `LifecycleWriter` — no second
        `UPDATE memory_item SET status` (hard rule 5). `write.to_status` is always
        `apply()`'s return value, computed by the worker; this store never decides the edge.

        `actor_principal` defaults `None`: promotion/retirement are machine transitions, so
        nothing here fabricates an actor. A cross-project or stale write raises
        `stores.pg.lifecycle.StaleStatusTransition` (the UPDATE matches zero rows under RLS +
        the `project_id`/`status = from_status` predicate) — the `TracebedError` the harness
        `_Vault` raises for the same two cases.
        """
        self._lifecycle.persist_status(
            project_id,
            MemoryStatusWrite(
                memory_id=write.memory_id,
                from_status=write.from_status,
                to_status=write.to_status,
                now=write.now,
            ),
        )

    def insert_review_item(
        self, project_id: ProjectId, reason: str, memory_id: MemoryId | None = None
    ) -> None:
        """D-021's "otherwise -> review_queue" branch. Delegates verbatim to
        `Repo.insert_review_item` (never a status change); signature pinned to `Repo`'s by
        `tests/phase3/test_promotion.py::test_review_write_matches_the_real_repo_method_signature`.
        """
        self._repo.insert_review_item(project_id, reason, memory_id)

    def select_candidates_for_promotion(
        self, project_id: ProjectId
    ) -> Sequence[CandidateMemoryRow]:
        """BLOCKED — see module docstring / contract RISK 2. `promotion_outcomes`,
        `promotion_distinct_principals` and `outcome_consistent` need an
        `outcome_event ⋈ injection_log` aggregation whose predicate is unspecified;
        `scan_repass` and `open_contradiction` have no backing column. A guessed SELECT would
        promote memories on invented evidence, so this refuses rather than fabricate."""
        raise NotImplementedError(
            f"PromotionRepo.select_candidates_for_promotion (project {project_id}) is blocked: "
            "the promotion-evidence aggregation (outcome_event⋈injection_log for "
            "promotion_outcomes/promotion_distinct_principals/outcome_consistent) is specified "
            "nowhere, and scan_repass/open_contradiction have no backing schema in migrations "
            "0001-0005 (contract RISK 2 / FIDELITY-AUDIT.md M3). The persist + insert_review_item "
            "write surface is implemented; the selects await the §6 promotion-evidence schema."
        )

    def select_validated_for_retirement(
        self, project_id: ProjectId
    ) -> Sequence[ValidatedMemoryRow]:
        """BLOCKED — see module docstring / contract RISK 2 & 4. Every field EXCEPT
        `distinct_scoring_principals` exists on `memory_item`, but that field is the D-021
        K-floor sourced from the scored Q-update ledger (`memory_q_update`), which migration
        0006 has not yet created. Retirement is a memory-destruction edge; sourcing its
        safety floor from nothing is the catastrophic case, so this refuses."""
        raise NotImplementedError(
            f"PromotionRepo.select_validated_for_retirement (project {project_id}) is blocked: "
            "distinct_scoring_principals (the D-021 K-floor) requires the scored Q-update ledger "
            "memory_q_update, created by migration 0006 (ScorerRepoPort, contract RISK 4), which "
            "does not exist in migrations 0001-0005. The persist + insert_review_item write "
            "surface is implemented; this select awaits 0006."
        )
