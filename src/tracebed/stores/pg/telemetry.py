"""Telemetry facade (PHASE-0 Task 16 / PHASE0-CONTRACT.md §5.4).

Thin, intentionally dumb wrapper over `Repo.insert_retrieval_event` /
`Repo.insert_injection_rows`. It exists as its own module -- rather than
callers reaching for `Repo` directly -- because it is the one symbol named in
`adapters.ports.TelemetryPort`: `hotpath/` (Phase 1) depends on the Protocol,
not on the concrete repository, so retrieval code stays swappable and
offline-testable against a fake.

The one rule that matters here (PLAN.md §2 invariant 2, restated in the task
description): EVERY retrieval writes a `retrieval_event` row, including the
ones that returned nothing. `outcome_code="empty_result"` and
`outcome_code="timeout_prefix_only"` are both "a row got written"; the
difference between "the system correctly found nothing" (abstention) and
"the system failed to respond in time" (timeout) lives entirely in which
`OutcomeCode` the caller passes, never in whether a row exists at all.
Skipping the write on an empty result -- the tempting "nothing to record"
shortcut -- would make Phase 3's lift computation blind to exactly the
failure mode it exists to catch.
"""

from __future__ import annotations

from collections.abc import Sequence

from tracebed.domain.clock import Clock
from tracebed.domain.enums import Arm, OutcomeCode
from tracebed.domain.ids import ProjectId, RunId
from tracebed.stores.pg.repo import Repo
from tracebed.stores.pg.rows import InjectionRow, RetrievalEventInsert

__all__ = ["Telemetry"]


class Telemetry:
    """Satisfies `adapters.ports.TelemetryPort` structurally.

    Writers only (§14 telemetry DO-NOT list): every method takes the caller's
    `project_id` and forwards it unmodified to `Repo`, which scopes the write
    through the §5.0 GUC. Nothing here reads, and nothing aggregates.
    """

    def __init__(self, repo: Repo, clock: Clock) -> None:
        self._repo = repo
        # `clock` is part of the contract §5.4 constructor signature (every
        # time-dependent component takes one), but `Repo.insert_retrieval_event`
        # and `Repo.insert_injection_rows` already stamp `created_at` /
        # `injected_at` from the Repo's own injected clock -- this facade never
        # needs `datetime.now()` and would violate the "no bare timestamps"
        # rule (contract Conventions) if it stamped a second, independently
        # sourced instant onto the same row. Held for signature parity and for
        # any future telemetry field that is computed here rather than in Repo.
        self._clock = clock

    def record_retrieval(
        self,
        project_id: ProjectId,
        run_id: RunId,
        *,
        outcome_code: OutcomeCode,
        latency_ms: int,
        embed_latency_ms: int | None,
        candidates_considered: int,
        top_score: float | None,
        arm: Arm,
    ) -> None:
        """Write one `retrieval_event` row. Called on every `/v1/retrieve`, no exceptions --
        including calls where nothing was found or the store degraded to prefix-only."""
        self._repo.insert_retrieval_event(
            project_id,
            RetrievalEventInsert(
                run_id=run_id,
                outcome_code=outcome_code,
                latency_ms=latency_ms,
                embed_latency_ms=embed_latency_ms,
                candidates_considered=candidates_considered,
                top_score=top_score,
                arm=arm,
            ),
        )

    def record_injections(
        self, project_id: ProjectId, run_id: RunId, rows: Sequence[InjectionRow]
    ) -> None:
        """Write the `injection_log` rows for one retrieval. A call with an empty `rows`
        sequence is a legitimate no-op (nothing was injected) -- `Repo.insert_injection_rows`
        already short-circuits on empty input rather than issuing a zero-row statement."""
        self._repo.insert_injection_rows(project_id, run_id, rows)
