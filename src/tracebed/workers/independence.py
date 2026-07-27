"""The computable independence definition — PLAN.md invariant 7; D-020.

`domain.state_machine` already carries the actual clique computation
(`ShadowConfirmation`, `independent_confirmations`, `SHADOW_CONFIRM_MIN_INDEPENDENT`) as a
pure function of a sequence it is handed — deliberately, since the guard proving invariant 7
must be testable with zero I/O. This module is the missing other half: turning `run_id`s a
quarantined memory claims as corroborating evidence into the `ShadowConfirmation` tuples that
function actually consumes, by resolving each one against `trace_index`.

D-020's whole point is that "independent" cannot be computed from `run_id` alone — it needs
the AUTHENTICATED `submitter_principal` and the `input_signature_hash`, both stamped on
`trace_index` at ingest time, never from a caller's payload (PHASE0-CONTRACT.md §3.5 / C-05).
This module never accepts a principal or signature as a bare argument for exactly that
reason: the only way to get one is `TracePrincipalLookupPort.lookup`, which a real
implementation backs with a `trace_index` row, so a run that never produced one contributes
nothing rather than a guessed identity.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from tracebed.domain.errors import TracebedError
from tracebed.domain.ids import PrincipalId, ProjectId, RunId
from tracebed.domain.state_machine import (
    MAX_CONFIRMATIONS_CONSIDERED,
    SHADOW_CONFIRM_MIN_INDEPENDENT,
    ShadowConfirmation,
    independent_confirmations,
)

__all__ = [
    "MAX_CONFIRMATIONS_CONSIDERED",
    "SHADOW_CONFIRM_MIN_INDEPENDENT",
    "ConfirmingRun",
    "ShadowConfirmation",
    "TracePrincipalLookupPort",
    "build_confirmations",
    "count_independent",
    "independent_confirmations",
    "independent_of",
]

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ConfirmingRun:
    """One `trace_index` row's identity-bearing columns (PHASE0-CONTRACT.md §3.5).

    Exactly the three fields `domain.state_machine.ShadowConfirmation` needs — kept as its
    own type (rather than constructing `ShadowConfirmation` directly inside the port) so a
    `TracePrincipalLookupPort` implementation depends only on this module, never on
    `domain.state_machine`'s internals.
    """

    run_id: RunId
    principal_id: PrincipalId
    input_signature_hash: bytes


@runtime_checkable
class TracePrincipalLookupPort(Protocol):
    def lookup(self, project_id: ProjectId, run_id: RunId) -> ConfirmingRun | None:
        """The authenticated principal and input-signature hash `trace_index` recorded for
        this run, or `None` if no such row exists.

        A real implementation reads `trace_index.submitter_principal` and
        `trace_index.input_signature_hash` — columns set at authenticated ingest, never
        caller-asserted (D-020) — and must never fall back to a payload-supplied identity.
        `None` is not an error: a `run_id` a memory's provenance names but that never
        produced a trace_index row (a proposal referencing a run still mid-flight, a replay
        artifact, ...) simply confirms nothing, which is the fail-closed direction invariant
        7 requires.
        """
        ...


def build_confirmations(
    project_id: ProjectId,
    run_ids: Sequence[RunId],
    lookup: TracePrincipalLookupPort,
) -> tuple[ShadowConfirmation, ...]:
    """Resolve a quarantined memory's claimed corroborating runs into `ShadowConfirmation`s.

    Three things this refuses to do silently, each a way independence would otherwise be
    over-reported:

    1. A `run_id` with no discoverable `trace_index` row contributes nothing (`lookup`
       returned `None`) — it is not manufactured as "independent by default".
    2. A repeated `run_id` is looked up once; `domain.state_machine`'s own compatibility
       graph would already treat two confirmations sharing a `run_id` as non-independent,
       but doing the lookup twice for the same run is wasted I/O for no additional signal.
    3. Only the first `MAX_CONFIRMATIONS_CONSIDERED` distinct run ids are resolved at all —
       the same bound `domain.state_machine.independent_confirmations` applies to its input,
       reused here so a memory that accumulated an unbounded confirmation list cannot turn
       this into an unbounded number of lookups either. Slicing before resolving, rather
       than after, is what keeps the two bounds in agreement.
    4. A row `domain.state_machine.ShadowConfirmation` refuses to construct (today: an
       `input_signature_hash` that is not `SIG_HASH_LEN` bytes) contributes nothing instead
       of raising. That type's own `__post_init__` documents why the check exists — "a
       malformed row would crash the shadow validator instead of merely failing to
       corroborate (invariant 7: deficient evidence refuses, it does not explode)" — but the
       `ValueError` it raises is not a `TracebedError`, so letting it escape here converts
       one malformed `trace_index` row into a hard stop for EVERY quarantined memory in the
       project on every sweep. Dropping is also the only safe direction: one fewer
       confirmation can refuse a promotion, it can never grant one.
    """
    deduped: list[RunId] = []
    seen: set[RunId] = set()
    for run_id in run_ids:
        if run_id in seen:
            continue
        seen.add(run_id)
        deduped.append(run_id)
        if len(deduped) >= MAX_CONFIRMATIONS_CONSIDERED:
            break

    confirmations: list[ShadowConfirmation] = []
    for run_id in deduped:
        found = lookup.lookup(project_id, run_id)
        if found is None:
            continue
        if found.run_id != run_id:
            # A lookup returning a different run's identity than the one asked for is not a
            # "no data" case — it is a broken port, and silently accepting it would let a
            # confirmation be attributed to the wrong run (and, transitively, credited
            # against the wrong memory's corroboration count).
            raise TracebedError(
                f"TracePrincipalLookupPort.lookup({project_id!r}, {run_id!r}) returned a "
                f"ConfirmingRun for {found.run_id!r} instead"
            )
        try:
            confirmation = ShadowConfirmation(
                run_id=found.run_id,
                principal_id=found.principal_id,
                input_signature_hash=found.input_signature_hash,
            )
        except ValueError:
            # Caught rather than length-checked here so the definition of "a usable
            # confirmation" stays in exactly one place (the domain type); a future field
            # validation added there must not silently start crashing this sweep either.
            logger.warning(
                "shadow confirmation for run %s in project %s is unusable "
                "(malformed trace_index identity columns); it corroborates nothing",
                run_id,
                project_id,
            )
            continue
        confirmations.append(confirmation)
    return tuple(confirmations)


def independent_of(a: ShadowConfirmation, b: ShadowConfirmation) -> bool:
    """Are these two observations independent of each other under D-020?

    Asked through `independent_confirmations` on the pair rather than by re-deriving
    "distinct run AND distinct principal AND distinct input-signature cluster", so there
    stays exactly ONE definition of independence in the codebase. A two-node compatibility
    graph has a clique of size 2 iff its single edge exists, which is precisely the pairwise
    predicate — no separate implementation to drift from the guard's.
    """
    return independent_confirmations((a, b), at_least=2) >= 2


def count_independent(
    project_id: ProjectId,
    run_ids: Sequence[RunId],
    lookup: TracePrincipalLookupPort,
    *,
    at_least: int | None = None,
) -> int:
    """`build_confirmations` followed by `domain.state_machine.independent_confirmations`.

    A convenience composition, not a second implementation: the clique search stays in
    exactly one place. `at_least` is passed straight through so a caller that only needs to
    know "does this clear N" gets the same early-exit performance `independent_confirmations`
    already offers.
    """
    confirmations = build_confirmations(project_id, run_ids, lookup)
    return independent_confirmations(confirmations, at_least=at_least)
