"""scoring_epoch management (PLAN.md §5's `scoring_epoch` table; invariant 7).

Every Q update and every shadow confirmation is supposed to record which
judge configuration produced it, and comparing two such values across a judge
change is rejected rather than silently allowed: a judge model swap, a
sampling-parameter change, or even a code edit to the judge's own prompt
invalidates the meaning of the `c` factor invariant 8's formula depends on,
the same way an embedding-model swap invalidates a stored vector (D-007's
same argument, one layer up).

`resolve_epoch` is what makes this automatic. Nobody increments an epoch
counter by hand: the epoch's identity IS the judge pin (model id, model
version, sampling params, prompt hash), so the moment any one of those four
changes, the next `resolve_epoch` call sees a pin that does not match the
stored current epoch and starts a new one on its own.

ONE STORE, SEVERAL PINNED WORKERS. `scoring_epoch` is a single global table
and D-008 pins three workers to it — the contribution judge, the shadow
validator and the distiller — each with its own prompt and therefore its own
pin. `current_epoch()` returns the single most-recently-started row, so those
workers alternate past each other: judge resolves, distiller resolves and sees
the judge's pin, mints; judge resolves again and sees the distiller's pin,
mints again. Left alone that is an epoch minted per call forever, and two Q
updates a minute apart under an unchanged judge would refuse to be compared.
The fix is a contract on the store, not a branch here: `start_epoch` is
insert-or-return-existing FOR THAT PIN (see its docstring), so alternating
workers settle onto one stable epoch id each and a pin that has been seen
before keeps its original id. `resolve_epoch` verifies the pin it gets back,
so a store that ignores the contract fails loudly instead of silently
stamping artifacts with someone else's epoch.

CONTRACT GAP (reported, not worked around): this chunk owns `workers/scorer.py`,
`workers/contribution_judge.py`, and `workers/epochs.py` — not
`stores/pg/repo.py` and not `migrations/`. `scoring_epoch` is a real,
migrated table (`migrations/0001_registries.sql`) but `Repo` has no accessor
for it yet (no `get_current_scoring_epoch`, no `insert_scoring_epoch`), so
`EpochStorePort` is declared here, beside its consumer, per the precedent
`adapters/ports.py` itself documents (C-18: "`SubjectKeyStore` and
`ConfigStorePort` stay defined beside their consumers instead of being
centralised" — `stores.pg` is not this chunk's to extend, either). A future
`Repo` implementation satisfies this Protocol structurally, exactly like
`ConfigStorePort` does today. Its `start_epoch` needs a unique index over the
pin columns to implement the contract above atomically; the migration has no
such index today, which is part of the same gap.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Protocol, runtime_checkable

from tracebed.domain.clock import Clock
from tracebed.domain.errors import CrossEpochComparison, TracebedError

__all__ = [
    "EpochStamped",
    "EpochStorePort",
    "EpochStoreViolation",
    "JudgePin",
    "ScoringEpoch",
    "assert_same_epoch",
    "resolve_epoch",
]


class EpochStoreViolation(TracebedError):
    """An `EpochStorePort` returned an epoch that does not carry the pin it
    was asked for.

    Every artifact stamped with that epoch id would claim to have been
    produced under a judge configuration that never produced it, and nothing
    downstream could tell — `assert_same_epoch` compares ids, so a wrong id
    that is *consistently* wrong passes every check while meaning nothing.
    """


def _frozen_params(params: Mapping[str, object]) -> Mapping[str, object]:
    """A snapshot of `sampling_params` the caller can no longer reach.

    `JudgePin` is `frozen=True`, but a `Mapping` field makes that a half
    truth: the caller keeps a reference to the dict it passed in, and mutating
    it afterwards retroactively changes the identity of an epoch that has
    already stamped artifacts. Copying into a read-only view keeps the pin's
    equality semantics intact (`MappingProxyType({'a': 1}) == {'a': 1}`) while
    making the frozen claim true.
    """
    return MappingProxyType(dict(params))


@dataclass(frozen=True, slots=True)
class JudgePin:
    """The four fields that together identify one scoring epoch (D-008).

    Equality here IS the epoch-sameness test `resolve_epoch` runs — there is
    deliberately no fifth "epoch label" a human could forget to update: any
    difference in any field below is, by construction, a different epoch.
    """

    judge_model_id: str
    judge_model_version: str
    sampling_params: Mapping[str, object]
    prompt_hash: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "sampling_params", _frozen_params(self.sampling_params))


@dataclass(frozen=True, slots=True)
class ScoringEpoch:
    """One row of `scoring_epoch` (PLAN.md §5). `epoch_id` is assigned by the
    store (`GENERATED ALWAYS AS IDENTITY` in the migration) — never minted
    here, since this module has no connection to hand out identity values
    from.
    """

    epoch_id: int
    judge_model_id: str
    judge_model_version: str
    sampling_params: Mapping[str, object]
    prompt_hash: str
    started_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "sampling_params", _frozen_params(self.sampling_params))
        # `scoring_epoch.started_at` is `timestamptz NOT NULL`
        # (migrations/0001_registries.sql), and this row is what dates every
        # stamped artifact for an audit ("which judge was in force when this Q
        # moved"). A naive value there is the D-043 hazard verbatim: Postgres
        # reinterprets it in the session TimeZone, and two epochs minted hours
        # apart can end up ordered wrongly relative to the updates they
        # stamped. Refused on the same terms `workers.scorer.ScoringEvent`
        # refuses a naive `arrived_at`.
        if self.started_at.tzinfo is None or self.started_at.utcoffset() is None:
            raise EpochStoreViolation(
                f"scoring_epoch {self.epoch_id} has a timezone-naive started_at; "
                "the column it comes from is timestamptz"
            )

    def pin(self) -> JudgePin:
        return JudgePin(
            judge_model_id=self.judge_model_id,
            judge_model_version=self.judge_model_version,
            sampling_params=self.sampling_params,
            prompt_hash=self.prompt_hash,
        )


@runtime_checkable
class EpochStorePort(Protocol):
    """What `resolve_epoch` needs from storage (module docstring's contract_gap)."""

    def current_epoch(self) -> ScoringEpoch | None:
        """The most recently started epoch, or `None` before the first ever
        judge call in this deployment's history. A fast path only — it is not
        pin-scoped, so `resolve_epoch` still has to check the pin it gets."""
        ...

    def start_epoch(self, pin: JudgePin, started_at: datetime) -> ScoringEpoch:
        """The epoch for `pin`: the EXISTING row if this deployment has ever
        started one for exactly this pin, otherwise a newly persisted row.

        Insert-or-return-existing, not insert-unconditionally, for the reason
        the module docstring gives: several pinned workers share this one
        table and alternate through it, and a store that mints on every call
        would mint an epoch per call and make every artifact incomparable to
        the one before it. This also makes the operation idempotent under a
        retry and under two workers racing on the same pin — both are the same
        requirement, and both are satisfied by an upsert on the pin columns.

        Never mutates a prior epoch row and never reuses an `epoch_id` for a
        different pin — old epochs stay queryable so anything already stamped
        with them remains attributable.
        """
        ...


def resolve_epoch(pin: JudgePin, *, store: EpochStorePort, clock: Clock) -> ScoringEpoch:
    """The current epoch for `pin`, starting (or re-finding) one automatically
    if the store's current epoch has a different pin, or there is no current
    epoch yet.

    This is the whole mechanism behind "changing the judge model, its
    version, its sampling params or its prompt hash starts a new epoch —
    automatically, from the pin, not by someone remembering to increment a
    number": there is no branch here that compares anything BUT the pin.
    """
    current = store.current_epoch()
    if current is not None and current.pin() == pin:
        return current
    started = store.start_epoch(pin, clock.now())
    if started.pin() != pin:
        raise EpochStoreViolation(
            f"store returned epoch {started.epoch_id} whose pin does not match the "
            f"pin it was asked for"
        )
    return started


@runtime_checkable
class EpochStamped(Protocol):
    """Structural marker for "this value says which scoring_epoch produced
    it" — `ScoringEpoch` itself and `contribution_judge.ContributionVerdict`
    both satisfy this with no inheritance relationship between them."""

    @property
    def epoch_id(self) -> int: ...


def assert_same_epoch(a: EpochStamped, b: EpochStamped) -> None:
    """Refuses to let two epoch-stamped artifacts be treated as comparable.

    Invariant 7: "CROSS-EPOCH COMPARISON IS REJECTED, not silently allowed."
    A judge swap changes what `c` means; a Q trajectory, or a single Q update
    built from a contribution verdict judged under a different epoch than the
    one the scorer itself resolved for this tick, is comparing two different
    rulers as if they were one. There is no coercion path here — the caller
    either has two values from the same epoch or gets an exception, never a
    best-effort answer.
    """
    if a.epoch_id != b.epoch_id:
        raise CrossEpochComparison(
            f"cannot compare artifacts from scoring_epoch {a.epoch_id} and {b.epoch_id}"
        )
