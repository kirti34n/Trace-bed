"""The incremental-delta consolidator (PLAN.md §7 Phase 2 / §8 improvement 4).

PLAN.md §8: "the incremental-delta consolidator itself is not [cuttable]; only the
[regression] harness is." This module — `Consolidator` — is that non-cuttable core;
`harness/consolidation_regression.py` is the separate, explicitly-cuttable proof that it
holds up across repeated sweeps.

`Consolidator.consolidate()` is the nightly-merge-loop step: given a memory's current
structured representation (`workers.deltas.ElementSet`) and a fresh set of observed
`Element`s for this sweep, it emits exactly one `Delta` per element that is new (ADD) or
whose text changed (AMEND) — nothing else. It deliberately never infers a REMOVE on its
own: `retract()` is the only path that produces one, and it requires the caller to name
the element explicitly. This is the direct fix for ACE's brevity-bias/context-collapse
finding (arXiv:2510.04618, ICLR 2026) — a consolidator that is willing to decide, on its
own, that an element absent from this sweep's `incoming` must mean "no longer true" would
silently drop any fact whose upstream source happened not to re-surface it this sweep
(a partial extractor run, a reordered batch, ...), and nothing would ever detect it,
because each individual sweep looks reasonable in isolation. Every emitted delta is
recorded (`workers.deltas.DeltaRecord`), so the pre-consolidation state is always
reconstructible via `workers.deltas.reconstruct`.

The honest limit of that guarantee, stated because a test asserting "no wholesale
rewrite" would otherwise read as stronger than it is: nothing here stops a caller from
handing `consolidate()` an `incoming` that re-states EVERY element with shorter text,
which emits one AMEND per element and is a whole-content rewrite wearing a delta costume.
What the structure buys is not prevention, it is that such a sweep is inspectable
(N named AMENDs, each naming what it changed) and reversible (`workers.deltas.reconstruct`
with `upto_sweep=N` returns the exact pre-sweep state) instead of being one opaque
content write. Prevention needs a bound on how much of a memory one sweep may amend, and
PLAN.md §6 defines no such field — that is a contract_gap, not a licence to pick a
fraction here (hard rule 4).

LLM-free: there is no `adapters.llm`/`LLMProviderPort` import anywhere in this module.
Deciding whether two *different* names denote the same underlying fact (semantic
deduplication across elements) is exactly the judgement call this module refuses to make
unilaterally — that is Phase 3 territory (a judge, or an operator via the dashboard's
`operator_edit`, D-032), reachable here only through the same named-element vocabulary
(`retract`), never invented as a heuristic.

Takes an injectable `Clock` (hard rule 3: no bare wall-clock read outside `SystemClock`) —
`DeltaRecord.applied_at` is stamped from it, which is what lets the regression harness run
its full multi-sweep soak on a `FakeClock` with zero wall-clock dependency.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from tracebed.domain.clock import Clock
from tracebed.domain.ids import MemoryId
from tracebed.workers.deltas import Delta, DeltaOp, DeltaRecord, Element, ElementSet, apply_deltas

__all__ = ["ConsolidationOutcome", "Consolidator"]


@dataclass(frozen=True, slots=True)
class ConsolidationOutcome:
    """One `consolidate()`/`retract()` call's full result: the state before and
    after, the deltas that produced the difference, and their recorded log
    entries. `deltas`/`records` may both be empty — a sweep that changes
    nothing emits nothing, which is itself the "no silent rewrite" guarantee
    made observable (a naive rewrite-in-place implementation would instead
    always produce SOME write, even when nothing changed)."""

    memory_id: MemoryId
    sweep: int
    before: ElementSet
    after: ElementSet
    deltas: tuple[Delta, ...]
    records: tuple[DeltaRecord, ...]


class Consolidator:
    """One nightly-merge-loop step over one memory's structured element set."""

    def __init__(self, clock: Clock) -> None:
        self._clock = clock

    def consolidate(
        self,
        memory_id: MemoryId,
        state: ElementSet,
        incoming: Sequence[Element],
        *,
        sweep: int,
    ) -> ConsolidationOutcome:
        """Diffs `incoming` against `state` by name: a name not yet present
        becomes an ADD; a name present with different text becomes an AMEND;
        a name present with identical text produces no delta at all. Never
        emits a REMOVE — see the module docstring for why that omission is
        deliberate, not an oversight.

        `incoming` must name each element at most once. Left unchecked this
        splits into two different silent behaviours for the same upstream bug:
        a repeated name absent from `state` produces two ADD deltas and blows
        up inside `apply_deltas` with a message about the element already
        existing (it did not, a moment ago), while a repeated name present in
        `state` produces two AMEND deltas in one sweep and quietly keeps the
        last one — an unannounced last-writer-wins over a memory's content,
        which is the shape of write this module exists to make impossible.
        """
        names = [element.name for element in incoming]
        if len(names) != len(set(names)):
            duplicates = sorted({name for name in names if names.count(name) > 1})
            raise ValueError(
                f"consolidate: incoming names each element at most once; duplicated: {duplicates}"
            )

        existing = state.by_name()
        deltas: list[Delta] = []
        for element in incoming:
            current = existing.get(element.name)
            if current is None:
                deltas.append(Delta(op=DeltaOp.ADD, name=element.name, text=element.text))
            elif current.text != element.text:
                deltas.append(Delta(op=DeltaOp.AMEND, name=element.name, text=element.text))
            # identical name + identical text: nothing changed, nothing recorded.

        after = apply_deltas(state, deltas)
        applied_at = self._clock.now()
        records = tuple(
            DeltaRecord(memory_id=memory_id, sweep=sweep, delta=delta, applied_at=applied_at)
            for delta in deltas
        )
        return ConsolidationOutcome(
            memory_id=memory_id,
            sweep=sweep,
            before=state,
            after=after,
            deltas=tuple(deltas),
            records=records,
        )

    def retract(
        self,
        memory_id: MemoryId,
        state: ElementSet,
        name: str,
        *,
        sweep: int,
    ) -> ConsolidationOutcome:
        """Explicit, caller-driven removal of one named element — the ONE
        delta kind `consolidate()` never emits on its own (module docstring).
        Raises `KeyError` if `name` is not present: retracting an element
        that never existed is not a retraction, and silently succeeding would
        make a caller's typo indistinguishable from "already handled".
        """
        if name not in state.by_name():
            raise KeyError(f"cannot retract {name!r}: no element with that name exists")
        delta = Delta(op=DeltaOp.REMOVE, name=name)
        after = apply_deltas(state, (delta,))
        applied_at = self._clock.now()
        record = DeltaRecord(memory_id=memory_id, sweep=sweep, delta=delta, applied_at=applied_at)
        return ConsolidationOutcome(
            memory_id=memory_id,
            sweep=sweep,
            before=state,
            after=after,
            deltas=(delta,),
            records=(record,),
        )
