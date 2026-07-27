"""Structured incremental deltas — the consolidator's data model (PLAN.md §7 Phase 2 /
§8 improvement 4).

ACE (arXiv:2510.04618, ICLR 2026) names brevity bias and context collapse as the failure
modes of exactly the nightly-merge consolidation loop: a consolidator that rewrites an
item wholesale progressively strips detail until the memory says something shorter and
less true than what it replaced, and nothing detects it because each individual rewrite
looked reasonable in isolation. The defence this module implements is structural, not a
policy: a consolidated memory's content is represented as an `ElementSet` — an ordered
set of independently-named `Element`s — and the ONLY way to produce a new `ElementSet`
from an old one is `apply_delta`/`apply_deltas`, each of which names exactly one element
by its stable `name` and does exactly one of ADD / REMOVE / AMEND to it. There is no
function anywhere in this module (or in `workers.consolidator`) that takes a whole new
content string and replaces `.elements` with something derived from it — that structural
absence is what a "no wholesale rewrite" test can assert on rather than trust.

Every applied delta is meant to be recorded (`DeltaRecord`) by the caller (see
`workers.consolidator.Consolidator`), and `reconstruct()` replays a recorded log back into
an `ElementSet` — including a "state before sweep N" reconstruction — which is what makes
the pre-consolidation state reconstructible without a separate snapshot table this chunk
does not own.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from tracebed.domain.ids import MemoryId

__all__ = [
    "Delta",
    "DeltaOp",
    "DeltaRecord",
    "Element",
    "ElementSet",
    "apply_delta",
    "apply_deltas",
    "reconstruct",
]


class DeltaOp(StrEnum):
    """The closed vocabulary of structural operations a consolidation sweep may
    emit. Local to this module — no other chunk needs this enum, so it does
    not belong in `domain/enums.py` (§3.2's ownership rule is about symbols
    that cross chunk boundaries; this one does not)."""

    ADD = "add"
    REMOVE = "remove"
    AMEND = "amend"


@dataclass(frozen=True, slots=True)
class Element:
    """One independently-addressable, named unit of a consolidated memory's
    content. `name` is a stable identifier across sweeps (e.g. a fact's
    slug) — it is what lets a later sweep say "amend THIS one" instead of
    "here is the new whole text", and what lets a regression harness check
    "is this specific fact still here" rather than "does the text still look
    similar"."""

    name: str
    text: str

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("Element.name cannot be empty or whitespace-only")
        if not self.text.strip():
            raise ValueError("Element.text cannot be empty or whitespace-only")


@dataclass(frozen=True, slots=True)
class Delta:
    """One structural operation against one named element. `text` is required
    for ADD/AMEND (there is no such thing as adding or amending an element to
    nothing — that is what REMOVE is for) and forbidden for REMOVE (a REMOVE
    that also carried replacement text would be an AMEND wearing a different
    name, which defeats the point of a closed, inspectable vocabulary)."""

    op: DeltaOp
    name: str
    text: str | None = None

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("Delta.name cannot be empty or whitespace-only")
        if self.op is DeltaOp.REMOVE:
            if self.text is not None:
                raise ValueError("a REMOVE delta must not carry text")
        elif not self.text or not self.text.strip():
            raise ValueError(f"a {self.op.value} delta requires non-empty text")


@dataclass(frozen=True, slots=True)
class ElementSet:
    """A structured representation of one memory's content: an ordered tuple
    of uniquely-named `Element`s. `render()` is the ONLY place this module
    turns elements back into a flat string — everything upstream of it
    (consolidation, delta logging, reconstruction) operates on named elements,
    never on that flat string.

    This dataclass exposes exactly two public methods, `by_name` and
    `render`; neither can rewrite `.elements` — the only functions in this
    module that produce a new `ElementSet` are `apply_delta`/`apply_deltas`,
    which is what a structural "no wholesale rewrite" test asserts on.
    """

    elements: tuple[Element, ...] = ()

    def __post_init__(self) -> None:
        names = [e.name for e in self.elements]
        if len(names) != len(set(names)):
            raise ValueError("ElementSet cannot carry two elements with the same name")

    def by_name(self) -> dict[str, Element]:
        return {e.name: e for e in self.elements}

    def render(self) -> str:
        """Deterministic join of element texts in stored order."""
        return "\n".join(e.text for e in self.elements)


def _required_text(delta: Delta) -> str:
    """Narrows `Delta.text` for ADD/AMEND. `Delta.__post_init__` already
    guarantees it, so this raise is unreachable through the constructor — but a
    bare `assert` would be, and `python -O` strips asserts, which would turn the
    guarantee into an `AttributeError` inside `Element` on a nightly worker
    path (same reasoning as `core.scans.tier_a_template`'s exhaustiveness
    check, which is a raise for exactly this reason)."""
    if delta.text is None:
        raise ValueError(f"a {delta.op.value} delta requires text")
    return delta.text


def apply_delta(state: ElementSet, delta: Delta) -> ElementSet:
    """The ONLY function that turns one `Delta` into a new `ElementSet`.

    Each op's precondition is enforced, never silently downgraded to a
    different op: ADD requires the name be ABSENT, AMEND and REMOVE require
    it be PRESENT. Letting an AMEND silently behave like an ADD (or vice
    versa) would hide exactly the failure a consolidation regression harness
    exists to catch — "nothing changed" would become indistinguishable from
    "something vanished and got silently re-added under the same name".
    """
    existing = state.by_name()
    if delta.op is DeltaOp.ADD:
        if delta.name in existing:
            raise ValueError(f"cannot ADD {delta.name!r}: an element with that name already exists")
        new_elements = (*state.elements, Element(name=delta.name, text=_required_text(delta)))
    elif delta.op is DeltaOp.AMEND:
        if delta.name not in existing:
            raise ValueError(f"cannot AMEND {delta.name!r}: no element with that name exists")
        amended_text = _required_text(delta)
        new_elements = tuple(
            Element(name=e.name, text=amended_text) if e.name == delta.name else e
            for e in state.elements
        )
    elif delta.op is DeltaOp.REMOVE:
        if delta.name not in existing:
            raise ValueError(f"cannot REMOVE {delta.name!r}: no element with that name exists")
        new_elements = tuple(e for e in state.elements if e.name != delta.name)
    else:  # pragma: no cover - exhaustive over the closed DeltaOp vocabulary
        raise ValueError(f"unknown delta op: {delta.op!r}")
    return ElementSet(elements=new_elements)


def apply_deltas(state: ElementSet, deltas: Sequence[Delta]) -> ElementSet:
    """Applies `deltas` in order, one `apply_delta` call at a time. This is
    what "applying deltas in order reproduces the final state" means
    concretely: replaying a memory's full delta log through this function
    from an empty `ElementSet` must equal whatever `.after` the last sweep
    produced."""
    for delta in deltas:
        state = apply_delta(state, delta)
    return state


@dataclass(frozen=True, slots=True)
class DeltaRecord:
    """One persisted log entry: which memory, which sweep, which delta, when.
    A caller (`workers.consolidator.Consolidator`) stamps `applied_at` from an
    injected `Clock` — never from a bare wall-clock read (hard rule 3) —
    which is what makes a sequence of these replayable inside a FakeClock-
    driven soak."""

    memory_id: MemoryId
    sweep: int
    delta: Delta
    applied_at: datetime

    def __post_init__(self) -> None:
        if self.sweep < 0:
            raise ValueError("sweep must be >= 0")


def reconstruct(records: Sequence[DeltaRecord], *, upto_sweep: int | None = None) -> ElementSet:
    """Replays an ordered delta log from an empty `ElementSet`.

    `upto_sweep`, when given, stops BEFORE that sweep's own deltas are
    applied — i.e. `upto_sweep=N` reconstructs the state exactly as it stood
    immediately before sweep N ran. This is what makes "the pre-consolidation
    state is reconstructible" true from the recorded log alone, with no
    separate snapshot table (this chunk owns no such table — see
    `workers.novelty`'s contract_gap note on the parallel `Repo` gap).

    `records` must already be in application order (sweep, then order within
    a sweep) — this function does not sort them; sorting silently would risk
    hiding an out-of-order log rather than surfacing it as a caller bug.
    """
    state = ElementSet()
    for record in records:
        if upto_sweep is not None and record.sweep >= upto_sweep:
            break
        state = apply_delta(state, record.delta)
    return state
