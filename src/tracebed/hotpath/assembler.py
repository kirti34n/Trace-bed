"""Budget packing and dedup: candidates -> an ordered, placed slot list (PLAN.md §6 `budget.*`).

CONTRACT GAP (reported, not silently invented): unlike Phase 0, this phase
has no `PHASE1-CONTRACT.md` pinning the boundary between the retriever
(which decides *which* memories are relevant and computes their calibrated
score, `hotpath.calibration.calibrated_score`) and this module (which decides
*how many of them fit* and in what order). `Candidate` below is this chunk's
own proposal for that shape, built only from types the retriever/abstention
chunk already established (`hotpath.calibration.CalibratedSignals` ->
`calibrated_score` gives `Candidate.score`) plus Phase 0's frozen domain
types. If the retriever chunk lands a different shape, reconciling the two
is a merge-time task, not a silent divergence — flagged here so the next
reader does not mistake this for a binding cross-chunk contract.

PLACEMENT IS LOAD-BEARING (D-016): the static prefix (cacheable — built once
per agent-type and unchanged run to run) is placed FIRST; every dynamic slot
(fact/exemplar/pitfall/candidate_note/jit_lesson — different on every call)
is placed LAST, after all cacheable content. A prompt-cache provider
invalidates a changed block *and everything textually after it*; interleaving
dynamic content between cached prefix and the rest of the prompt would
invalidate the entire cached prefix on every single call, which is precisely
the audit finding D-016 exists to correct. `assemble()` enforces this by
construction: the returned slot tuple always has every `STATIC_PREFIX` entry
before every dynamic-slot entry, regardless of candidate input order.

Budget shape (PLAN.md §6, `domain.config.BudgetConfig` — every number below
is read from `EffectiveConfig`, never a literal here, per hard rule 4):

  - `total_tokens` (1200) = `static_prefix` (700) + `dynamic` (500) under the
    shipped defaults, and is enforced as the OUTER bound whether or not the
    parts still sum to it after a project/agent-type override.
  - `static_prefix` splits into `static_prefix_prefs` (200, `MemType.PREFERENCE`
    candidates) and `static_prefix_lessons` (500, everything else in the
    STATIC_PREFIX slot) — both drawn from the same 700-token pool, so lessons
    only get what prefs did not spend, capped at their own 500.
  - `dynamic` (500) is a SHARED pool across all five dynamic slots, each ALSO
    capped individually by `slot_caps` (fact 250 / exemplar 150 / pitfall 100
    / candidate_note 100 / jit_lesson 150 — these sum to 750, deliberately
    more than the 500 shared pool, so the shared-pool cap is what actually
    binds in the mixed case). Slots are spent in `templates.SLOT_ORDER`.
  - Tier A `candidate` rows are the `CANDIDATE_NOTE` slot specifically
    (`domain.state_machine.RETRIEVABLE_STATUSES`' own comment: "candidate:
    Tier A only, cap 1/run, labeled lower-trust" — `templates.SECTION_LABELS`
    carries the label); `tier_a.candidate_cap_per_run` additionally caps the
    *count* of candidate_note entries, independent of and in addition to
    that slot's token cap.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from math import isfinite

from tracebed.domain.config import EffectiveConfig
from tracebed.domain.enums import MemType, Slot
from tracebed.domain.events import ContextSlot
from tracebed.domain.ids import MemoryId
from tracebed.hotpath.templates import SLOT_ORDER

__all__ = ["AssembledContext", "Candidate", "assemble"]

_DYNAMIC_SLOTS: tuple[Slot, ...] = tuple(s for s in SLOT_ORDER if s is not Slot.STATIC_PREFIX)


@dataclass(frozen=True, slots=True)
class Candidate:
    """One retrieval candidate available for a context slot, before packing.

    `mem_type` decides the `STATIC_PREFIX` prefs/lessons split (only
    consulted for that slot); it is otherwise inert. `score` is the
    retriever's calibrated composite (`hotpath.calibration.calibrated_score`)
    — never an RRF rank (D-015), because a rank cannot be compared across
    candidates for the "keep the highest-scoring copy" dedup rule below.
    `dedup_key` identifies content, not identity: two different `memory_id`s
    with the same `dedup_key` (e.g. a Tier A candidate note that duplicates
    an already-validated fact's content) collapse to one entry, because
    `dedup_key` — not `memory_id` — is what "dedup across slots" packs on.
    `tokens` is a precomputed token count (the retriever/tokenizer's job,
    not this module's); `text` is the raw, unescaped content — escaping
    happens once, in `templates.render_entry`, never here.
    """

    slot: Slot
    memory_id: MemoryId
    mem_type: MemType
    text: str
    tokens: int
    score: float
    dedup_key: str

    def __post_init__(self) -> None:
        if self.tokens < 0:
            raise ValueError(f"tokens must be >= 0, got {self.tokens!r}")
        if not self.text.strip():
            raise ValueError("candidate text cannot be empty or whitespace-only")
        if not self.dedup_key:
            raise ValueError("dedup_key cannot be empty")
        # A NaN score silently destroys this module's determinism guarantee:
        # NaN compares False against everything, so `sorted(key=(-score, id))`
        # stops being a total order and the SAME candidate set packs into a
        # different slot list depending on the retriever's iteration order
        # (measured: four distinct orderings from three candidates). The
        # rendered block would then be unreproducible from the stored
        # `retrieval_event`, which is exactly what an audit needs it to be.
        # +/-inf is rejected for the same reason it is never a real score:
        # it makes one candidate uncomparable-by-magnitude with every other.
        if not isfinite(self.score):
            raise ValueError(f"score must be finite, got {self.score!r}")


@dataclass(frozen=True, slots=True)
class AssembledContext:
    """The assembler's output: an ordered slot list ready for `renderer.render()`.

    `slots` is already in final placement order (static prefix, then every
    dynamic slot) — `renderer.render()` re-groups defensively, but nothing
    downstream needs to reorder this to get correct placement.
    """

    slots: tuple[ContextSlot, ...]
    total_tokens: int
    dropped_memory_ids: tuple[MemoryId, ...]
    """Every input `memory_id` absent from `slots` — dropped by dedup, by the
    tier_a count cap, because no remaining budget fit it, or because its slot
    had no configured cap — sorted by `str(memory_id)` for a deterministic,
    diffable report. Derived by subtracting the selected set from the input
    set, so no reason for exclusion can go unreported. Telemetry's job to log
    these, not this module's (this module has no clock, no repo, no I/O)."""


def _better(candidate: Candidate, current: Candidate) -> bool:
    """Strict "wins the dedup slot" ordering: higher score, then lower id.

    The `memory_id` tie-break makes the winner independent of input order —
    `_pack`'s determinism promise is worth nothing if the set it packs already
    depends on which arm happened to list a duplicate first.
    """
    return candidate.score > current.score or (
        candidate.score == current.score and str(candidate.memory_id) < str(current.memory_id)
    )


def _collapse(candidates: Sequence[Candidate], key: Callable[[Candidate], object]) -> list[Candidate]:
    """Keep the single best candidate per `key`, in first-seen key order."""
    best: dict[object, Candidate] = {}
    for candidate in candidates:
        current = best.get(key(candidate))
        if current is None or _better(candidate, current):
            best[key(candidate)] = candidate
    return list(best.values())


def _dedup(candidates: Sequence[Candidate]) -> list[Candidate]:
    """Keep the highest-scoring candidate per `memory_id` AND per `dedup_key`.

    "Dedup across slots" means the same content proposed for two different
    slots — or the same memory proposed twice — collapses to its single
    best-scoring occurrence before any slot packing happens, not after.

    Both keys, in that order, because they catch different duplicates and
    neither subsumes the other. `dedup_key` identifies CONTENT: two distinct
    `memory_id`s carrying the same text (a Tier A candidate note duplicating an
    already-validated fact) must not both occupy the budget. `memory_id`
    identifies the ROW: one memory proposed twice under two different
    `dedup_key`s — which is what happens the moment anything upstream derives
    the key from something the two proposals do not share, e.g. the slot — would
    otherwise render twice, producing two `injection_log` rows with the same
    `(project_id, run_id, memory_id)` primary key for one run. Collapsing by
    `memory_id` first also means the surviving `dedup_key` group is chosen from
    already-unique rows, so the result cannot depend on which duplicate arrived
    first.
    """
    by_memory = _collapse(candidates, lambda c: c.memory_id)
    return _collapse(by_memory, lambda c: c.dedup_key)


def _pack(
    candidates: Sequence[Candidate], *, cap: int, max_count: int | None = None
) -> tuple[list[Candidate], int]:
    """Greedy, highest-score-first fill of one token budget (PLAN.md §6).

    "Over-budget input is truncated at slot caps, not arbitrarily": the
    boundary this function truncates at is always exactly `cap` (an
    `EffectiveConfig` value, never improvised) or `max_count` items, never a
    partial candidate — a memory item is an atomic unit of context, so a
    candidate either fits whole or is dropped whole; nothing is sliced
    mid-content. Candidates are considered in descending-score order (ties
    broken by `memory_id` for determinism — `Candidate.__post_init__` rejects
    a non-finite score precisely so this key stays a total order) and a
    candidate that would overflow `cap` is skipped rather than stopping the
    scan, so a smaller, lower-scoring candidate later in the order can still
    fill leftover room — this can only ever use MORE of the budget than a
    first-overflow-stops strategy, never exceed it.

    Deliberately returns only what it SELECTED. Which candidates were dropped
    is derived once, globally, in `assemble()` as "every input id that is not
    in the final slot list" — an accumulate-the-drops-as-you-go scheme reports
    nothing at all for a candidate that never reaches a `_pack` call (a slot
    the loop does not visit), which is a silent content loss with no audit
    trail. Subtraction cannot lose one.
    """
    ordered = sorted(candidates, key=lambda c: (-c.score, str(c.memory_id)))
    selected: list[Candidate] = []
    used = 0
    for candidate in ordered:
        if max_count is not None and len(selected) >= max_count:
            continue
        if used + candidate.tokens > cap:
            continue
        selected.append(candidate)
        used += candidate.tokens
    return selected, used


def assemble(candidates: Sequence[Candidate], *, cfg: EffectiveConfig) -> AssembledContext:
    """Dedup, then pack within budget, then place (static first, dynamic last).

    Every threshold consulted comes from `cfg.budget` / `cfg.tier_a` —
    `EffectiveConfig`, the layered project/agent-type/killswitch snapshot
    (PHASE0-CONTRACT.md §3.4) — never a literal in this function.

    Every pool is additionally clamped by what `budget.total_tokens` still
    has left. With the shipped defaults the section sums agree exactly
    (700 + 500 == 1200) and the clamp never bites, but `budget.*` fields are
    independently overridable per project and per agent type
    (`OVERRIDABLE_SECTIONS`, PLAN.md §6) — nothing validates that an operator
    lowering `total_tokens` also lowers `static_prefix`/`dynamic`. Without the
    clamp, that operator gets a block over the budget they just set; treating
    `total_tokens` as the outer bound makes the stated budget the one that
    actually holds, under any config, by construction rather than by an
    assertion that fires in production.
    """
    budget = cfg.budget
    deduped = _dedup(candidates)

    static_items = [c for c in deduped if c.slot is Slot.STATIC_PREFIX]
    prefs = [c for c in static_items if c.mem_type is MemType.PREFERENCE]
    lessons = [c for c in static_items if c.mem_type is not MemType.PREFERENCE]

    static_pool = _clamp(budget.static_prefix, budget.total_tokens)
    prefs_selected, prefs_used = _pack(
        prefs, cap=_clamp(budget.static_prefix_prefs, static_pool)
    )
    lessons_cap = _clamp(budget.static_prefix_lessons, static_pool - prefs_used)
    lessons_selected, lessons_used = _pack(lessons, cap=lessons_cap)

    remaining_dynamic = _clamp(budget.dynamic, budget.total_tokens - prefs_used - lessons_used)
    dynamic_pool = remaining_dynamic
    dynamic_selected: list[Candidate] = []
    for slot in _DYNAMIC_SLOTS:
        items = [c for c in deduped if c.slot is slot]
        # `.get`, not `[...]`: `slot_caps` is a plain dict field, so a project
        # override that replaces the whole mapping can legally omit a slot. A
        # KeyError here would be an unhandled 500 on the hot path — invariant 2
        # says a memory failure degrades to less context, never to a failed
        # retrieve. An unconfigured slot therefore has no budget to spend, and
        # its candidates surface in `dropped_memory_ids` where an operator can
        # see the misconfiguration instead of losing the call.
        slot_cap = _clamp(budget.slot_caps.get(slot.value, 0), remaining_dynamic)
        max_count = cfg.tier_a.candidate_cap_per_run if slot is Slot.CANDIDATE_NOTE else None
        selected, used = _pack(items, cap=slot_cap, max_count=max_count)
        dynamic_selected.extend(selected)
        remaining_dynamic -= used

    ordered_candidates = prefs_selected + lessons_selected + dynamic_selected
    slots = tuple(
        ContextSlot(
            slot=c.slot,
            memory_id=c.memory_id.value,
            tokens=c.tokens,
            text=c.text,
        )
        for c in ordered_candidates
    )
    total_tokens = prefs_used + lessons_used + (dynamic_pool - remaining_dynamic)

    selected_ids = {c.memory_id for c in ordered_candidates}
    all_dropped = sorted(
        {c.memory_id for c in candidates if c.memory_id not in selected_ids},
        key=str,
    )
    return AssembledContext(
        slots=slots,
        total_tokens=total_tokens,
        dropped_memory_ids=tuple(all_dropped),
    )


def _clamp(cap: int, headroom: int) -> int:
    """The tighter of a configured cap and the budget still unspent, never negative."""
    return max(min(cap, headroom), 0)
