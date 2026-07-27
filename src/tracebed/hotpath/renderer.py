"""Render-as-data: the MEMORY block (PLAN.md §2 invariant 3, §3 API contract).

Emits the block under the EXACT header `MEMORY (recalled data, verify
against current state)` (`domain.events.MEMORY_HEADER` — a Pydantic
validator on `ContextBlock.header` already refuses anything else, so this
module could not drift from it even by accident), with pitfalls in their own
labelled sub-block, and never imperative phrasing anywhere in the template
text itself (`templates.SECTION_LABELS` are noun phrases; see that module's
docstring for the full escaping argument).

HONEST FRAMING, restated here because it is the fact a caller of `render()`
most needs (D-026, PLAN.md §10): this is a **governance control** — it keeps
memory from ever looking like a system instruction, which is what preserves
policy subordination. It is **not** an anti-poisoning control. Delimiting
this way is the *weakest* prompt-injection defense variant: ~50% ASR
reduction against a non-adaptive attacker, **>95% ASR under an adaptive
one** (Hines et al., arXiv:2403.14720; Nasr et al.). Never cite render/
renderer/template output as something that stops a designed adversary —
`core.scans` (content-level rejection, run before storage) and the state
machine's quarantine gate (PLAN.md §5) are the controls actually doing that
work; this module's contribution is structural confinement of free text to
escaped value positions, nothing more.

Output is byte-stable for a given slot list: `render()` is a pure function
of its `ContextSlot` sequence — same slots in (regardless of input order,
since slots are grouped into `templates.SLOT_ORDER` here rather than trusted
to already be sorted), same `rendered` bytes out, always.
"""

from __future__ import annotations

from collections.abc import Sequence

from tracebed.domain.enums import Slot
from tracebed.domain.events import MEMORY_HEADER, PLACEMENT_APPEND_LAST, ContextBlock, ContextSlot
from tracebed.hotpath.templates import SECTION_LABELS, SLOT_ORDER, render_entry

__all__ = ["render"]


def render(slots: Sequence[ContextSlot]) -> ContextBlock:
    """Build the full `ContextBlock` for an already-assembled slot list.

    `assembler.assemble()` owns budget packing, dedup, and the tier_a
    candidate cap; this function only owns turning an ORDERED, ALREADY-
    DECIDED slot list into the wire shape — it never drops, reorders by
    score, or truncates anything itself (it does re-group by the canonical
    `SLOT_ORDER` defensively, but preserves each slot's relative input order,
    so a caller that already produced correctly-ordered input gets identical
    output either way).

    `ContextBlock.slots` carries the SAME order as `rendered`, not the raw
    input order. These are two views of one injection: `injection_log.slot`
    rows are written from `slots`, while the model saw `rendered`. If the two
    disagreed on order, an auditor reconstructing "what was actually in the
    prompt, in what order" from the structured view would get an answer the
    prompt never contained — so the regrouping is applied once and both
    fields are built from it.

    An EMPTY slot list renders as the empty string, never as a lone
    `MEMORY_HEADER`. `Pipeline` calls this on the abstention and empty-result
    rungs too (PLAN.md §2 invariant 2: those rungs return "nothing"), and a
    bare header is not nothing — it spends prompt tokens to tell the model
    memory was recalled when none was, which is exactly the false-confidence
    signal abstention exists to avoid. `domain.events.empty_context_block()`
    already uses `rendered=""` for the same situation; this keeps the two
    paths byte-identical.
    """
    ordered = _in_canonical_order(slots)
    return ContextBlock(
        placement=PLACEMENT_APPEND_LAST,
        header=MEMORY_HEADER,
        slots=ordered,
        rendered=_render_text(ordered),
    )


def _in_canonical_order(slots: Sequence[ContextSlot]) -> list[ContextSlot]:
    """Group by `SLOT_ORDER`, preserving each slot's relative input order."""
    return [s for slot in SLOT_ORDER for s in slots if s.slot is slot]


def _render_text(ordered: Sequence[ContextSlot]) -> str:
    if not ordered:
        return ""
    lines: list[str] = [MEMORY_HEADER]
    current: Slot | None = None
    for item in ordered:
        if item.slot is not current:
            current = item.slot
            lines.append("")
            lines.append(SECTION_LABELS[item.slot])
        lines.append(
            render_entry(
                slot=item.slot,
                memory_id=item.memory_id,
                tokens=item.tokens,
                text=item.text,
            )
        )
    return "\n".join(lines)
