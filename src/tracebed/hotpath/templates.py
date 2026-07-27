r"""Closed-vocabulary template shapes, one per `Slot` (PLAN.md §2 invariant 3).

HONEST FRAMING (D-026, PLAN.md §10) — read this before trusting anything in
this module: render-as-data is a **governance control**, not an
anti-poisoning one. It preserves policy subordination (memory can never look
like a system instruction because it is never rendered as one), which is a
real and worth-having property. It does **not** stop a designed adversary:
delimiting/spotlighting is the *weakest* prompt-injection defense variant —
measured at roughly 50% attack-success-rate reduction against a
non-adaptive attacker and **>95% ASR under an adaptive one**
(Hines et al., arXiv:2403.14720; Nasr et al.). Nothing in this module, or in
`renderer.py`, or in `assembler.py`, should ever be cited as preventing
prompt injection. What it demonstrably does is make every top-level token in
a rendered block come from a fixed, closed vocabulary — attacker-controlled
text is confined to escaped *value positions* it can never structurally
escape from, which is the property the tests in this chunk actually prove.

Escaping mechanism: every free-text field value is encoded with
`json.dumps(value, ensure_ascii=True)` before it is placed in a template.
Three properties of that encoding are what make the invariant hold, not
convention:

  1. The result is always a single physical line — a real newline in the
     source text becomes the two-character escape `\\n`, never a raw `\n`.
     A payload can therefore never make the renderer emit an extra line
     (a forged section header, a forged `MEMORY_HEADER`, a second entry).
  2. Every literal `"` is escaped to `\"`, so a payload can never terminate
     the JSON string early and start writing raw template syntax.
  3. `ensure_ascii=True` turns every non-ASCII code point — including
     bidirectional-override control characters (U+202E and friends) and any
     other Unicode confusable — into a `\uXXXX` escape, so no byte of the
     rendered line can visually reorder or disguise surrounding template
     text.

Nothing here holds an opinion about *content* (that is `core.scans`' job,
which runs before a memory item is ever stored); this module's only
guarantee is structural: template syntax and value payload never share a
tokenisation.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Final
from uuid import UUID

from tracebed.domain.enums import Slot
from tracebed.domain.events import MEMORY_HEADER

__all__ = [
    "SECTION_LABELS",
    "SLOT_ORDER",
    "STRUCTURAL_LINES",
    "ParsedEntry",
    "parse_entry",
    "render_entry",
]

# The literal token written when a slot entry has no backing memory_id (the
# domain type is `UUID | None` — `ContextSlot.memory_id`, PHASE0-CONTRACT.md
# §3.5). Deliberately not a valid UUID shape, so it can never collide with a
# real minted id in `parse_entry`.
_NO_MEMORY_ID: Final = "-"

# Canonical render order (D-016 / PLAN §6): the static, cacheable slot first,
# then every dynamic slot, in a fixed order the assembler also uses when it
# spends the shared `budget.dynamic` pool (PLAN.md §6: "fact/exemplar/
# pitfall/candidate/jit").
SLOT_ORDER: Final[tuple[Slot, ...]] = (
    Slot.STATIC_PREFIX,
    Slot.FACT,
    Slot.EXEMPLAR,
    Slot.PITFALL,
    Slot.CANDIDATE_NOTE,
    Slot.JIT_LESSON,
)

# SLOT_ORDER is not merely a display preference: `renderer._render_text` walks
# it to decide what to emit, and `assembler._DYNAMIC_SLOTS` derives from it to
# decide what to spend budget on. A member missing from it is therefore a
# memory item that is silently never rendered AND never reported as dropped —
# a content loss with no audit trail, which no test downstream can distinguish
# from "the retriever returned nothing". A duplicate member is the mirror
# failure: the same section emitted twice. Both are import-time errors, not
# runtime luck (same enforcement style as SECTION_LABELS below).
if len(SLOT_ORDER) != len(set(SLOT_ORDER)) or set(SLOT_ORDER) != set(Slot):
    raise RuntimeError(  # pragma: no cover - would only fire on a future Slot member
        f"SLOT_ORDER must list every Slot exactly once; "
        f"missing: {sorted(set(Slot) - set(SLOT_ORDER))}, "
        f"duplicated: {sorted({s for s in SLOT_ORDER if SLOT_ORDER.count(s) > 1})}"
    )

# Fixed, closed-vocabulary section labels. Every one is a noun phrase, never
# an instruction directed at the reader/agent — invariant 3's "never
# imperative phrasing" applies to the renderer's own template text, not only
# to the escaped values it carries. PITFALL gets its own labelled sub-block
# per PLAN.md §2 invariant 3 verbatim ("pitfalls in a separate labeled
# sub-block"); CANDIDATE_NOTE's label carries the lower-trust disclosure
# PLAN.md §5's retrievable-statuses note requires for Tier A `candidate` rows
# ("labeled lower-trust").
SECTION_LABELS: Final[dict[Slot, str]] = {
    Slot.STATIC_PREFIX: "STATIC PREFIX",
    Slot.FACT: "FACTS",
    Slot.EXEMPLAR: "EXEMPLARS",
    Slot.PITFALL: "PITFALLS (unconfirmed against current state)",
    Slot.CANDIDATE_NOTE: "CANDIDATE NOTES (tier A, unconfirmed, lower-trust)",
    Slot.JIT_LESSON: "JIT LESSONS",
}

if set(SECTION_LABELS) != set(Slot):  # exhaustiveness at import time, not by luck
    raise RuntimeError(  # pragma: no cover - would only fire on a future Slot member
        f"SECTION_LABELS is not total over Slot; missing: {sorted(set(Slot) - set(SECTION_LABELS))}"
    )

# `MEMORY_HEADER` (from domain.events) plus every section label plus the
# blank separator line: the complete set of non-entry lines a correctly
# rendered block may ever contain. Exposed so the property test can classify
# every line of a rendered document as either "structural" (a member of this
# set) or "entry" (matches `_ENTRY_RE`) with no third category.
STRUCTURAL_LINES: Final[frozenset[str]] = frozenset({MEMORY_HEADER, "", *SECTION_LABELS.values()})

_MEMORY_ID_RE: Final = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_SLOT_ALTERNATION: Final = "|".join(member.value for member in Slot)

# The ONE entry shape, parameterised only over the closed `Slot` vocabulary.
# `text_json` is intentionally greedy (`".*"`) — json.dumps never emits a raw
# newline or an unescaped `"` inside the string body, so on a single
# already-split line the first `"` through the LAST `"` is exactly the JSON
# string's own boundary; nothing an adversarial value can contain shifts that
# boundary (see the module docstring's three properties).
_ENTRY_RE: Final[re.Pattern[str]] = re.compile(
    rf'^- \[(?P<slot>{_SLOT_ALTERNATION})\] '
    rf'id=(?P<memory_id>{_MEMORY_ID_RE}|-) '
    rf'tokens=(?P<tokens>\d+) '
    rf'text=(?P<text_json>".*")$'
)


def render_entry(*, slot: Slot, memory_id: UUID | None, tokens: int, text: str) -> str:
    """The only place a slot's fields become text. One line, always.

    `memory_id` (server-minted UUID or absent) and `tokens` (a computed int)
    are not attacker-reachable, so they are written verbatim; `text` is the
    sole free-text field and is always JSON-encoded (module docstring).
    """
    if tokens < 0:
        raise ValueError(f"tokens must be >= 0, got {tokens!r}")
    memory_id_token = str(memory_id) if memory_id is not None else _NO_MEMORY_ID
    text_json = json.dumps(text, ensure_ascii=True)
    return f"- [{slot.value}] id={memory_id_token} tokens={tokens} text={text_json}"


@dataclass(frozen=True, slots=True)
class ParsedEntry:
    """The result of successfully parsing one rendered entry line back apart."""

    slot: Slot
    memory_id: UUID | None
    tokens: int
    text: str


def parse_entry(line: str) -> ParsedEntry | None:
    """Parse one line back into its shape, or `None` if it matches no approved shape.

    Used by the property test to prove every non-structural line in a
    rendered document is an instance of exactly one of the six approved
    entry shapes, and that the value it carries round-trips byte-for-byte
    through the JSON encoding (proving the escaping did not silently mangle
    or truncate the payload it is supposed to be neutralising structurally).
    """
    match = _ENTRY_RE.match(line)
    if match is None:
        return None
    slot = Slot(match.group("slot"))
    memory_id_raw = match.group("memory_id")
    memory_id = None if memory_id_raw == _NO_MEMORY_ID else UUID(memory_id_raw)
    tokens = int(match.group("tokens"))
    try:
        text = json.loads(match.group("text_json"))
    except json.JSONDecodeError:
        return None
    if not isinstance(text, str):
        return None
    return ParsedEntry(slot=slot, memory_id=memory_id, tokens=tokens, text=text)
