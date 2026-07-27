"""Per-mem_type field validation (PHASE-0 Task 9, PHASE0-CONTRACT.md §4).

`scan()` only sees `content: str` plus a `ScanContext` (project_id, mem_type,
trust_tier, provenance_class, lane) — there is no `NewMemoryItem` at scan
time, so this sub-scan validates structural properties of the candidate
content string against its declared `mem_type`, not a full row shape. It
catches malformed candidates (empty, control-character-laden, absurdly long
for what the mem_type is meant to hold) before they ever reach a state-machine
transition or a template renderer.

Imports `tracebed.domain.enums.MemType` — the one domain dependency in this
sub-scan, because "per mem_type" is meaningless without the real enum.
"""

from __future__ import annotations

import re
from typing import Final

from tracebed.domain.enums import MemType

__all__ = [
    "SCHEMA_SUITE_VERSION",
    "check_schema",
    "max_content_chars",
    "oversize_reason",
]

# Folded into core/scans.SUITE_VERSION alongside the patterns/secrets versions
# so that changing a ceiling or a character class produces verdicts that are
# distinguishable from the ones the previous rule set issued. Without this, a
# stored scan_verdict_id would claim a rule set it was not actually produced by.
SCHEMA_SUITE_VERSION: Final[str] = "scans-schema/1.0.0"

# Character ceilings are deliberately generous relative to BudgetConfig's
# slot token caps (PLAN.md §6) — this is a structural sanity check, not a
# budget enforcer (the assembler owns budget truncation in Phase 1). A
# candidate this long for its mem_type is a strong signal of malformed or
# adversarially-padded content regardless of what it says.
_MAX_CONTENT_CHARS: Final[dict[MemType, int]] = {
    MemType.EPISODIC: 6_000,
    MemType.SEMANTIC: 6_000,
    MemType.LESSON: 3_000,
    MemType.PREFERENCE: 1_500,
}
_DEFAULT_MAX_CONTENT_CHARS: Final[int] = 6_000

# Disallow C0 control characters other than \t/\n/\r — binary/control-char
# smuggling has no legitimate reason to appear in memory content, which is
# always rendered as escaped text inside a template (invariant 3).
_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def max_content_chars(mem_type: MemType) -> int:
    """The character ceiling for `mem_type`. Public because `core.scans.scan`
    applies it as a pre-flight guard *before* the regex sub-scans run — that
    is the only thing bounding the CPU an unauthenticated-shaped, attacker-
    sized candidate can force onto the synchronous write path."""
    return _MAX_CONTENT_CHARS.get(mem_type, _DEFAULT_MAX_CONTENT_CHARS)


def oversize_reason(mem_type: MemType) -> str:
    """THE reason string for a ceiling breach. One definition so the pre-flight
    guard in `scan()` and `check_schema` cannot drift apart."""
    return f"schema:content_exceeds_{mem_type.value}_ceiling"


def check_schema(content: str, *, mem_type: MemType) -> tuple[str, ...]:
    """Returns reason strings (empty tuple = passed). Every reason is
    prefixed `schema:` so `ScanResult.reasons` stays self-describing."""
    reasons: list[str] = []

    stripped = content.strip()
    if not stripped:
        # Nothing else is checkable on empty content; return immediately so
        # callers don't also see a spurious "too short" reason stacked on it.
        return ("schema:empty_content",)

    if _CONTROL_CHAR_RE.search(content) is not None:
        reasons.append("schema:control_characters")

    if len(content) > max_content_chars(mem_type):
        reasons.append(oversize_reason(mem_type))

    return tuple(reasons)
