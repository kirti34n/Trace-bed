"""Closed-vocabulary Tier A template validator (PHASE-0 Task 9, D-019).

Tier A operational notes are rendered exclusively from `TierANote` — a
closed-vocabulary enum + identifier-charset + hex-digest tuple. There is no
free-text `str` parameter on the constructor, by construction: this is the
compile-time half of Phase 2's zero-passthrough gate (a structural test
introspects `TierANote.__init__`'s resolved type hints and fails CI if
anyone ever adds a bare `str` field). `render_note` is a deterministic
template that can only ever reproduce bytes drawn from that closed
vocabulary, which is what makes the gate test ("rendered output shares no
>=8-byte substring with any tool-error body fixture") true by design rather
than by luck.

`tool_id`/`tool_version`/`payload_class_hash` are identifier/hash-shaped
strings, so "no str field" is enforced the same way `domain/ids.py` enforces
"no bare UUID field" — via distinct types (`typing.NewType`, not a bare
`str` alias) rather than by refusing to hold string data at all. mypy sees
`ToolIdentifier`/`HexDigest`, not `str`; `__post_init__` still does the
actual runtime charset/hex validation, since `NewType` is identity-only at
runtime (D-019: the enforcement that matters is the regex check, this just
keeps the type-level signal honest too).

D-019's finding: tool error bodies echo attacker input verbatim (stack
traces quote payloads; Pydantic v2 embeds the offending value as
`input_value=` in its own error message), so "structured note, free text
stays behind a pointer" was false until the constructor itself made a raw
string bypass impossible. This module has zero imports from
`tracebed.domain` — `ErrorClassEnum` is scans-internal vocabulary
(PHASE0-CONTRACT.md §3.2), independent of anything landing in a sibling
chunk first.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, NewType

__all__ = [
    "ErrorClassEnum",
    "HexDigest",
    "TierANote",
    "ToolIdentifier",
    "render_note",
]

#: Identifier-charset string (tool_id / tool_version). Distinct from `str`
#: at the type level so "no str field" is checkable by introspection.
ToolIdentifier = NewType("ToolIdentifier", str)

#: Lowercase hex sha256 digest of a payload's *schema class* (never its
#: content). Distinct from `str` at the type level for the same reason.
HexDigest = NewType("HexDigest", str)


class ErrorClassEnum(StrEnum):
    """The closed set of operational error classes a Tier A note may carry.
    Exactly PHASE0-CONTRACT.md §4's enumeration — the binding contract's
    ten members supersede PHASE-0.md's prose listing (contract wins per its
    own authority order; logged as a contract_gap)."""

    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    AUTH_DENIED = "auth_denied"
    SCHEMA_VALIDATION = "schema_validation"
    TOOL_UNAVAILABLE = "tool_unavailable"
    NETWORK = "network"
    SERVER_ERROR = "server_error"
    CANCELLED = "cancelled"
    RESOURCE_EXHAUSTED = "resource_exhausted"
    UNKNOWN = "unknown"


# Identifier charset. Matches the contract's `^[A-Za-z0-9_.:-]{1,128}$`
# exactly (§4), which is binding, so this is what the check is.
#
# Honest limit, stated because the previous comment here claimed the opposite:
# this charset does NOT make prose smuggling impossible. `_` and `.` are legal
# separators, so `ignore_all_prior_instructions` is a well-formed tool_id and
# 128 characters is room for a sentence. Two layers cover the residual channel:
# `patterns._normalised` runs the injection rule set over the separator-split
# form of any content (so the smuggled sentence is detected wherever this note
# is later scanned), and Phase 2's extractor must source tool_id from the tool
# registry/manifest rather than from an error body. The charset's real job is
# narrower and it does do it: no whitespace, no newline, no quote, no angle
# bracket — a note can never carry a verbatim run of tool-output text.
_IDENTIFIER_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")

# payload_class_hash is a sha256 hex digest of the payload's *schema class*
# (never its content) — lowercase hex, fixed digest length.
_HEX_DIGEST_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class TierANote:
    """Closed vocabulary by construction. NO free-text `str` field exists
    here — every field is either an enum, a `NewType`-distinct
    identifier/hash string, or a non-negative int, each validated in
    `__post_init__`. This is what a structural test can introspect via
    `typing.get_type_hints(TierANote.__init__)` and assert stays true
    forever (D-019)."""

    error_class: ErrorClassEnum
    tool_id: ToolIdentifier
    tool_version: ToolIdentifier
    count: int
    duration_ms: int
    payload_class_hash: HexDigest

    def __post_init__(self) -> None:
        if not isinstance(self.error_class, ErrorClassEnum):
            raise TypeError(f"error_class must be ErrorClassEnum, got {type(self.error_class).__name__}")
        if _IDENTIFIER_RE.match(self.tool_id) is None:
            raise ValueError(f"tool_id fails identifier charset {_IDENTIFIER_RE.pattern!r}: {self.tool_id!r}")
        if _IDENTIFIER_RE.match(self.tool_version) is None:
            raise ValueError(f"tool_version fails identifier charset {_IDENTIFIER_RE.pattern!r}: {self.tool_version!r}")
        if self.count < 0:
            raise ValueError(f"count must be >= 0, got {self.count}")
        if self.duration_ms < 0:
            raise ValueError(f"duration_ms must be >= 0, got {self.duration_ms}")
        if _HEX_DIGEST_RE.match(self.payload_class_hash) is None:
            raise ValueError(f"payload_class_hash must be a 64-char lowercase hex sha256 digest: {self.payload_class_hash!r}")


# Short, opaque codes for error_class and field labels — NOT the enum's own
# English words ("timeout", "schema_validation", "cancelled", ...) and NOT
# spelled-out labels ("payload_class_hash="). A tool error body describing a
# timeout will very plausibly contain the literal word "timeout"; a body
# about a memory-exhaustion error will very plausibly contain the literal
# word "payload". Rendering the full English vocabulary word would make the
# zero-passthrough gate fail on ordinary, non-adversarial error prose — not
# because anything leaked, but because English has a limited vocabulary for
# describing timeouts. Short fixed codes are still closed-vocabulary
# (`_ERROR_CLASS_CODE` is total over `ErrorClassEnum`, exhaustively checked
# below) and still fully reversible; they just don't double as common
# English substrings.
_ERROR_CLASS_CODE: Final[dict[ErrorClassEnum, str]] = {
    ErrorClassEnum.TIMEOUT: "TMO",
    ErrorClassEnum.RATE_LIMITED: "RLM",
    ErrorClassEnum.AUTH_DENIED: "AUD",
    ErrorClassEnum.SCHEMA_VALIDATION: "SCV",
    ErrorClassEnum.TOOL_UNAVAILABLE: "TUN",
    ErrorClassEnum.NETWORK: "NET",
    ErrorClassEnum.SERVER_ERROR: "SRV",
    ErrorClassEnum.CANCELLED: "CNL",
    ErrorClassEnum.RESOURCE_EXHAUSTED: "REX",
    ErrorClassEnum.UNKNOWN: "UNK",
}
if set(_ERROR_CLASS_CODE) != set(ErrorClassEnum):  # exhaustiveness, checked at import time
    # A raise, not an `assert`: `python -O` strips asserts, and the failure
    # mode this guards is a KeyError inside render_note on a production write
    # path the moment someone adds an ErrorClassEnum member without a code.
    raise RuntimeError(
        "_ERROR_CLASS_CODE is not total over ErrorClassEnum; missing: "
        f"{sorted(set(ErrorClassEnum) - set(_ERROR_CLASS_CODE))}"
    )

# Fixed, deterministic template — the ONLY place a TierANote's fields become
# text. Every substitution slot is bound to a validated, closed-vocabulary
# field; there is no format-string interpolation of anything else.
_TEMPLATE: Final[str] = "TAN1|ec={error_class}|ti={tool_id}|tv={tool_version}|n={count}|dur={duration_ms}|pch={payload_class_hash}"


def render_note(note: TierANote) -> str:
    """Deterministic template rendering, closed-vocabulary input only.
    Same `TierANote` -> byte-identical string, always."""
    return _TEMPLATE.format(
        error_class=_ERROR_CLASS_CODE[note.error_class],
        tool_id=note.tool_id,
        tool_version=note.tool_version,
        count=note.count,
        duration_ms=note.duration_ms,
        payload_class_hash=note.payload_class_hash,
    )
