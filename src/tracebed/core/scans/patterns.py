"""Injection-pattern rule set (PHASE-0 Task 9, PHASE0-CONTRACT.md §4).

Detects imperative phrasing aimed at a model, tool-invocation syntax, role /
instruction markers, delimiter-escape attempts, and known prompt-injection
markers. Deliberately has **no import from `tracebed.domain`** — this module
is content-in, hits-out so it is testable (and reusable) with zero dependency
on the rest of the domain layer landing first (RT-03: scans exists before any
write path and must not block on sibling chunks to be exercised in isolation).

Every rule carries an id, a severity, and a rationale string so a rejection
routed to `review_queue` can be explained to an operator (PHASE-0 Task 9).
Severity is informational triage metadata, not a pass/fail lever: `scan()`
(in `core/scans/__init__.py`) rejects on ANY non-empty reason list, strong or
weak — a `ScanResult.passed` derived from anything less would silently let a
"weak" injection payload become one of the same-run injectable candidates
that D-019/D-024 exist to keep out.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

__all__ = [
    "PATTERNS_SUITE_VERSION",
    "PatternHit",
    "RuleSeverity",
    "scan_patterns",
]

# Bumped whenever a rule is added, removed, or its regex changes meaning —
# folded into core/scans.SUITE_VERSION so a corpus regression is traceable
# to the exact rule set that produced it.
# 1.1.0: added the separator-normalised second pass (see `_normalised`).
PATTERNS_SUITE_VERSION: Final[str] = "scans-patterns/1.1.0"


class RuleSeverity(StrEnum):
    """Operator-facing confidence label. See module docstring: not a gate."""

    STRONG = "strong"
    WEAK = "weak"


@dataclass(frozen=True, slots=True)
class PatternHit:
    """One rule match. `reason` is the exact string that lands in
    `ScanResult.reasons` and, ultimately, in the review_queue row."""

    rule_id: str
    severity: RuleSeverity
    rationale: str
    reason: str


@dataclass(frozen=True, slots=True)
class _Rule:
    id: str
    severity: RuleSeverity
    rationale: str
    pattern: re.Pattern[str]


def _rule(id_: str, severity: RuleSeverity, rationale: str, pattern: str, *, flags: int = re.IGNORECASE) -> _Rule:
    return _Rule(id=id_, severity=severity, rationale=rationale, pattern=re.compile(pattern, flags))


# -- STRONG: unambiguous injection intent, structural markers a benign ------
# operational document has no reason to contain.
_STRONG_RULES: Final[tuple[_Rule, ...]] = (
    _rule(
        "ignore-prior-instructions",
        RuleSeverity.STRONG,
        "imperative command to discard prior/system instructions — classic override attempt",
        r"\b(ignore|disregard|override|forget)\b[^.\n]{0,40}\b(previous|prior|above|earlier|system|all)\b"
        r"[^.\n]{0,40}\b(instructions?|prompt|rules|guidelines|directives?)\b",
    ),
    _rule(
        "new-instructions-marker",
        RuleSeverity.STRONG,
        "explicit 'new instructions:' header used to smuggle a replacement instruction block",
        r"\bnew\s+instructions?\s*:",
    ),
    _rule(
        "role-marker-injection",
        RuleSeverity.STRONG,
        "chat role marker (system:/assistant:) at line start — attempts to forge a turn boundary",
        r"^\s*(system|assistant)\s*:\s*\S",
        flags=re.IGNORECASE | re.MULTILINE,
    ),
    _rule(
        "chatml-control-tag",
        RuleSeverity.STRONG,
        "ChatML/special-token control sequence — attempts to forge a model-internal turn boundary",
        r"<\|\s*(?:im_start|im_end|system|assistant|endoftext)\s*\|>",
    ),
    _rule(
        "xml-role-tag",
        RuleSeverity.STRONG,
        "pseudo-XML system/admin/instructions tag — delimiter-escape attempt against templated rendering",
        r"</?\s*(?:system|instructions|admin_override|root_prompt)\s*>",
    ),
    _rule(
        "tool-invocation-syntax",
        RuleSeverity.STRONG,
        "embedded tool/function-call syntax — attempts to trigger real tool invocation from recalled text",
        r'(?:"tool_call"|"function_call"|<tool_call>|<function_call>|\btool_code\b)',
    ),
    _rule(
        "jailbreak-marker",
        RuleSeverity.STRONG,
        "named jailbreak/unrestricted-mode marker",
        r"\b(DAN\s+mode|developer\s+mode\s+enabled|do\s+anything\s+now|jailbreak(?:ed)?\s+mode)\b",
    ),
    _rule(
        "reveal-system-prompt",
        RuleSeverity.STRONG,
        "request to exfiltrate the hidden system prompt/instructions",
        r"\breveal\s+(?:your|the)\s+(?:system\s+prompt|hidden\s+prompt|instructions)\b",
    ),
    _rule(
        "print-verbatim",
        RuleSeverity.STRONG,
        "instructs the model to reproduce attacker-controlled content verbatim, bypassing rendering",
        r"\bprint\s+(?:the\s+following\s+)?verbatim\b",
    ),
    _rule(
        "act-as-unrestricted",
        RuleSeverity.STRONG,
        "persona-override request explicitly asking for removal of restrictions",
        r"\bact\s+as\b[^.\n]{0,40}\b(?:unrestricted|no\s+restrictions|without\s+(?:any\s+)?(?:filters|limits|restrictions))\b",
    ),
    _rule(
        "pretend-unbound",
        RuleSeverity.STRONG,
        "persona-override request claiming the model is not bound by its normal rules",
        r"\bpretend\s+(?:that\s+)?you(?:'re|\s+are)\b[^.\n]{0,40}\b(?:not\s+bound|no\s+rules|without\s+restrictions)\b",
    ),
    _rule(
        "exfiltrate-data",
        RuleSeverity.STRONG,
        "instructs exfiltration of secrets/credentials to an attacker-controlled destination",
        r"\bsend\s+(?:all|the)\s+(?:data|secrets|credentials|api\s+keys?|tokens?)\s+to\b",
    ),
    _rule(
        "decode-and-execute",
        RuleSeverity.STRONG,
        "instructs decoding an encoded blob and executing/evaluating the result",
        r"\bdecode\b[^.\n]{0,25}\bbase64\b[^.\n]{0,40}\b(?:execute|run|eval)\b",
    ),
    _rule(
        "override-safety",
        RuleSeverity.STRONG,
        "explicit instruction to ignore safety/guardrail/policy layers",
        r"\bignore\s+(?:your\s+)?(?:safety|guardrails?|content\s+policy|moderation)\b",
    ),
    _rule(
        "boundary-override-marker",
        RuleSeverity.STRONG,
        "bracketed boundary/override marker used to forge the end of the user turn",
        r"\[\s*(?:end\s+of\s+user\s+message|system\s+override|admin\s+override|end\s+context)\s*\]",
    ),
    _rule(
        "hash-instruction-marker",
        RuleSeverity.STRONG,
        "markdown-heading-style '## Instructions' block smuggled into recalled content",
        r"^#{2,}\s*instructions?\b",
        flags=re.IGNORECASE | re.MULTILINE,
    ),
    _rule(
        "you-are-now-persona",
        RuleSeverity.STRONG,
        "persona-replacement instruction ('you are now ...') aimed at the model reading this text",
        r"\byou\s+are\s+now\b[^.\n]{0,40}\b(?:chatgpt|an?\s+ai|a\s+different\s+(?:model|assistant))\b",
    ),
)

# -- WEAK: imperative-shaped phrasing that is plausible in ordinary --------
# operational prose but worth a lower-confidence flag for the review queue.
_WEAK_RULES: Final[tuple[_Rule, ...]] = (
    _rule(
        "imperative-you-must-now",
        RuleSeverity.WEAK,
        "second-person imperative aimed at immediate model behavior change",
        r"\byou\s+must\s+now\b",
    ),
    _rule(
        "please-ignore",
        RuleSeverity.WEAK,
        "polite-form override request, softer variant of an ignore-instructions attempt",
        r"\bplease\s+ignore\b",
    ),
    _rule(
        "from-now-on-behavior",
        RuleSeverity.WEAK,
        "'from now on' behavior-change framing, common in low-effort injection attempts",
        r"\bfrom\s+now\s+on\b[^.\n]{0,30}\b(?:you|respond|behave|act)\b",
    ),
    _rule(
        "important-override-framing",
        RuleSeverity.WEAK,
        "urgency framing paired with an imperative, a common injection lead-in",
        r"\bthis\s+is\s+(?:very\s+)?important\b[^.\n]{0,30}\bmust\b",
    ),
    _rule(
        "meta-ai-commentary",
        RuleSeverity.WEAK,
        "'as an AI language model' meta-commentary marker, often used to frame a fake refusal/override",
        r"\bas\s+an\s+ai\s+language\s+model\b",
    ),
)


# Identifier-shaped compound: two or more alphanumeric segments joined by
# `_`, `.`, `-` or `:`. Exactly the charset `tier_a_template._IDENTIFIER_RE`
# admits, which is the point — see `_normalised`.
_IDENTIFIER_COMPOUND_RE: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9]+(?:[_.:-][A-Za-z0-9]+)+")


def _normalised(text: str) -> str:
    """Splits identifier-shaped compounds into their words.

    Closes a real evasion, not a hypothetical one. `_` is a word character to
    `re`, so `\\bignore\\b` does NOT match inside `ignore_all_prior_instructions`
    — and `.` is excluded from the `[^.\\n]` gap classes the multi-word rules
    use, so `ignore.prior.instructions` escapes them too. Both strings are
    valid values for `TierANote.tool_id` (D-019's charset is
    `^[A-Za-z0-9_.:-]{1,128}$`), which is how attacker-chosen prose reaches a
    Tier-A note in identifier clothing. Running the rule set a second time over
    the separator-split form catches it.

    Only identifier-shaped compounds are rewritten, never the document's own
    punctuation: the multi-word rules rely on `.` as a sentence boundary to
    stay inside one clause, and dissolving every full stop would let a rule
    match across two unrelated sentences.

    Only `_` and `.` are replaced. `-` and `:` are already non-word characters
    that the gap classes admit, so `ignore-prior-instructions` and `system:x`
    match the rule set unmodified — replacing `:` would in fact *destroy* the
    `new instructions:` marker signal.
    """
    return _IDENTIFIER_COMPOUND_RE.sub(
        lambda m: m.group(0).replace("_", " ").replace(".", " "), text
    )


def scan_patterns(text: str) -> tuple[PatternHit, ...]:
    """Runs every STRONG then WEAK rule against `text`, then again over its
    separator-normalised form (`_normalised`). Order is stable and a rule
    that fires in both passes yields exactly one hit, so callers that only
    care about the first hit (e.g. logging) get the highest-confidence one
    first and `ScanResult.reasons` never repeats a rule id."""
    variants = [text]
    normalised = _normalised(text)
    if normalised != text:
        variants.append(normalised)

    hits: list[PatternHit] = []
    for rule in (*_STRONG_RULES, *_WEAK_RULES):
        if any(rule.pattern.search(variant) is not None for variant in variants):
            hits.append(
                PatternHit(
                    rule_id=rule.id,
                    severity=rule.severity,
                    rationale=rule.rationale,
                    reason=f"injection:{rule.id}",
                )
            )
    return tuple(hits)
