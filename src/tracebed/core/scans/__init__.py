"""The shared scan gate suite (PHASE-0 Task 9, PHASE0-CONTRACT.md §4).

`scan(content, *, context)` runs, in order: injection-pattern scan
(`patterns.py`), secret scan (`secrets.py`), and per-mem_type schema check
(`schema_check.py`). `ScanResult.verdict()` is the ONLY site anywhere that
constructs a `ScanVerdict` — every write path (Tasks 14-16, and every later
phase) must present one to `Repo.insert_memory_item`, and `verify_verdict`
(also only defined here) is what the repository calls to prove a verdict was
genuinely minted by this module for this exact content (RT-03: this module
exists and is enforced before any write path does).

Pure module: no repo import, no I/O. Persisting a rejection to `review_queue`
is the CALLER's job, via `persist_rejection`'s writer callable — that keeps
`core/scans` importable from anywhere, including a future hot path, without
ever importing `stores.pg`.
"""

from __future__ import annotations

import hashlib
import hmac
import uuid
from dataclasses import dataclass
from typing import Final, Protocol

from tracebed.core.scans import patterns as _patterns
from tracebed.core.scans import schema_check as _schema_check
from tracebed.core.scans import secrets as _secrets
from tracebed.core.scans._authority import SIGNING_KEY as _SIGNING_KEY
from tracebed.domain.canonical import content_hash as _content_hash
from tracebed.domain.clock import Clock, SystemClock
from tracebed.domain.enums import Lane, MemType, ProvenanceClass, TrustTier
from tracebed.domain.errors import ScanRejected, ScanVerdictForgery
from tracebed.domain.ids import ProjectId
from tracebed.domain.scan import ScanVerdict

__all__ = [
    "SUITE_VERSION",
    "ReviewQueueWriter",
    "ScanContext",
    "ScanResult",
    "persist_rejection",
    "scan",
    "verify_verdict",
]

# Bumped on any rule-set change in patterns.py/secrets.py/schema_check.py.
# Folds ALL THREE sub-suite versions in so a stored verdict's suite_version
# alone is enough to know exactly which rule set produced it — schema_check
# was previously omitted, which would have let a ceiling change ship under a
# suite_version claiming the rule set it was not produced by.
SUITE_VERSION: Final[str] = (
    f"scans/1.2.0+{_patterns.PATTERNS_SUITE_VERSION}"
    f"+{_secrets.SECRETS_SUITE_VERSION}+{_schema_check.SCHEMA_SUITE_VERSION}"
)

# The one wall-clock source (hard rule 5 / PHASE0-CONTRACT.md §14: no
# `datetime.now()`/`time.time()` outside SystemClock). `ScanResult.verdict()`
# needs an `issued_at_ms` and the contract gives it no clock parameter, so the
# module default is a SystemClock; tests and simulated-clock workers pass their
# own via the keyword.
_DEFAULT_CLOCK: Final[Clock] = SystemClock()


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Everything the scan suite needs about *where* content is headed,
    beyond the content itself (PHASE0-CONTRACT.md §4)."""

    project_id: ProjectId
    mem_type: MemType
    trust_tier: TrustTier
    provenance_class: ProvenanceClass
    lane: Lane


def _sign(verdict_id: uuid.UUID, content_hash_hex: str, suite_version: str, issued_at_ms: int) -> bytes:
    """HMAC-SHA256 over verdict_id || content_hash || suite_version ||
    issued_at_ms (C-06's exact byte layout)."""
    message = (
        verdict_id.bytes
        + content_hash_hex.encode("utf-8")
        + suite_version.encode("utf-8")
        + issued_at_ms.to_bytes(8, "big")
    )
    return hmac.new(_SIGNING_KEY, message, hashlib.sha256).digest()


@dataclass(frozen=True, slots=True)
class ScanResult:
    """The outcome of one `scan()` call. `verdict()` is the only place a
    `ScanVerdict` is constructed anywhere in the codebase."""

    passed: bool
    reasons: tuple[str, ...]
    content_hash: str
    suite_version: str

    def verdict(self, *, clock: Clock | None = None) -> ScanVerdict:
        """Mints a `ScanVerdict` bound to this exact `content_hash`.
        Raises `ScanRejected(self.reasons)` if the scan did not pass —
        there is no path from a failed scan to a verdict.

        `clock` is keyword-only and optional so the contract's `verdict()`
        call form is unchanged; it exists because the alternative was a raw
        `time.time_ns()`, which hard rule 5 forbids outside `SystemClock`."""
        if not self.passed:
            raise ScanRejected(self.reasons)
        verdict_id = uuid.uuid4()
        issued_at_ms = (clock or _DEFAULT_CLOCK).now_ms()
        sig = _sign(verdict_id, self.content_hash, self.suite_version, issued_at_ms)
        return ScanVerdict(
            verdict_id=verdict_id,
            content_hash=self.content_hash,
            suite_version=self.suite_version,
            issued_at_ms=issued_at_ms,
            sig=sig,
        )


def _dedupe(reasons: list[str]) -> tuple[str, ...]:
    """Order-preserving de-duplication.

    Not cosmetic. `secrets.find_high_entropy_tokens` emits one hit per distinct
    high-entropy token, so a candidate packed with them produced a `reasons`
    tuple whose length scaled with attacker-controlled input — and
    `persist_rejection` joins that tuple into a single `review_queue` reason
    column. De-duplicating bounds both by the size of the rule set."""
    seen: set[str] = set()
    out: list[str] = []
    for reason in reasons:
        if reason not in seen:
            seen.add(reason)
            out.append(reason)
    return tuple(out)


def scan(content: str, *, context: ScanContext) -> ScanResult:
    """Runs the injection-pattern scan, the secret scan, and the per-mem_type
    schema check, in that order. Pure function — no I/O, no repo import.
    `passed` is True iff every sub-scan produced zero reasons.

    Over-long content short-circuits to the ceiling rejection *before* any
    sub-scan runs. `scan()` sits on the synchronous write path and its input is
    attacker-shaped by construction (that is the whole premise of D-024), so
    the per-mem_type ceiling has to bound the regex and entropy work, not just
    describe it after the fact. The verdict is identical either way — the
    content is rejected — so this is a fail-closed short-circuit, never a skip.
    """
    if len(content) > _schema_check.max_content_chars(context.mem_type):
        return ScanResult(
            passed=False,
            reasons=(_schema_check.oversize_reason(context.mem_type),),
            content_hash=_content_hash(content),
            suite_version=SUITE_VERSION,
        )

    reasons: list[str] = []
    reasons.extend(hit.reason for hit in _patterns.scan_patterns(content))
    reasons.extend(hit.reason for hit in _secrets.scan_secrets(content))
    reasons.extend(_schema_check.check_schema(content, mem_type=context.mem_type))
    return ScanResult(
        passed=not reasons,
        reasons=_dedupe(reasons),
        content_hash=_content_hash(content),
        suite_version=SUITE_VERSION,
    )


def verify_verdict(verdict: ScanVerdict, expected_content_hash: str) -> None:
    """The repository calls this before every `memory_item` insert
    (PHASE0-CONTRACT.md §3.7 point 4). Raises `ScanVerdictForgery` on an
    HMAC mismatch (the verdict was not minted by this process/module) OR a
    content-hash mismatch (the verdict was minted for different content —
    "a verdict for content A does not verify against content B")."""
    expected_sig = _sign(verdict.verdict_id, verdict.content_hash, verdict.suite_version, verdict.issued_at_ms)
    if not hmac.compare_digest(expected_sig, verdict.sig):
        raise ScanVerdictForgery("scan verdict signature does not match this process's signing key")
    if verdict.content_hash != expected_content_hash:
        raise ScanVerdictForgery("scan verdict content_hash does not match the content being inserted")


class ReviewQueueWriter(Protocol):
    """Structurally satisfied by a bound `Repo.insert_review_item` (whose
    third parameter, `memory_id`, defaults to None) — passed in by the
    caller so this module never imports `stores.pg` (PHASE-0 Task 9)."""

    def __call__(self, project_id: ProjectId, reason: str) -> None: ...


def persist_rejection(result: ScanResult, *, context: ScanContext, writer: ReviewQueueWriter) -> None:
    """Persists a scan rejection to `review_queue` via a caller-supplied
    writer callable. No-op when `result.passed` — callers may call this
    unconditionally after every `scan()` without a branch."""
    if result.passed:
        return
    writer(context.project_id, "; ".join(result.reasons))
