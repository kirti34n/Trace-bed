"""ScanVerdict — the forgery-resistant proof that `core.scans` ran.

PHASE0-CONTRACT.md §3.7/C-06 and PLAN.md invariant 6 / D-024:
`Repo.insert_memory_item` refuses any write that does not present a
`ScanVerdict`, and the verdict itself must not be mintable by anything except
the scan suite — otherwise "every insert is scanned" degrades to "every
insert claims to be scanned". This module owns the token's *shape* and its
construction guard; it deliberately does NOT hold the signing key or the
verification function (those live in `core.scans`, per the contract, so that
`domain` stays a pure, key-free leaf and `stores.pg` only ever depends on
`core.scans.verify_verdict`, never reads the key itself).
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from types import FrameType
from typing import Final
from uuid import UUID

from tracebed.domain.errors import ScanVerdictForgery

__all__ = ["ScanVerdict"]

_ALLOWED_CALLER_MODULE_PREFIX = "tracebed.core.scans"

# §2 content_hash is a sha256 hex digest and §3.7's sig is HMAC-SHA256.
CONTENT_HASH_HEX_LEN: Final = 64
SIG_LEN: Final = 32
_HEX_DIGITS: Final = frozenset("0123456789abcdef")


def _guard_caller_module() -> None:
    """Reject construction from anywhere but the scan suite (PHASE0-CONTRACT.md §3.7 step 2).

    Walks the call stack outward past this module's own frames — the
    dataclass-generated `__init__` and this `__post_init__` are both defined
    in `tracebed.domain.scan`, so skipping frames whose `__name__` equals
    this module's own name lands on the actual instantiating module. Only a
    module whose name starts with `tracebed.core.scans` may proceed; every
    other caller (test code, a stray `ScanVerdict(...)` written by mistake in
    `stores.pg`, an attacker with code-execution but not import access to the
    scan suite's frame) raises `ScanVerdictForgery` instead of receiving a
    token that unblocks an insert.
    """
    frame: FrameType | None = sys._getframe(1)  # frame calling _guard_caller_module (__post_init__)
    while frame is not None and frame.f_globals.get("__name__") == __name__:
        frame = frame.f_back
    caller_module = frame.f_globals.get("__name__", "") if frame is not None else ""
    # Package-boundary check, not a bare string prefix: "tracebed.core.scans"
    # itself, or anything under it ("tracebed.core.scans.patterns", "..._authority").
    # A bare `startswith` would also accept an unrelated sibling module named
    # e.g. "tracebed.core.scansomething" — a real gap the contract's prose
    # ("starts with tracebed.core.scans") leaves open; this is the same set
    # for every legitimate caller and strictly smaller for everything else.
    is_allowed = caller_module == _ALLOWED_CALLER_MODULE_PREFIX or caller_module.startswith(
        _ALLOWED_CALLER_MODULE_PREFIX + "."
    )
    if not is_allowed:
        raise ScanVerdictForgery(
            f"ScanVerdict may only be constructed from "
            f"{_ALLOWED_CALLER_MODULE_PREFIX!r} (or a submodule); "
            f"got {caller_module or '<unknown>'!r}"
        )


@dataclass(frozen=True, slots=True)
class ScanVerdict:
    """Opaque proof-of-scan token (PHASE0-CONTRACT.md §3.7).

    `sig` is an HMAC-SHA256 over `verdict_id.bytes + content_hash.encode() +
    suite_version.encode() + issued_at_ms.to_bytes(8, "big")`, keyed by the
    process-local signing key in `core.scans._authority`. Verdicts are valid
    only within the process that minted them (Phase 0 scans and inserts
    always happen in the same process); recomputing and comparing that HMAC
    is `core.scans.verify_verdict`'s job, not this module's — this dataclass
    only carries the fields and enforces *where* it may be built.

    The ONLY legal constructor site is `core.scans.ScanResult.verdict()`.
    """

    verdict_id: UUID
    content_hash: str
    suite_version: str
    issued_at_ms: int
    sig: bytes

    def __post_init__(self) -> None:
        _guard_caller_module()
        self._check_shape()

    def _check_shape(self) -> None:
        """Reject structurally impossible verdicts at construction.

        Defence in depth behind the HMAC, aimed at two specific failure modes
        rather than at an attacker: (1) a caller passing raw content where a
        §2 `content_hash` belongs — `Repo.insert_memory_item` compares this
        field for string equality against `content_hash(item.content)`, so a
        non-canonical form (uppercase hex, the content itself) would surface
        as an unexplained `ScanVerdictForgery` deep in the write path rather
        than at the mistake; (2) a short or empty `sig`, which must never be
        constructible at all — `hmac.compare_digest` against a degenerate
        signature is exactly the comparison nobody wants to reason about.
        """
        if len(self.content_hash) != CONTENT_HASH_HEX_LEN or not _HEX_DIGITS.issuperset(
            self.content_hash
        ):
            raise ScanVerdictForgery(
                f"content_hash must be {CONTENT_HASH_HEX_LEN} lowercase hex characters"
            )
        if len(self.sig) != SIG_LEN:
            raise ScanVerdictForgery(f"sig must be {SIG_LEN} bytes of HMAC-SHA256")
        if not self.suite_version:
            raise ScanVerdictForgery("suite_version must be non-empty")
        if self.issued_at_ms < 0:
            raise ScanVerdictForgery("issued_at_ms must be non-negative")
