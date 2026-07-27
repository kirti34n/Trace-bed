"""Input-signature hashing and SimHash clustering (PHASE0-CONTRACT.md §3.8).

Backs shadow-confirmation independence (PLAN.md invariant 7 / D-020):
"independent" corroboration requires distinct authenticated principals AND
distinct input-signature clusters. Without a real near-duplicate detector,
"independent" degrades to "submitted twice" — a two-call Sybil bypass
(GovMem measured naive counting at a 0.597 false-promotion rate). This module
is the offline-testable half of that guarantee; `domain.state_machine`
consumes `same_cluster`/`hamming` through `independent_confirmations`.
"""

from __future__ import annotations

import hashlib
import unicodedata
from collections.abc import Sequence
from typing import TYPE_CHECKING, Final

from tracebed.domain.canonical import canonical_json

if TYPE_CHECKING:
    from tracebed.domain.ids import AgentTypeId

__all__ = [
    "ABSENT_SIGNATURE",
    "MAX_TOOL_MANIFEST_ENTRIES",
    "SAME_CLUSTER_MAX_HAMMING",
    "SIG_HASH_LEN",
    "SIMHASH_HEAD_CHARS",
    "hamming",
    "input_signature_hash",
    "is_absent_signature",
    "same_cluster",
    "simhash64",
]

SIMHASH_HEAD_CHARS: Final = 512
SAME_CLUSTER_MAX_HAMMING: Final = 8  # D-020
SIG_HASH_LEN: Final = 40  # 32 sha256 bytes + 8 simhash bytes
ABSENT_SIGNATURE: Final = bytes(40)  # C-07: run with no run_start (sweeper fallback)

# Both inputs to `input_signature_hash` arrive from an attacker-controllable
# `run_start` payload (`payload: dict[str, Any]`, C-05) on the ingest write
# path. Neither is bounded by anything upstream, so the bound lives here:
# without it a single trace event sizes the work this function does.
MAX_TOOL_MANIFEST_ENTRIES: Final = 512
_MAX_TOOL_ID_CHARS: Final = 256
# Generous pre-slice before NFC-normalising `query_text`: normalisation and
# casefolding allocate proportionally to the whole string, but only the first
# SIMHASH_HEAD_CHARS characters can ever reach the shingler. 64x headroom
# means whitespace collapsing still has far more material than it can use.
_MAX_NORMALISE_CHARS: Final = SIMHASH_HEAD_CHARS * 64

_SHINGLE_SIZE: Final = 3


def _char_shingles(text: str, size: int) -> list[str]:
    """DISTINCT 3-gram character shingles. Text shorter than `size` yields the whole text.

    Distinct, not multiset — this is a security property, not a micro-optimisation.
    With per-occurrence votes, a long run of one repeated character contributes
    hundreds of identical votes and dominates the whole signature. Measured on
    the current corpus: two submissions of the *same* sentence padded with
    "a" * 400 vs "b" * 400 landed 26 bits apart (two "independent" clusters),
    while two *different* sentences sharing a "y" * 100 tail landed 0 bits
    apart (one cluster). Both are backwards, and the first is the one that
    matters: it is a one-line Sybil bypass of D-020's distinct-cluster half of
    shadow confirmation (invariant 7). Deduplicating caps any repeated filler
    at a single vote, which moves those same pairs to 4 and 33 bits.

    Sorted for reproducibility under a randomised PYTHONHASHSEED; the vote sum
    is order-independent anyway, so this costs nothing and removes the question.
    """
    if len(text) < size:
        return [text] if text else []
    return sorted({text[i : i + size] for i in range(len(text) - size + 1)})


def simhash64(text: str) -> int:
    """64-bit SimHash over 3-gram character shingles of a normalised text head.

    PHASE0-CONTRACT.md §3.8: NFC-normalised, casefolded, whitespace-collapsed
    first `SIMHASH_HEAD_CHARS` characters; per-shingle hash = first 8 bytes
    (big-endian) of sha256(shingle). Shingles are counted once each, not per
    occurrence — see `_char_shingles` for why that is load-bearing. Bit-voting
    over shingle hashes makes
    near-duplicate free text (typo, reordered clause, different whitespace)
    land within a small Hamming distance of each other while unrelated text
    does not — that gap is what `same_cluster` thresholds on. Empty text -> 0.

    Work is bounded by `_MAX_NORMALISE_CHARS` before any allocation-heavy
    Unicode pass runs: `query_text` is attacker-supplied off a `run_start`
    payload, and normalising a multi-megabyte string to derive 512 characters
    of signal is an unbounded allocation on the ingest write path.
    """
    normalized = unicodedata.normalize("NFC", text[:_MAX_NORMALISE_CHARS]).casefold()
    normalized = " ".join(normalized.split())  # whitespace-collapse
    head = normalized[:SIMHASH_HEAD_CHARS]
    if not head:
        return 0

    shingles = _char_shingles(head, _SHINGLE_SIZE)
    bit_votes = [0] * 64
    for shingle in shingles:
        digest = hashlib.sha256(shingle.encode("utf-8")).digest()[:8]
        h = int.from_bytes(digest, "big")
        for bit in range(64):
            if (h >> bit) & 1:
                bit_votes[bit] += 1
            else:
                bit_votes[bit] -= 1

    result = 0
    for bit in range(64):
        if bit_votes[bit] > 0:
            result |= 1 << bit
    return result


def hamming(a: int, b: int) -> int:
    """Hamming distance between two 64-bit (or arbitrary-width) integers."""
    return (a ^ b).bit_count()


def _trailing_simhash(sig: bytes) -> int:
    if len(sig) != SIG_HASH_LEN:
        raise ValueError(f"expected a {SIG_HASH_LEN}-byte signature, got {len(sig)} bytes")
    return int.from_bytes(sig[-8:], "big")


def same_cluster(a: bytes, b: bytes) -> bool:
    """Two SIG_HASH_LEN signatures are the same cluster iff their trailing
    8 simhash bytes are within SAME_CLUSTER_MAX_HAMMING (D-020). This is the
    authoritative membership test that `state_machine.independent_confirmations`
    uses to reject two same-wording submissions from counting as independent.

    Deliberately unaware of `ABSENT_SIGNATURE` (BMAD B5 / D-131): this is a pure
    Hamming-distance predicate over any two `SIG_HASH_LEN` byte strings, and
    `tests/phase0/test_signatures.py` pins that contract directly --
    `test_same_cluster_rejects_wrong_length` calls this with `ABSENT_SIGNATURE` as one
    argument and a wrong-length value as the other and still requires the length
    `ValueError`, and `test_same_cluster_at_the_threshold_boundary` uses the same 40
    zero bytes as an ordinary boundary-test signature and requires the plain distance
    rule, not a forced match, against a far-away one. Whether a signature is evidence
    AT ALL -- as opposed to "are these two clusters near each other" -- is answered by
    `is_absent_signature`, and by the one caller that turns a `run_id` into evidence in
    the first place (`workers.independence.build_confirmations`), never by this
    function, which must keep meaning exactly "Hamming distance <= the radius" for
    every existing caller.
    """
    return hamming(_trailing_simhash(a), _trailing_simhash(b)) <= SAME_CLUSTER_MAX_HAMMING


def is_absent_signature(sig: bytes) -> bool:
    """True iff `sig` is exactly the `ABSENT_SIGNATURE` sentinel (BMAD B5 / D-131).

    The fail-closed test `workers.independence.build_confirmations` runs BEFORE
    counting a resolved signature as evidence at all: a run with no `run_start` is
    missing evidence, not a signature that happens to hash into its own distinct
    cluster, and it must never be allowed to win the distinct-input-signature-cluster
    leg of D-020 by virtue of being maximally far (in Hamming terms) from everything
    real. `input_signature_hash` derives 32 of these 40 bytes from `hashlib.sha256`,
    so a genuine signature landing on all-zero has probability ~2^-256 --
    indistinguishable from never, in this system's threat model.

    Equality over all `SIG_HASH_LEN` bytes, deliberately -- NOT a test on the trailing
    8 simhash bytes alone, and NOT `same_cluster(sig, ABSENT_SIGNATURE)`. Both narrower
    forms look equivalent and are not: `simhash64("") == 0` by construction, so a run
    whose `run_start` recorded an EMPTY `query_text` produces a real sha256 prefix beside
    an all-zero tail, and a cluster-radius form additionally swallows every real
    signature whose tail popcount is <= SAME_CLUSTER_MAX_HAMMING. Either would silently
    strike genuine evidence off the record as "no run_start was ever recorded" -- turning
    a fail-closed guard against a Sybil bypass into a way to suppress a competitor's
    corroboration by feeding it a low-popcount query.
    """
    return sig == ABSENT_SIGNATURE


def _normalise_tool_manifest(tool_manifest: Sequence[str] | None) -> list[str]:
    """Validate and sort the attacker-supplied tool manifest (C-05 / §3.8).

    `tool_manifest` reaches this module out of `run_start.payload`, which is
    `dict[str, Any]` — the static `Sequence[str]` annotation is a promise the
    wire cannot keep. Three concrete failures this rejects rather than hashes:
    a bare `str` (itself a `Sequence[str]`, so `sorted()` would silently
    signature its *characters*), non-`str` elements (`sorted()` either raises
    an unexpected `TypeError` deep inside the ingest consumer or, for a
    homogeneous list of ints, produces a plausible-looking signature from
    type-confused input), and an unbounded entry count.
    """
    if tool_manifest is None:
        return []
    if isinstance(tool_manifest, str | bytes):
        raise ValueError(
            "input_signature_hash: tool_manifest must be a sequence of str, not a string"
        )
    entries = list(tool_manifest)
    if len(entries) > MAX_TOOL_MANIFEST_ENTRIES:
        raise ValueError(
            f"input_signature_hash: tool_manifest has {len(entries)} entries, "
            f"limit is {MAX_TOOL_MANIFEST_ENTRIES}"
        )
    for entry in entries:
        if not isinstance(entry, str):
            raise ValueError(
                f"input_signature_hash: tool_manifest entries must be str, got {type(entry).__name__}"
            )
        if len(entry) > _MAX_TOOL_ID_CHARS:
            raise ValueError(
                f"input_signature_hash: tool_manifest entry exceeds {_MAX_TOOL_ID_CHARS} characters"
            )
    return sorted(entries)


def input_signature_hash(
    *,
    agent_type_id: AgentTypeId,
    query_text: str,
    workflow_template: str | None,
    tool_manifest: Sequence[str] | None,
) -> bytes:
    """The exact feature set (PHASE0-CONTRACT.md §3.8/C-07).

    sha256(canonical_json({agent_type, workflow_template, sorted tool_manifest}))
    concatenated with simhash64(query_text) as 8 big-endian bytes — always
    SIG_HASH_LEN (40) bytes. Depends only on the C-05 run_start payload keys,
    never on event order or arrival timing, so `ingest.trace_writer` computes
    the same signature whether events replay in order or not (Task 14's
    reordering-stability test).

    Raises ValueError on a tool_manifest this module refuses to hash (see
    `_normalise_tool_manifest`) — the caller on the ingest path turns that
    into a rejected/dead-lettered event, never a silently wrong signature.
    """
    features = {
        "agent_type": str(agent_type_id),
        "workflow_template": workflow_template or "",
        "tool_manifest": _normalise_tool_manifest(tool_manifest),
    }
    structured = hashlib.sha256(canonical_json(features)).digest()  # always 32 bytes
    free_text = simhash64(query_text).to_bytes(8, "big")  # always 8 bytes
    return structured + free_text
