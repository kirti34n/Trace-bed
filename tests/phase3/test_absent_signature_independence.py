"""Red-team probe 5 (generalises probe 4): ABSENT_SIGNATURE must never win D-020's
distinct-cluster leg (BMAD-EVALUATION.md B5 / DECISIONS.md D-131).

`signatures.ABSENT_SIGNATURE` is `bytes(40)`, written by `ingest.trace_writer` for a run that
never sent a `run_start` (a sweeper fallback, C-07). Its trailing simhash of all zeros sits
~32 Hamming bits from a typical real signature -- well outside `SAME_CLUSTER_MAX_HAMMING` --
so `signatures.same_cluster`'s plain distance check, left alone, reads it as "obviously a
distinct cluster" from any real signature it is compared against. That is backwards: a run
whose input was never recorded is MISSING evidence, not evidence of a distinct input, and
letting it win the cluster leg for free is a Sybil bypass one absent `run_start` away from any
Sybil identity's second confirmation -- exactly the shape red-team probe 4
(`tests/phase3/test_independence.py::test_two_runs_in_the_same_real_cluster_are_one_confirmation`,
PLAN.md §7 Phase 3 gate probe 4, "correlated-trace corroboration") already guards against for
real-but-correlated signatures. This file is the same probe with the correlated wording
replaced by no wording at all.

FIX: `workers.independence.build_confirmations` -- the seam that turns a `run_id` into
evidence in the first place -- now excludes a resolved confirmation from its returned tuple
whenever `domain.signatures.is_absent_signature` (new: exact byte-equality with
`ABSENT_SIGNATURE`) is true, logging it at `INFO` first. `domain.signatures.same_cluster`
itself is DELIBERATELY LEFT UNCHANGED: `tests/phase0/test_signatures.py` (pre-existing,
committed, outside this chunk's file list) pins it as a pure Hamming-distance predicate --
`test_same_cluster_rejects_wrong_length` calls it with `ABSENT_SIGNATURE` as one argument and
a wrong-length value as the other and still requires the length `ValueError`, and
`test_same_cluster_at_the_threshold_boundary` uses `bytes(32) + (0).to_bytes(8, "big")`
(byte-identical to `ABSENT_SIGNATURE`) as an ordinary boundary-test signature and requires the
plain distance rule, not a forced match. A same-cluster special case was tried first and
reverted specifically because it broke those two tests; see D-131's "Alternatives considered"
for the full account.

PRINCIPAL-leg question the task also asks: is there an ABSENT_SIGNATURE-shaped sentinel for
`principal_id`? No, and `test_no_sentinel_principal_value_exists_for_the_principal_leg` below
is the structural proof, not an assumption: `trace_index.submitter_principal` is `uuid NOT
NULL` at the schema (`migrations/0002_partitioned.sql`), `stores.pg.rows.TraceIndexRow
.submitter_principal` is typed `PrincipalId`, never `PrincipalId | None`, and `ingest
.trace_writer._resolve_owner` always derives it from an authenticated envelope's
`principal_id` -- the lowest-`seq` envelope in the batch when no `run_start` exists, but
always a REAL principal, never a placeholder (`ingest/trace_writer.py:409-411`). There is no
"absent principal" value for a confirmation to carry, so no analogous fix is needed there.

SECOND FIX, D-136 (the audit pass): dropping an absent-signature row is right for CANDIDATE
EVIDENCE and wrong for a DISQUALIFYING REFERENCE SET, and `build_confirmations` is asked for
both. `workers.shadow_validator._resolve_confirmations` resolves the memory's own ORIGIN runs
solely in order to throw away confirmations correlated with them; silently deleting an
absent-signature origin from that set deletes the origin's authenticated PRINCIPAL from it
too, so a "confirmation" resubmitted under the origin's own identity stops being disqualified.
Measured, not theorised: a failure lesson (one confirmation is the whole bar) distilled from an
origin that never sent `run_start` was promoted out of quarantine by a self-replay under the
origin's own principal -- a case that refuses correctly when the origin's signature is real.
`build_confirmations` therefore takes `include_absent_signatures`, and `independent_of` fails
closed on the sentinel, so a kept origin disqualifies everything rather than nothing.

BOTH LEGS ARE NOW CLOSED (D-139, the integration pass). `workers.shadow_validator
._resolve_confirmations` passes `include_absent_signatures=True` on its ORIGIN-set call, so
`test_self_replay_of_an_absent_signature_origin_never_leaves_quarantine` below is an ordinary
passing test -- the `xfail(strict=True)` marker that tracked the missing call site is deleted,
which is what the marker's `strict=True` existed to force.

FIXTURE COLLISION, also closed in the same pass: `tests/phase3/test_independence.py`,
`test_shadow_validation.py` and `test_corroboration_writer.py` each defined an all-zero
`_CLUSTER_A` placeholder that was byte-identical to `ABSENT_SIGNATURE` and fed it through
`build_confirmations` as ordinary "cluster A" evidence, so eighteen of their tests went red
against the correct exclusion. All three now use a nonzero tail (`0x0000000000000001`, one bit
from zero and therefore still the same cluster as anything they previously called cluster A),
and `test_cluster_radius_boundary_is_inclusive_at_max_hamming` -- which never read `_CLUSTER_A`
and built its boundary pair off a hardcoded `_sig(0)` -- is anchored at `1 << 63`, which
preserves both Hamming distances exactly. `tests/phase0/test_state_machine.py` calls
`domain.state_machine.independent_confirmations`/`ShadowConfirmation` directly, bypassing
`build_confirmations` entirely, so it was never affected despite using the same placeholder.
"""

from __future__ import annotations

import dataclasses
import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from tracebed.domain.clock import FakeClock
from tracebed.domain.config import (
    AbstentionConfig,
    BudgetConfig,
    CacheConfig,
    DerivedConfig,
    EffectiveConfig,
    KillswitchConfig,
    LifecycleConfig,
    PromotionConfig,
    ProposalConfig,
    QueueConfig,
    RetirementConfig,
    RetrievalConfig,
    ScoreConfig,
    ScoringConfig,
    SessionConfig,
    SpendConfig,
    TierAConfig,
)
from tracebed.domain.enums import MemType, ProvenanceClass, TrustTier
from tracebed.domain.ids import AgentTypeId, MemoryId, PrincipalId, ProjectId, RunId
from tracebed.domain.memory import Provenance
from tracebed.domain.signatures import (
    ABSENT_SIGNATURE,
    SAME_CLUSTER_MAX_HAMMING,
    SIG_HASH_LEN,
    hamming,
    input_signature_hash,
    is_absent_signature,
    same_cluster,
)
from tracebed.domain.state_machine import ShadowConfirmation, Status
from tracebed.workers.epochs import ScoringEpoch
from tracebed.workers.independence import (
    ConfirmingRun,
    TracePrincipalLookupPort,
    build_confirmations,
    count_independent,
    independent_of,
)
from tracebed.workers.shadow_validator import (
    QuarantinedMemoryRow,
    ShadowTransitionWrite,
    ShadowValidator,
)

pytestmark = pytest.mark.phase3

PROJECT = ProjectId(UUID(int=1))
_REPO_ROOT = Path(__file__).resolve().parents[2]
_LOGGER_NAME = "tracebed.workers.independence"


def _run(tag: int) -> RunId:
    return RunId(UUID(int=tag))


def _principal(tag: int) -> PrincipalId:
    return PrincipalId(UUID(int=tag))


def _real_sig(cluster: int) -> bytes:
    """A real-shaped `SIG_HASH_LEN`-byte signature whose trailing 8 bytes are `cluster`,
    zero-padded -- same construction as `test_independence.py::_sig`, kept self-contained here
    rather than imported (this codebase's convention: a test file does not couple to another
    test file's fixtures, see `test_lifecycle_migration.py`'s module docstring).

    `cluster` must be nonzero: an all-zero 32-byte prefix plus an all-zero 8-byte tail is
    exactly `ABSENT_SIGNATURE`, and this helper's whole point is to build signatures that are
    NOT that -- see `test_no_real_fixture_in_this_file_collides_with_absent_signature`.
    """
    assert cluster != 0, "a zero cluster tag collides with ABSENT_SIGNATURE -- see docstring"
    return (b"\x00" * 32) + cluster.to_bytes(8, "big")


_CLUSTER_A = 0x0000000000000001
_CLUSTER_B = 0xFFFFFFFFFFFFFFFF


class _FakeLookup:
    """Stands in for a real `trace_index` read (`TracePrincipalLookupPort`)."""

    def __init__(self, table: dict[RunId, ConfirmingRun]) -> None:
        self._table = table

    def lookup(self, project_id: ProjectId, run_id: RunId) -> ConfirmingRun | None:
        return self._table.get(run_id)


# --------------------------------------------------------------------------- #
# Fixture hygiene: this file's own "real" signatures must not accidentally BE
# the sentinel, which is exactly the mistake this bug generalises from.
# --------------------------------------------------------------------------- #


def test_no_real_fixture_in_this_file_collides_with_absent_signature() -> None:
    assert _real_sig(_CLUSTER_A) != ABSENT_SIGNATURE
    assert _real_sig(_CLUSTER_B) != ABSENT_SIGNATURE


# --------------------------------------------------------------------------- #
# is_absent_signature is the exact-match sentinel test; same_cluster stays a
# pure Hamming-distance predicate, deliberately unaware of the sentinel.
# --------------------------------------------------------------------------- #


def test_absent_signature_is_its_own_length_so_it_is_never_dropped_for_shape() -> None:
    """Guards the guard: if ABSENT_SIGNATURE were ever anything other than exactly
    `SIG_HASH_LEN` bytes, `ShadowConfirmation.__post_init__` would reject it outright and
    every test below would be proving something vacuous."""
    assert len(ABSENT_SIGNATURE) == SIG_HASH_LEN


def test_is_absent_signature_matches_only_the_exact_sentinel() -> None:
    assert is_absent_signature(ABSENT_SIGNATURE) is True
    assert is_absent_signature(_real_sig(_CLUSTER_A)) is False
    assert is_absent_signature(_real_sig(_CLUSTER_B)) is False


def test_absent_signature_is_genuinely_far_by_the_plain_distance_check() -> None:
    """Documents WHY this needed a fix at all: ABSENT_SIGNATURE's trailing simhash (all
    zeros) really is ~32 Hamming bits from a typical real signature -- nowhere near
    `SAME_CLUSTER_MAX_HAMMING` -- so `same_cluster`'s plain distance check, left alone, calls
    it a distinct cluster on its own merits. That is exactly why the fix lives in
    `build_confirmations` (excluding it from evidence before it ever reaches `same_cluster`)
    rather than in `same_cluster` itself -- see the module docstring for the pre-existing
    tests that pin `same_cluster` against a special case."""
    real = _real_sig(_CLUSTER_B)
    assert hamming(0, int.from_bytes(real[-8:], "big")) >= 32


def test_same_cluster_is_not_special_cased_for_absent_signature() -> None:
    """Pin the negative: `same_cluster` must NOT treat ABSENT_SIGNATURE specially. Two
    all-zero trailing simhashes are Hamming-distance 0 apart, so this is `True` by the
    ORDINARY rule, exactly like `tests/phase0/test_signatures
    .py::test_same_cluster_at_the_threshold_boundary` relies on the same 40 zero bytes
    behaving as a perfectly normal signature value, not a sentinel `same_cluster` recognises."""
    assert same_cluster(ABSENT_SIGNATURE, ABSENT_SIGNATURE) is True
    # And still raises on a genuine shape defect, exactly as it does for any other input --
    # ABSENT_SIGNATURE on one side changes nothing about that.
    with pytest.raises(ValueError, match="40-byte"):
        same_cluster(ABSENT_SIGNATURE, b"short")


# --------------------------------------------------------------------------- #
# End to end through build_confirmations / count_independent -- the behaviours
# the task specifies.
# --------------------------------------------------------------------------- #


def test_two_absent_signature_confirmations_do_not_corroborate() -> None:
    """Two distinct runs, two distinct principals, BOTH carrying ABSENT_SIGNATURE (neither
    ever sent a `run_start`): independence must not reach 2. Both are excluded from
    `build_confirmations`'s output entirely, so the confirmation set actually handed to the
    clique search is empty."""
    table = {
        _run(1): ConfirmingRun(_run(1), _principal(1), ABSENT_SIGNATURE),
        _run(2): ConfirmingRun(_run(2), _principal(2), ABSENT_SIGNATURE),
    }
    lookup = _FakeLookup(table)
    assert count_independent(PROJECT, list(table.keys()), lookup) == 0
    assert build_confirmations(PROJECT, list(table.keys()), lookup) == ()


def test_one_absent_plus_one_real_does_not_reach_the_threshold_of_two() -> None:
    """The actual bypass the bug enabled: one run that never sent a `run_start` (free,
    attacker-reachable) beside one run with perfectly ordinary real evidence, distinct
    principals, distinct runs. Pre-fix this reached independence 2 -- a promotion-eligible
    "confirmation" bought for the cost of one missing `run_start`. Post-fix the absent one is
    excluded entirely, leaving a single real confirmation: independence caps at 1, the same
    way a real correlated-cluster pair does in red-team probe 4."""
    table = {
        _run(1): ConfirmingRun(_run(1), _principal(1), ABSENT_SIGNATURE),
        _run(2): ConfirmingRun(_run(2), _principal(2), _real_sig(_CLUSTER_A)),
    }
    lookup = _FakeLookup(table)
    assert count_independent(PROJECT, list(table.keys()), lookup) == 1


def test_two_genuinely_distinct_real_signatures_still_reach_two() -> None:
    """Control: the fix must not have collaterally damaged the genuine case. Two distinct
    runs, two distinct principals, two real signatures in genuinely distinct clusters -- this
    is exactly what shadow confirmation is supposed to let through."""
    table = {
        _run(1): ConfirmingRun(_run(1), _principal(1), _real_sig(_CLUSTER_A)),
        _run(2): ConfirmingRun(_run(2), _principal(2), _real_sig(_CLUSTER_B)),
    }
    lookup = _FakeLookup(table)
    assert count_independent(PROJECT, list(table.keys()), lookup) == 2


def test_a_third_real_confirmation_still_lifts_an_absent_pair_to_independent() -> None:
    """The absent-signature confirmation does not poison the rest of the set -- it is simply
    removed from consideration. Paired against two genuinely distinct real signatures (rather
    than against another absent one or the same real cluster), independence still reaches 2,
    proving the fix removes exactly one node from the graph and nothing else about how the
    remaining confirmations combine."""
    table = {
        _run(1): ConfirmingRun(_run(1), _principal(1), ABSENT_SIGNATURE),
        _run(2): ConfirmingRun(_run(2), _principal(2), _real_sig(_CLUSTER_A)),
        _run(3): ConfirmingRun(_run(3), _principal(3), _real_sig(_CLUSTER_B)),
    }
    lookup = _FakeLookup(table)
    assert count_independent(PROJECT, list(table.keys()), lookup) == 2


def test_every_run_absent_signature_caps_independence_at_zero() -> None:
    """A whole confirmation set where every run never sent a `run_start`: no amount of
    distinct principals turns absent evidence into corroboration -- every one of them is
    excluded, so the confirmation set the clique search ever sees is empty, matching
    `test_twenty_principals_one_cluster_never_reaches_two` in `test_independence.py`'s shape
    for the real-cluster case (there, capped at 1; here, at 0, because none of them are
    evidence at all)."""
    table = {_run(i): ConfirmingRun(_run(i), _principal(i), ABSENT_SIGNATURE) for i in range(1, 21)}
    lookup = _FakeLookup(table)
    assert count_independent(PROJECT, list(table.keys()), lookup) == 0


def test_absent_signature_confirmation_is_excluded_but_still_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Fail closed does not mean silently discarded. `build_confirmations` excludes an
    ABSENT_SIGNATURE confirmation from the tuple it returns (it cannot be handed over as
    evidence) but logs it at resolution time -- an operator does not have to know to query
    `trace_index` for all-zero signatures to notice that run-with-no-run_start traffic
    exists. Contrast with a wrong-LENGTH signature
    (`test_a_malformed_signature_corroborates_nothing_and_does_not_raise` in
    `test_independence.py`), which is dropped for a different reason (shape defect) and only
    logged at `WARNING`, not `INFO`."""
    table = {
        _run(1): ConfirmingRun(_run(1), _principal(1), ABSENT_SIGNATURE),
        _run(2): ConfirmingRun(_run(2), _principal(2), _real_sig(_CLUSTER_A)),
    }
    lookup = _FakeLookup(table)
    with caplog.at_level(logging.INFO, logger=_LOGGER_NAME):
        resolved = build_confirmations(PROJECT, list(table.keys()), lookup)

    assert [c.run_id for c in resolved] == [_run(2)]
    messages = [record.message for record in caplog.records]
    assert any(
        "ABSENT_SIGNATURE" in message and "run 00000000-0000-0000-0000-000000000001" in message
        for message in messages
    )


def test_absent_signature_confirmation_does_not_log_for_a_real_signature(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The log line is specific to ABSENT_SIGNATURE, not emitted for every resolved
    confirmation -- otherwise it would be noise an operator learns to ignore rather than a
    signal."""
    table = {_run(1): ConfirmingRun(_run(1), _principal(1), _real_sig(_CLUSTER_A))}
    lookup = _FakeLookup(table)
    with caplog.at_level(logging.INFO, logger=_LOGGER_NAME):
        resolved = build_confirmations(PROJECT, [_run(1)], lookup)

    assert len(resolved) == 1
    assert not any("ABSENT_SIGNATURE" in record.message for record in caplog.records)


class _AbsentSignatureLookup:
    """`TracePrincipalLookupPort` structural check plus a from-scratch resolve, so this file
    does not rely solely on the dict-backed `_FakeLookup` for the port contract."""

    def lookup(self, project_id: ProjectId, run_id: RunId) -> ConfirmingRun | None:
        return ConfirmingRun(run_id, _principal(run_id.value.int), ABSENT_SIGNATURE)


def test_port_is_structurally_a_trace_principal_lookup_port() -> None:
    assert isinstance(_AbsentSignatureLookup(), TracePrincipalLookupPort)


def test_lookup_still_runs_once_per_run_id_even_though_the_result_is_excluded() -> None:
    """Exclusion happens AFTER resolving, not instead of it -- `build_confirmations`'s
    existing dedup-before-lookup behaviour (`test_duplicate_run_id_counted_once` in
    `test_independence.py`) is unaffected by this fix; this just confirms the excluded path
    does not skip the lookup or double-count it."""
    calls: list[RunId] = []

    class _CountingLookup:
        def lookup(self, project_id: ProjectId, run_id: RunId) -> ConfirmingRun | None:
            calls.append(run_id)
            return ConfirmingRun(run_id, _principal(1), ABSENT_SIGNATURE)

    build_confirmations(PROJECT, [_run(1), _run(1), _run(1)], _CountingLookup())
    assert calls == [_run(1)]


# --------------------------------------------------------------------------- #
# The PRINCIPAL-leg question: does an equivalent sentinel exist? No -- proved
# structurally against the migration and the row type, not assumed.
# --------------------------------------------------------------------------- #


def test_no_sentinel_principal_value_exists_for_the_principal_leg() -> None:
    """`trace_index.submitter_principal` is `uuid NOT NULL` at the schema -- there is no
    column state an absent-`run_start` run (or any run) can be written with that reads as
    "no principal", the way `ABSENT_SIGNATURE` reads as "no signature". Read as text rather
    than asserted from memory, so a future migration that weakened this constraint would fail
    this test rather than silently reopening the same class of bug on the principal leg."""
    sql = (_REPO_ROOT / "migrations" / "0002_partitioned.sql").read_text(encoding="utf-8")
    match = re.search(r"submitter_principal\s+uuid\s+NOT NULL", sql)
    assert match is not None, (
        "trace_index.submitter_principal must stay `uuid NOT NULL` -- if this ever "
        "changes, ConfirmingRun/ShadowConfirmation.principal_id needs the same "
        "ABSENT_SIGNATURE-shaped fail-closed treatment this file gives the signature leg"
    )


def test_confirming_run_principal_id_is_typed_non_optional() -> None:
    """The Python-side half of the same claim: `ConfirmingRun.principal_id` (what
    `TracePrincipalLookupPort.lookup` hands back) is typed `PrincipalId`, never
    `PrincipalId | None` -- there is no annotation-level slot for an absent principal to
    occupy, unlike `input_signature_hash: bytes`, which happily accepts `ABSENT_SIGNATURE`
    because both are `bytes` of the same length."""
    field = next(f for f in dataclasses.fields(ConfirmingRun) if f.name == "principal_id")
    assert field.type == "PrincipalId"


# --------------------------------------------------------------------------- #
# D-136, part 1: the exclusion must be EXACT-SENTINEL, not "looks a bit like
# the sentinel". Two narrower predicates pass every test above while quietly
# striking real evidence off the record; these are the tests that kill them.
# --------------------------------------------------------------------------- #


def _genuine_signature(query_text: str) -> bytes:
    """A signature built by the production function, not hand-assembled.

    Every other fixture in this file (and in `test_independence.py`) fakes the 32-byte
    structured half as `b"\\x00" * 32`, which is fine for a Hamming test on the trailing
    bytes but useless for asking "does a REAL signature survive the sentinel check" -- a
    fake whose first 32 bytes are already the sentinel's first 32 bytes cannot answer that.
    """
    return input_signature_hash(
        agent_type_id=AgentTypeId(UUID(int=7)),
        query_text=query_text,
        workflow_template=None,
        tool_manifest=None,
    )


def test_a_real_signature_with_an_all_zero_simhash_tail_is_not_the_sentinel() -> None:
    """`simhash64("") == 0` BY CONSTRUCTION (`domain.signatures.simhash64`: "Empty text ->
    0"), so a run whose `run_start` recorded an empty `query_text` legitimately produces a
    real sha256 prefix beside eight zero bytes. It is fully recorded evidence and must
    corroborate normally.

    This is the test that kills the tempting `sig[-8:] == bytes(8)` form of
    `is_absent_signature` -- which passes every other test in this file, because every other
    fixture here has a nonzero tail, and would then silently delete real evidence for an
    entire class of legitimate run."""
    empty_query = _genuine_signature("")
    assert empty_query[-8:] == bytes(8)  # the tail really is all zeros
    assert empty_query != ABSENT_SIGNATURE  # ... and it is still not the sentinel
    assert is_absent_signature(empty_query) is False

    table = {
        _run(1): ConfirmingRun(_run(1), _principal(1), empty_query),
        _run(2): ConfirmingRun(_run(2), _principal(2), _genuine_signature("a real question")),
    }
    lookup = _FakeLookup(table)
    assert count_independent(PROJECT, list(table.keys()), lookup) == 2


def test_a_real_low_popcount_signature_is_not_the_sentinel() -> None:
    """Kills the other tempting form, `same_cluster(sig, ABSENT_SIGNATURE)`: a cluster-radius
    test swallows every real signature whose trailing popcount is <= SAME_CLUSTER_MAX_HAMMING
    (8 of 2^64 tails are within radius 8 of zero -- rare, but attacker-searchable by grinding
    `query_text`). Under that form, an attacker who wants a competitor's memory to STAY
    quarantined only has to get one confirming run submitted with a query whose simhash has a
    low popcount. Exact-sentinel equality is what makes evidence suppression impossible."""
    low_popcount_tail = (1 << SAME_CLUSTER_MAX_HAMMING) - 1
    near_sentinel = (b"\xab" * 32) + low_popcount_tail.to_bytes(8, "big")
    assert same_cluster(near_sentinel, ABSENT_SIGNATURE) is True  # within the cluster radius
    assert is_absent_signature(near_sentinel) is False  # ... but not the sentinel

    table = {
        _run(1): ConfirmingRun(_run(1), _principal(1), near_sentinel),
        _run(2): ConfirmingRun(_run(2), _principal(2), _real_sig(_CLUSTER_B)),
    }
    lookup = _FakeLookup(table)
    assert count_independent(PROJECT, list(table.keys()), lookup) == 2


def test_the_exclusion_log_is_exactly_info_not_a_promoted_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Pins the LEVEL, not just the text. `caplog.at_level(INFO)` captures WARNING too, so the
    existing log assertion above survives a silent promotion of this line to WARNING/ERROR --
    which matters because `test_independence.py` distinguishes the two cases by level: a
    wrong-LENGTH signature is a malformed row (WARNING, someone should look), an absent
    signature is an ordinary consequence of a run that never sent `run_start` (INFO, high
    volume, must not page anyone)."""
    lookup = _FakeLookup({_run(1): ConfirmingRun(_run(1), _principal(1), ABSENT_SIGNATURE)})
    with caplog.at_level(logging.DEBUG, logger=_LOGGER_NAME):
        build_confirmations(PROJECT, [_run(1)], lookup)

    absent_records = [r for r in caplog.records if "ABSENT_SIGNATURE" in r.message]
    assert [r.levelno for r in absent_records] == [logging.INFO]


# --------------------------------------------------------------------------- #
# D-136, part 2: dropping is right for EVIDENCE and wrong for a DISQUALIFYING
# reference set. `include_absent_signatures` + a fail-closed `independent_of`
# are the two halves that keep the origin-correlation filter working.
# --------------------------------------------------------------------------- #


def test_include_absent_signatures_keeps_the_row_for_a_disqualifying_reference_set() -> None:
    """`workers.shadow_validator._resolve_confirmations` resolves the memory's own ORIGIN runs
    for the sole purpose of throwing away anything correlated with them. Dropping an
    absent-signature origin deletes a node from THAT set, which is the unsafe direction:
    fewer confirmations can only refuse a promotion, fewer origins can only grant one."""
    lookup = _FakeLookup({_run(1): ConfirmingRun(_run(1), _principal(1), ABSENT_SIGNATURE)})
    assert build_confirmations(PROJECT, [_run(1)], lookup) == ()
    kept = build_confirmations(PROJECT, [_run(1)], lookup, include_absent_signatures=True)
    assert [c.run_id for c in kept] == [_run(1)]
    assert kept[0].input_signature_hash == ABSENT_SIGNATURE


def test_include_absent_signatures_does_not_disable_the_other_drop_rules() -> None:
    """The flag relaxes the ABSENT_SIGNATURE rule and nothing else -- a malformed (wrong
    length) row is still dropped, and an unresolvable run still contributes nothing, because
    those are shape/knowledge defects rather than the deliberate "no run_start" sentinel."""
    lookup = _FakeLookup(
        {
            _run(1): ConfirmingRun(_run(1), _principal(1), b"too-short"),
            _run(2): ConfirmingRun(_run(2), _principal(2), ABSENT_SIGNATURE),
        }
    )
    kept = build_confirmations(
        PROJECT, [_run(1), _run(2), _run(3)], lookup, include_absent_signatures=True
    )
    assert [c.run_id for c in kept] == [_run(2)]


def _confirmation(tag: int, principal: int, sig: bytes) -> ShadowConfirmation:
    return ShadowConfirmation(
        run_id=_run(tag), principal_id=_principal(principal), input_signature_hash=sig
    )


def test_independent_of_fails_closed_when_either_side_is_absent() -> None:
    """`same_cluster`'s plain distance rule answers "distinct cluster" for ABSENT_SIGNATURE vs
    any real signature (~32 bits apart), so the undefended `independent_of` calls a run with
    NO recorded input independent of one with a real input -- confidently, on the strength of
    the one leg it cannot actually evaluate. Its only caller is a disqualification test, where
    "cannot tell" must disqualify."""
    absent = _confirmation(1, 1, ABSENT_SIGNATURE)
    real = _confirmation(2, 2, _real_sig(_CLUSTER_B))
    assert same_cluster(absent.input_signature_hash, real.input_signature_hash) is False
    assert independent_of(absent, real) is False
    assert independent_of(real, absent) is False


def test_independent_of_is_unchanged_for_two_real_signatures() -> None:
    """Control for the previous test: the fail-closed clause is a pre-test on the sentinel, not
    a new definition of independence -- every real pair still gets exactly the guard's own
    answer (distinct run AND distinct principal AND distinct cluster)."""
    a = _confirmation(1, 1, _real_sig(_CLUSTER_A))
    same_principal = _confirmation(2, 1, _real_sig(_CLUSTER_B))
    same_cluster_other_principal = _confirmation(3, 2, _real_sig(_CLUSTER_A))
    genuinely_other = _confirmation(4, 2, _real_sig(_CLUSTER_B))
    assert independent_of(a, same_principal) is False
    assert independent_of(a, same_cluster_other_principal) is False
    assert independent_of(a, genuinely_other) is True


def test_a_kept_absent_origin_disqualifies_every_confirmation_it_is_compared_against() -> None:
    """The two halves composed, in the exact shape `_resolve_confirmations` uses them: resolve
    the origin set with `include_absent_signatures=True`, then keep only confirmations
    `independent_of` EVERY origin. An absent-signature origin disqualifies the lot -- nothing
    is known about the input the memory was distilled from, so nothing can be shown to be a
    genuinely new observation of it."""
    origin_lookup = _FakeLookup({_run(9): ConfirmingRun(_run(9), _principal(1), ABSENT_SIGNATURE)})
    origins = build_confirmations(PROJECT, [_run(9)], origin_lookup, include_absent_signatures=True)
    assert len(origins) == 1

    offered_lookup = _FakeLookup(
        {
            _run(1): ConfirmingRun(_run(1), _principal(1), _real_sig(_CLUSTER_A)),
            _run(2): ConfirmingRun(_run(2), _principal(2), _real_sig(_CLUSTER_B)),
        }
    )
    offered = build_confirmations(PROJECT, [_run(1), _run(2)], offered_lookup)
    survivors = [c for c in offered if all(independent_of(c, o) for o in origins)]
    assert survivors == []


# --------------------------------------------------------------------------- #
# The end-to-end route, through the worker that actually promotes. This is the
# leg the build-seam tests above cannot see, and the one D-136 found broken.
# --------------------------------------------------------------------------- #

_EPOCH = datetime(2026, 1, 1, tzinfo=UTC)
_ORIGIN_RUN = 99


def _cfg() -> EffectiveConfig:
    return EffectiveConfig(
        retrieval=RetrievalConfig(),
        abstention=AbstentionConfig(),
        score=ScoreConfig(),
        budget=BudgetConfig(),
        scoring=ScoringConfig(),
        promotion=PromotionConfig(),
        retirement=RetirementConfig(),
        lifecycle=LifecycleConfig(),
        derived=DerivedConfig(),
        proposals=ProposalConfig(),
        tier_a=TierAConfig(),
        killswitch=KillswitchConfig(),
        spend=SpendConfig(),
        cache=CacheConfig(),
        session=SessionConfig(),
        queue=QueueConfig(),
    )


class _StubRepo:
    def __init__(self, rows: list[QuarantinedMemoryRow]) -> None:
        self._rows = rows
        self.persisted: list[ShadowTransitionWrite] = []

    def select_quarantined(self, project_id: ProjectId) -> list[QuarantinedMemoryRow]:
        return self._rows

    def persist(self, project_id: ProjectId, write: ShadowTransitionWrite) -> None:
        self.persisted.append(write)


_EPOCH_ROW = ScoringEpoch(
    epoch_id=7,
    judge_model_id="gemini-3.1-pro",
    judge_model_version="2026-07-01",
    sampling_params={"temperature": 0},
    prompt_hash="deadbeef",
    started_at=_EPOCH,
)


def _self_replay_case(
    origin_signature: bytes,
) -> tuple[_StubRepo, QuarantinedMemoryRow, _FakeLookup]:
    """A failure lesson (`promotion.failure_lesson_outcomes` == 1, so ONE confirmation is the
    whole bar) distilled from origin run 99, submitted by principal 1. Its single offered
    confirmation is a fresh run submitted by THE SAME principal 1 -- a self-replay, which
    D-020 says is the same observation again and must never clear quarantine."""
    table = {
        _run(_ORIGIN_RUN): ConfirmingRun(_run(_ORIGIN_RUN), _principal(1), origin_signature),
        _run(5): ConfirmingRun(_run(5), _principal(1), _real_sig(_CLUSTER_B)),
    }
    row = QuarantinedMemoryRow(
        id=MemoryId(UUID(int=1)),
        project_id=PROJECT,
        status=Status.QUARANTINED,
        trust_tier=TrustTier.B,
        mem_type=MemType.LESSON,
        provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(_run(_ORIGIN_RUN),)),
        status_changed_at=_EPOCH,
        is_failure_lesson=True,
        confirming_run_ids=(_run(5),),
    )
    repo = _StubRepo([row])
    return repo, row, _FakeLookup(table)


def test_self_replay_of_a_real_origin_never_leaves_quarantine() -> None:
    """The control, and red-team probe 4's n=1 form: when the origin run HAS a real signature,
    the origin-correlation filter sees a shared principal and discards the replay."""
    repo, row, lookup = _self_replay_case(_real_sig(_CLUSTER_A))
    validator = ShadowValidator(repo, FakeClock(_EPOCH), lookup, _EPOCH_ROW)
    outcome = validator.evaluate_one(PROJECT, row, cfg=_cfg())
    assert outcome.promoted is False
    assert outcome.independent_count == 0
    assert repo.persisted == []


def test_self_replay_of_an_absent_signature_origin_never_leaves_quarantine() -> None:
    """The same self-replay, with the only change being that the origin run never sent a
    `run_start`. That is attacker-reachable for free -- omit one event -- and it must not
    change the verdict."""
    repo, row, lookup = _self_replay_case(ABSENT_SIGNATURE)
    validator = ShadowValidator(repo, FakeClock(_EPOCH), lookup, _EPOCH_ROW)
    outcome = validator.evaluate_one(PROJECT, row, cfg=_cfg())
    assert outcome.promoted is False
    assert repo.persisted == []
