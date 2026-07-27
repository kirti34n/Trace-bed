"""`workers.independence` — the computable shadow-confirmation definition (D-020).

Fully offline: `_FakeLookup` is an in-file fake (this codebase's convention, contract
§13.1) standing in for a real `trace_index` read. Every test here proves the same point
GovMem's 0.597 false-promotion measurement names: counting *runs* or *principals* alone
overstates independence, and only the pairwise (distinct run, distinct principal, distinct
cluster) definition gets it right.
"""

from __future__ import annotations

import hashlib
from uuid import UUID

import pytest

from tracebed.domain.errors import TracebedError
from tracebed.domain.ids import AgentTypeId, PrincipalId, ProjectId, RunId
from tracebed.domain.signatures import (
    SAME_CLUSTER_MAX_HAMMING,
    hamming,
    input_signature_hash,
    same_cluster,
    simhash64,
)
from tracebed.workers.independence import (
    MAX_CONFIRMATIONS_CONSIDERED,
    ConfirmingRun,
    TracePrincipalLookupPort,
    build_confirmations,
    count_independent,
)

pytestmark = pytest.mark.phase3

PROJECT = ProjectId(UUID(int=1))


def _run(tag: int) -> RunId:
    return RunId(UUID(int=tag))


def _principal(tag: int) -> PrincipalId:
    return PrincipalId(UUID(int=tag))


def _sig(cluster: int) -> bytes:
    """A `SIG_HASH_LEN`-byte signature whose trailing 8 bytes (the cluster half,
    `domain.signatures.same_cluster`) are exactly `cluster`, zero-padded. Two different
    `cluster` values 64 bits apart in Hamming distance (0x00.. vs 0xFF..) land far outside
    `SAME_CLUSTER_MAX_HAMMING` (8), i.e. definitely distinct clusters; the same `cluster`
    value is definitionally the same cluster (Hamming 0).
    """
    return (b"\x00" * 32) + cluster.to_bytes(8, "big")


# NOT 0: `_sig(0)` is `bytes(40)`, which IS `domain.signatures.ABSENT_SIGNATURE`. Since D-131
# `build_confirmations` drops that value as "no `run_start` was ever recorded" rather than
# resolving it as ordinary evidence, so a fixture built on it would be testing the sentinel path
# while claiming to test cluster arithmetic. 1 is one bit from 0 -- well inside
# `SAME_CLUSTER_MAX_HAMMING`, so every "same cluster" claim this constant backs still holds --
# and is not the sentinel.
_CLUSTER_A = 0x0000000000000001
_CLUSTER_B = 0xFFFFFFFFFFFFFFFF


def _far_cluster(tag: int) -> int:
    """A 64-bit cluster id pairwise FAR from every other `_far_cluster` value.

    Small integers (0, 1, 2, ... 19) are NOT distinct clusters: they differ in at most 5
    bits, well inside `SAME_CLUSTER_MAX_HAMMING` (8). A fixture that used them while
    claiming "twenty distinct clusters" would be satisfied by the cluster check alone, so
    the principal half of D-020 could be deleted outright and the test would stay green --
    which is exactly what a mutation run found. Hashing spreads the values across the
    64-bit space; `test_far_clusters_really_are_distinct_clusters` proves it rather than
    assuming it.
    """
    return int.from_bytes(hashlib.sha256(f"cluster:{tag}".encode()).digest()[:8], "big")


class _FakeLookup:
    """Stands in for a real `trace_index` read (`TracePrincipalLookupPort`)."""

    def __init__(self, table: dict[RunId, ConfirmingRun]) -> None:
        self._table = table
        self.calls: list[RunId] = []

    def lookup(self, project_id: ProjectId, run_id: RunId) -> ConfirmingRun | None:
        self.calls.append(run_id)
        return self._table.get(run_id)


class _MismatchedLookup:
    """A broken port: always answers for a DIFFERENT run than the one asked about."""

    def lookup(self, project_id: ProjectId, run_id: RunId) -> ConfirmingRun | None:
        return ConfirmingRun(
            run_id=_run(999_999), principal_id=_principal(1), input_signature_hash=_sig(_CLUSTER_A)
        )


def test_far_clusters_really_are_distinct_clusters() -> None:
    """Guards the guard: every Sybil test below leans on `_far_cluster` values being
    pairwise distinct clusters. If they were not, those tests would pass on the cluster
    check alone and would say nothing about principals."""
    values = [_far_cluster(i) for i in range(20)]
    closest = min(hamming(a, b) for i, a in enumerate(values) for b in values[i + 1 :])
    assert closest > SAME_CLUSTER_MAX_HAMMING


def test_twenty_runs_one_principal_never_reaches_two() -> None:
    """A single Sybil identity replaying many runs: one principal, twenty runs, all
    pairwise-distinct clusters (`_far_cluster`, not small ints -- see its docstring).
    Independence caps at 1 no matter how many runs pile up, and it is the PRINCIPAL check
    doing the capping: nothing else in the fixture would."""
    table = {
        _run(i): ConfirmingRun(_run(i), _principal(1), _sig(_far_cluster(i)))
        for i in range(20)
    }
    lookup = _FakeLookup(table)
    count = count_independent(PROJECT, list(table.keys()), lookup)
    assert count == 1


def test_twenty_principals_one_cluster_never_reaches_two() -> None:
    """Twenty distinct authenticated principals, but every one submitted the same
    (near-duplicate) wording — one input-signature cluster. Distinct principals alone is
    not corroboration; the cluster half of D-020 exists exactly to catch this."""
    table = {
        _run(i): ConfirmingRun(_run(i), _principal(i), _sig(_CLUSTER_A)) for i in range(20)
    }
    lookup = _FakeLookup(table)
    count = count_independent(PROJECT, list(table.keys()), lookup)
    assert count == 1


def test_two_principals_two_clusters_reach_two() -> None:
    """The genuine case: two runs, two distinct principals, two distinct clusters."""
    table = {
        _run(1): ConfirmingRun(_run(1), _principal(1), _sig(_CLUSTER_A)),
        _run(2): ConfirmingRun(_run(2), _principal(2), _sig(_CLUSTER_B)),
    }
    lookup = _FakeLookup(table)
    count = count_independent(PROJECT, list(table.keys()), lookup)
    assert count == 2


def test_missing_trace_index_row_contributes_nothing() -> None:
    """A `run_id` a memory's provenance names but that never produced a `trace_index` row
    (proposal referencing an in-flight run, a replay artifact) must not be manufactured
    into a confirmation — the fail-closed direction invariant 7 requires."""
    table = {
        _run(1): ConfirmingRun(_run(1), _principal(1), _sig(_CLUSTER_A)),
    }
    lookup = _FakeLookup(table)
    count = count_independent(PROJECT, [_run(1), _run(2)], lookup)
    assert count == 1
    # Both run ids were still looked up -- absence is not skipped over silently.
    assert set(lookup.calls) == {_run(1), _run(2)}


def test_duplicate_run_id_counted_once() -> None:
    table = {_run(1): ConfirmingRun(_run(1), _principal(1), _sig(_CLUSTER_A))}
    lookup = _FakeLookup(table)
    confirmations = build_confirmations(PROJECT, [_run(1), _run(1), _run(1)], lookup)
    assert len(confirmations) == 1
    # The lookup itself only ran once -- deduping happens before resolving, not after.
    assert lookup.calls == [_run(1)]


def test_lookup_returning_a_different_run_raises_tracebed_error() -> None:
    with pytest.raises(TracebedError):
        build_confirmations(PROJECT, [_run(1)], _MismatchedLookup())


@pytest.mark.parametrize("at_least", [1, 2, 3, 4])
@pytest.mark.parametrize("independent_runs", [1, 3])
def test_at_least_never_changes_a_threshold_decision(
    at_least: int, independent_runs: int
) -> None:
    """The only property callers may rely on from the `at_least` hint.

    `independent_confirmations` may stop as soon as the answer is known to clear the
    threshold, so the number it returns is NOT always the true maximum -- and it is not
    capped at `at_least` either (Bron-Kerbosch reports the first maximal clique it
    completes, which can be larger). What must never change is the `>=` decision every
    caller makes with it. Asserted as an equivalence rather than on the returned integer,
    because pinning the integer would pin the search order, which is an implementation
    detail of the clique walk.
    """
    table = {
        _run(i): ConfirmingRun(
            _run(i),
            _principal(i if independent_runs > 1 else 1),
            _sig(_far_cluster(i) if independent_runs > 1 else _CLUSTER_A),
        )
        for i in range(3)
    }
    runs = list(table.keys())

    exact = count_independent(PROJECT, runs, _FakeLookup(table))
    hinted = count_independent(PROJECT, runs, _FakeLookup(table), at_least=at_least)

    assert exact == independent_runs
    assert (hinted >= at_least) is (exact >= at_least)


def test_empty_run_ids_are_zero_confirmations() -> None:
    lookup = _FakeLookup({})
    assert count_independent(PROJECT, [], lookup) == 0
    assert build_confirmations(PROJECT, [], lookup) == ()


def test_port_is_structurally_a_trace_principal_lookup_port() -> None:
    assert isinstance(_FakeLookup({}), TracePrincipalLookupPort)


def test_lookup_count_is_bounded_by_max_confirmations_considered() -> None:
    """The confirmation list is attacker-influenced: anything that can append a run id to a
    memory's `shadow_confirm_runs` sizes the number of `trace_index` reads this performs.
    The bound is applied BEFORE resolving, so it bounds I/O and not merely the clique
    search -- and truncation can only ever lower the independence count, never raise it."""
    n = MAX_CONFIRMATIONS_CONSIDERED + 50
    table = {
        _run(i): ConfirmingRun(_run(i), _principal(i), _sig(_far_cluster(i))) for i in range(n)
    }
    lookup = _FakeLookup(table)

    confirmations = build_confirmations(PROJECT, list(table.keys()), lookup)

    assert len(lookup.calls) == MAX_CONFIRMATIONS_CONSIDERED
    assert len(confirmations) == MAX_CONFIRMATIONS_CONSIDERED


# --------------------------------------------------------------------------- #
# The cluster radius itself (D-020: 64-bit SimHash, Hamming <= 8 = same cluster).
# Computed from real `domain.signatures` output, not from hand-built byte
# patterns: the whole question is whether the radius sits in the gap between
# "reworded" and "unrelated", and a synthetic signature cannot answer it.
# --------------------------------------------------------------------------- #

_BASE_QUERY = "the payment tool returned a 503 timeout when charging the customer account"
_REWORDINGS = [
    "the payment tool returned a 503 timeout when charging the customer acount",  # typo
    "The payment tool returned a 503 timeout when charging the customer account.",  # case/punct
    "the payment tool returned  a 503 timeout when charging the  customer account",  # whitespace
    "the payment tool returned a 503 timeout while charging the customer account",  # one word
]
_UNRELATED = [
    "summarise the quarterly revenue report for the north america region",
    "reconcile the vendor invoice against purchase order 4471 and flag mismatches",
    "list every open incident assigned to the on-call rotation this week",
]


def _real_sig(query_text: str) -> bytes:
    return input_signature_hash(
        agent_type_id=AgentTypeId(UUID(int=7)),
        query_text=query_text,
        workflow_template=None,
        tool_manifest=["payments.charge"],
    )


@pytest.mark.parametrize("reworded", _REWORDINGS)
def test_trivial_rewording_is_not_a_distinct_cluster(reworded: str) -> None:
    """The narrow-radius failure: if a typo, a capital letter, or one swapped word bought a
    fresh cluster, D-020's distinct-cluster half would be satisfiable by find-and-replace
    and shadow confirmation would degrade to "submitted twice with different spelling"."""
    assert same_cluster(_real_sig(_BASE_QUERY), _real_sig(reworded))


@pytest.mark.parametrize("unrelated", _UNRELATED)
def test_unrelated_queries_are_distinct_clusters(unrelated: str) -> None:
    """The wide-radius failure, and the more damaging one: if unrelated inputs collapsed
    into one cluster, genuinely independent corroboration would be discarded and nothing
    content-derived could ever leave quarantine."""
    assert not same_cluster(_real_sig(_BASE_QUERY), _real_sig(unrelated))


def test_the_radius_sits_in_the_gap_between_reworded_and_unrelated() -> None:
    """Not just "each side lands correctly" but "there is daylight either way": the worst
    rewording must sit strictly below the threshold and the best unrelated pair strictly
    above it, or the two populations are only separated by the fixtures chosen here."""
    base = simhash64(_BASE_QUERY)
    worst_rewording = max(hamming(base, simhash64(text)) for text in _REWORDINGS)
    closest_unrelated = min(hamming(base, simhash64(text)) for text in _UNRELATED)

    assert worst_rewording <= SAME_CLUSTER_MAX_HAMMING
    assert closest_unrelated > SAME_CLUSTER_MAX_HAMMING
    assert closest_unrelated - worst_rewording >= 8  # daylight, not a coin-flip boundary


def test_cluster_radius_boundary_is_inclusive_at_max_hamming() -> None:
    """The radius itself, from both sides of the fence.

    `same_cluster` is `hamming <= SAME_CLUSTER_MAX_HAMMING`, so a pair at EXACTLY the
    threshold is one cluster (one confirmation) and a pair one bit further apart is two.
    Without this, an off-by-one in either direction — `<` instead of `<=`, or a radius read
    one too wide — is invisible: every other fixture in this file sits tens of bits from the
    boundary and would keep passing.
    """
    # The anchor is the high bit, not 0: `_sig(0)` is `ABSENT_SIGNATURE`, which
    # `build_confirmations` drops entirely (D-131), so a boundary pair anchored there would
    # measure the sentinel path instead of the radius. XOR-ing the offsets into a bit no
    # offset touches preserves both Hamming distances exactly.
    anchor = 1 << 63
    at_radius = (1 << SAME_CLUSTER_MAX_HAMMING) - 1  # exactly SAME_CLUSTER_MAX_HAMMING bits
    just_outside = (1 << (SAME_CLUSTER_MAX_HAMMING + 1)) - 1  # one more bit
    assert hamming(anchor, anchor | at_radius) == SAME_CLUSTER_MAX_HAMMING
    assert hamming(anchor, anchor | just_outside) == SAME_CLUSTER_MAX_HAMMING + 1

    inside = {
        _run(1): ConfirmingRun(_run(1), _principal(1), _sig(anchor)),
        _run(2): ConfirmingRun(_run(2), _principal(2), _sig(anchor | at_radius)),
    }
    assert count_independent(PROJECT, list(inside.keys()), _FakeLookup(inside)) == 1

    outside = {
        _run(1): ConfirmingRun(_run(1), _principal(1), _sig(anchor)),
        _run(2): ConfirmingRun(_run(2), _principal(2), _sig(anchor | just_outside)),
    }
    assert count_independent(PROJECT, list(outside.keys()), _FakeLookup(outside)) == 2


def test_a_malformed_signature_corroborates_nothing_and_does_not_raise() -> None:
    """`ShadowConfirmation.__post_init__` raises a bare `ValueError` on a wrong-length
    signature, and that is not a `TracebedError`. If it escaped here, one malformed
    `trace_index` row would abort the whole sweep — every other quarantined memory in the
    project would stop being evaluated — instead of merely failing to corroborate. The
    usable confirmation beside it must still be counted."""

    class _PartlyMalformedLookup:
        def lookup(self, project_id: ProjectId, run_id: RunId) -> ConfirmingRun | None:
            if run_id == _run(2):
                return ConfirmingRun(run_id, _principal(2), b"\x00" * 4)  # not SIG_HASH_LEN
            return ConfirmingRun(run_id, _principal(1), _sig(_CLUSTER_A))

    confirmations = build_confirmations(PROJECT, [_run(1), _run(2)], _PartlyMalformedLookup())

    assert [c.run_id for c in confirmations] == [_run(1)]
    assert count_independent(PROJECT, [_run(1), _run(2)], _PartlyMalformedLookup()) == 1


def test_independent_of_is_the_pairwise_form_of_the_guards_own_definition() -> None:
    from tracebed.workers.independence import independent_of

    a = ConfirmingRun(_run(1), _principal(1), _sig(_CLUSTER_A))
    same_principal = ConfirmingRun(_run(2), _principal(1), _sig(_CLUSTER_B))
    same_cluster_other_principal = ConfirmingRun(_run(3), _principal(2), _sig(_CLUSTER_A))
    genuinely_other = ConfirmingRun(_run(4), _principal(2), _sig(_CLUSTER_B))

    table = {c.run_id: c for c in (a, same_principal, same_cluster_other_principal, genuinely_other)}
    lookup = _FakeLookup(table)
    resolved = {c.run_id: c for c in build_confirmations(PROJECT, list(table), lookup)}

    assert not independent_of(resolved[a.run_id], resolved[same_principal.run_id])
    assert not independent_of(
        resolved[a.run_id], resolved[same_cluster_other_principal.run_id]
    )
    assert independent_of(resolved[a.run_id], resolved[genuinely_other.run_id])


def test_two_runs_in_the_same_real_cluster_are_one_confirmation() -> None:
    """End to end through the worker-side plumbing: two DIFFERENT authenticated principals,
    two different runs, wording that differs only by a typo. Distinct principals alone does
    not make them independent -- this is red-team probe 4 (correlated-trace corroboration)
    in its "same input-signature cluster" form."""
    table = {
        _run(1): ConfirmingRun(_run(1), _principal(1), _real_sig(_BASE_QUERY)),
        _run(2): ConfirmingRun(_run(2), _principal(2), _real_sig(_REWORDINGS[0])),
    }
    assert count_independent(PROJECT, list(table.keys()), _FakeLookup(table)) == 1

    genuine = dict(table)
    genuine[_run(3)] = ConfirmingRun(_run(3), _principal(3), _real_sig(_UNRELATED[0]))
    assert count_independent(PROJECT, list(genuine.keys()), _FakeLookup(genuine)) == 2
