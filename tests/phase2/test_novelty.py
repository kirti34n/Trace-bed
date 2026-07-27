"""The operational-lane novelty gate (PLAN.md §7 Phase 2 / §8 improvement 4).

Everything here is pure and offline — `workers.novelty` touches no store, no clock, and
no LLM; every test constructs its own `TierANote`/`Provenance` fixtures directly.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from tracebed.core.scans.tier_a_template import ErrorClassEnum, HexDigest, TierANote, ToolIdentifier
from tracebed.domain.enums import ProvenanceClass
from tracebed.domain.errors import ProvenanceIncomplete, TracebedError
from tracebed.domain.ids import (
    PrincipalId,
    ProjectId,
    RunId,
    mint_memory_id,
    mint_run_id,
)
from tracebed.domain.memory import Provenance
from tracebed.domain.signatures import SAME_CLUSTER_MAX_HAMMING, SIG_HASH_LEN, hamming
from tracebed.workers.novelty import (
    ExistingSignature,
    MergeUpdate,
    NoveltyDecision,
    NoveltyGate,
    is_near_duplicate,
    merge_provenance,
    structural_signature,
)

pytestmark = pytest.mark.phase2

_PROJECT = ProjectId("11111111-1111-1111-1111-111111111111")
_OTHER_PROJECT = ProjectId("22222222-2222-2222-2222-222222222222")

_HASH_A = "a" * 64
_HASH_B = "b" * 64


def _note(
    *,
    error_class: ErrorClassEnum = ErrorClassEnum.TIMEOUT,
    tool_id: str = "search-tool",
    tool_version: str = "1.0.0",
    count: int = 1,
    duration_ms: int = 100,
    payload_class_hash: str = _HASH_A,
) -> TierANote:
    return TierANote(
        error_class=error_class,
        tool_id=ToolIdentifier(tool_id),
        tool_version=ToolIdentifier(tool_version),
        count=count,
        duration_ms=duration_ms,
        payload_class_hash=HexDigest(payload_class_hash),
    )


def _provenance(*run_ids: RunId) -> Provenance:
    return Provenance(cls=ProvenanceClass.PARSER, trace_ids=run_ids)


# --------------------------------------------------------------------------- #
# structural_signature: identity fields drive it, count/duration never do.
# --------------------------------------------------------------------------- #


def test_identical_identity_fields_produce_identical_signature_regardless_of_count_or_duration() -> (
    None
):
    a = _note(count=1, duration_ms=50)
    b = _note(count=99, duration_ms=9000)
    assert structural_signature(a) == structural_signature(b)


def test_different_tool_id_changes_the_signature() -> None:
    a = _note(tool_id="search-tool")
    b = _note(tool_id="an-entirely-different-tool")
    assert structural_signature(a) != structural_signature(b)


def test_different_payload_class_hash_changes_the_signature() -> None:
    a = _note(payload_class_hash=_HASH_A)
    b = _note(payload_class_hash=_HASH_B)
    assert structural_signature(a) != structural_signature(b)


def test_signature_is_always_sig_hash_len_bytes() -> None:
    assert len(structural_signature(_note())) == SIG_HASH_LEN


# --------------------------------------------------------------------------- #
# is_near_duplicate is signature EQUALITY, not a Hamming radius. The pairs below
# are the reason: they are real, non-adversarial notes that a
# SAME_CLUSTER_MAX_HAMMING radius test declares "the same condition".
# --------------------------------------------------------------------------- #


def _flip_trailing_bits(signature: bytes, n_bits: int) -> bytes:
    """Flips exactly `n_bits` distinct low bits of `signature`'s trailing 8
    (simhash) bytes, producing a signature whose Hamming distance from the
    original is exactly `n_bits`."""
    trailing = int.from_bytes(signature[-8:], "big")
    for bit in range(n_bits):
        trailing ^= 1 << bit
    return signature[:-8] + trailing.to_bytes(8, "big")


def _simhash_distance(a: bytes, b: bytes) -> int:
    return hamming(int.from_bytes(a[-8:], "big"), int.from_bytes(b[-8:], "big"))


def test_identical_signatures_are_the_same_condition() -> None:
    assert is_near_duplicate(structural_signature(_note()), structural_signature(_note())) is True


def test_a_signature_one_simhash_bit_away_is_not_the_same_condition() -> None:
    """Anything short of byte-equality is a different condition. A single
    flipped bit is well inside SAME_CLUSTER_MAX_HAMMING, so this test goes red
    the moment the gate is reverted to a radius."""
    base = structural_signature(_note())
    one_bit_off = _flip_trailing_bits(base, 1)
    assert _simhash_distance(base, one_bit_off) <= SAME_CLUSTER_MAX_HAMMING
    assert is_near_duplicate(base, one_bit_off) is False


def test_a_signature_differing_only_in_its_exact_half_is_not_the_same_condition() -> None:
    """`domain.signatures.same_cluster` compares ONLY the trailing 8 SimHash
    bytes and would call these two identical. The leading 32 sha256 bytes are
    the half that actually pins the identity fields."""
    base = structural_signature(_note())
    exact_half_differs = bytes(b ^ 0xFF for b in base[:32]) + base[32:]
    assert _simhash_distance(base, exact_half_differs) == 0
    assert is_near_duplicate(base, exact_half_differs) is False


# Found by brute-forcing this module's own `structural_signature` over 1,500
# realistic notes: 0.2% of distinct-identity pairs land within
# SAME_CLUSTER_MAX_HAMMING of each other. These two are one such pair -- a
# rate_limited on one service and a timeout on another, 8 bits apart, i.e.
# EXACTLY at the radius a fuzzy gate would merge at.
_COLLIDING_HASH = "e7f6c011776e8db7cd330b54174fd76f7d0216b612387a5ffcfb81e6f0919683"


def _colliding_a() -> TierANote:
    return _note(
        error_class=ErrorClassEnum.RATE_LIMITED,
        tool_id="svc.22.api",
        tool_version="10.2.1",
        payload_class_hash=_COLLIDING_HASH,
    )


def _colliding_b() -> TierANote:
    return _note(
        error_class=ErrorClassEnum.TIMEOUT,
        tool_id="svc.28.api",
        tool_version="10.2.1",
        payload_class_hash=_COLLIDING_HASH,
    )


def test_distinct_conditions_whose_simhashes_collide_are_not_merged() -> None:
    sig_a, sig_b = structural_signature(_colliding_a()), structural_signature(_colliding_b())

    # The premise: a radius gate WOULD have merged these two.
    assert _simhash_distance(sig_a, sig_b) <= SAME_CLUSTER_MAX_HAMMING
    # The guarantee: this gate does not.
    assert is_near_duplicate(sig_a, sig_b) is False


def test_a_simhash_colliding_note_is_filed_as_new_and_keeps_its_own_provenance() -> None:
    """The end-to-end consequence of the previous test. Merging these two would
    graft the timeout run's trace_ids onto a memory that says rate_limited --
    invariant 6 says a derived memory points at the traces that produced it,
    and after such a merge it points at traces that did not."""
    gate = NoveltyGate()
    existing_note = _colliding_a()
    existing = ExistingSignature(
        project_id=_PROJECT,
        memory_id=mint_memory_id(),
        note=existing_note,
        provenance=_provenance(mint_run_id()),
        structural_signature=structural_signature(existing_note),
    )

    decision = gate.decide(_PROJECT, _colliding_b(), _provenance(mint_run_id()), [existing])

    assert decision.action == "new"
    assert decision.merge is None


def test_a_tool_version_bump_is_a_new_condition_not_a_merge() -> None:
    """Staleness, not dedup, owns a version bump: PLAN.md §7 Phase 2 requires
    "flip tool def -> dependents stale -> two strikes retire". Merging the new
    version's failures into the old version's note would erase the very signal
    the invalidator retires on. The two land ~11 bits apart -- close enough
    that a slightly wider radius would swallow them."""
    old = _note(tool_version="1.0.0")
    new = _note(tool_version="2.0.0")
    assert is_near_duplicate(structural_signature(old), structural_signature(new)) is False

    gate = NoveltyGate()
    existing = ExistingSignature(
        project_id=_PROJECT,
        memory_id=mint_memory_id(),
        note=old,
        provenance=_provenance(mint_run_id()),
        structural_signature=structural_signature(old),
    )
    assert gate.decide(_PROJECT, new, _provenance(mint_run_id()), [existing]).action == "new"


def test_is_near_duplicate_rejects_wrong_length_signatures() -> None:
    """A truncated or foreign-layout signature must raise, never return False:
    a quiet False reads as "novel" and files a duplicate row forever."""
    with pytest.raises(ValueError):
        is_near_duplicate(b"too-short", structural_signature(_note()))
    with pytest.raises(ValueError):
        is_near_duplicate(structural_signature(_note()), b"too-short")


# --------------------------------------------------------------------------- #
# NoveltyGate.decide: merges a near-duplicate, inserts a genuinely new item.
# --------------------------------------------------------------------------- #


def test_decide_merges_a_repeated_observation_of_the_same_condition() -> None:
    gate = NoveltyGate()
    existing_memory_id = mint_memory_id()
    existing_run = mint_run_id()
    existing_note = _note(count=3, duration_ms=120)
    existing = ExistingSignature(
        project_id=_PROJECT,
        memory_id=existing_memory_id,
        note=existing_note,
        provenance=_provenance(existing_run),
        structural_signature=structural_signature(existing_note),
    )

    incoming_run = mint_run_id()
    incoming_note = _note(count=1, duration_ms=999)
    decision = gate.decide(_PROJECT, incoming_note, _provenance(incoming_run), [existing])

    assert decision.action == "merge"
    assert decision.merge is not None
    assert decision.merge.memory_id == existing_memory_id
    # count is additive (both observations genuinely happened)...
    assert decision.merge.note.count == 4
    # ...duration keeps the larger of the two (a diagnostic ceiling never shrinks).
    assert decision.merge.note.duration_ms == 999
    # identity fields come from the EXISTING item, not the incoming one.
    assert decision.merge.note.error_class == existing_note.error_class
    assert decision.merge.note.tool_id == existing_note.tool_id


def test_decide_inserts_a_genuinely_new_condition() -> None:
    gate = NoveltyGate()
    existing_note = _note(tool_id="search-tool")
    existing = ExistingSignature(
        project_id=_PROJECT,
        memory_id=mint_memory_id(),
        note=existing_note,
        provenance=_provenance(mint_run_id()),
        structural_signature=structural_signature(existing_note),
    )

    decision = gate.decide(
        _PROJECT,
            _note(tool_id="an-entirely-different-tool"),
        _provenance(mint_run_id()),
        [existing],
    )

    assert decision.action == "new"
    assert decision.merge is None
    assert decision.structural_signature == structural_signature(
        _note(tool_id="an-entirely-different-tool")
    )


def test_decide_with_no_existing_items_always_inserts() -> None:
    gate = NoveltyGate()
    decision = gate.decide(_PROJECT, _note(), _provenance(mint_run_id()), [])
    assert decision.action == "new"
    assert decision.merge is None


# --------------------------------------------------------------------------- #
# Merge preserves the UNION of provenance trace_ids -- never just the newer one.
# Losing provenance on merge silently breaks invariant 6 and Recall & Rollback.
# --------------------------------------------------------------------------- #


def test_merge_provenance_unions_trace_ids_never_replaces_them() -> None:
    run_a, run_b, run_c = mint_run_id(), mint_run_id(), mint_run_id()
    existing_prov = Provenance(cls=ProvenanceClass.PARSER, trace_ids=(run_a, run_b))
    incoming_prov = Provenance(cls=ProvenanceClass.PARSER, trace_ids=(run_b, run_c))

    merged = merge_provenance(existing_prov, incoming_prov)

    assert set(merged.trace_ids) == {run_a, run_b, run_c}
    assert run_a in merged.trace_ids  # existing evidence is never dropped
    assert run_b in merged.trace_ids
    assert run_c in merged.trace_ids
    # de-duplicated, not doubled.
    assert merged.trace_ids.count(run_b) == 1


def test_decide_merge_branch_also_unions_provenance() -> None:
    gate = NoveltyGate()
    run_a, run_b = mint_run_id(), mint_run_id()
    note = _note()
    existing = ExistingSignature(
        project_id=_PROJECT,
        memory_id=mint_memory_id(),
        note=note,
        provenance=Provenance(cls=ProvenanceClass.PARSER, trace_ids=(run_a,)),
        structural_signature=structural_signature(note),
    )

    decision = gate.decide(_PROJECT, note, Provenance(cls=ProvenanceClass.PARSER, trace_ids=(run_b,)), [existing])

    assert decision.merge is not None
    assert set(decision.merge.provenance.trace_ids) == {run_a, run_b}


def test_merge_provenance_keeps_existing_evidence_first_and_in_order() -> None:
    """The union must be ORDER-PRESERVING with existing evidence first, not a
    set: a caller reading the first N trace_ids for a summary (or a forensics
    walk that truncates) must see the oldest evidence, and a set round-trip
    makes which evidence survives truncation depend on hash order."""
    run_a, run_b, run_c, run_d = mint_run_id(), mint_run_id(), mint_run_id(), mint_run_id()
    merged = merge_provenance(
        Provenance(cls=ProvenanceClass.PARSER, trace_ids=(run_a, run_b)),
        Provenance(cls=ProvenanceClass.PARSER, trace_ids=(run_c, run_b, run_d)),
    )
    assert merged.trace_ids == (run_a, run_b, run_c, run_d)


def test_merge_provenance_unions_tool_refs_and_input_sig_hashes_too() -> None:
    """trace_ids are not the only evidence on a Provenance; dropping either of
    the other two collections on merge is the same invariant-6 loss, quieter."""
    merged = merge_provenance(
        Provenance(
            cls=ProvenanceClass.PARSER,
            trace_ids=(mint_run_id(),),
            tool_refs=("tool-a",),
            input_sig_hashes=(b"\x01" * SIG_HASH_LEN,),
        ),
        Provenance(
            cls=ProvenanceClass.PARSER,
            trace_ids=(mint_run_id(),),
            tool_refs=("tool-b",),
            input_sig_hashes=(b"\x02" * SIG_HASH_LEN,),
        ),
    )
    assert merged.tool_refs == ("tool-a", "tool-b")
    assert merged.input_sig_hashes == (b"\x01" * SIG_HASH_LEN, b"\x02" * SIG_HASH_LEN)


def test_merge_provenance_carries_single_valued_fields_across_the_merge() -> None:
    """`verdict_id`/`run_id`/`principal` are not required for the PARSER class,
    but a row may still hold one, and a merge that rebuilt Provenance from only
    the three collections would drop it without a word."""
    verdict = uuid4()
    run = mint_run_id()
    principal = PrincipalId(uuid4())
    merged = merge_provenance(
        Provenance(cls=ProvenanceClass.PARSER, trace_ids=(mint_run_id(),), verdict_id=verdict),
        Provenance(
            cls=ProvenanceClass.PARSER,
            trace_ids=(mint_run_id(),),
            run_id=run,
            principal=principal,
        ),
    )
    assert merged.verdict_id == verdict
    assert merged.run_id == run
    assert merged.principal == principal


def test_merge_provenance_refuses_to_pick_between_conflicting_single_values() -> None:
    with pytest.raises(ValueError):
        merge_provenance(
            Provenance(cls=ProvenanceClass.PARSER, trace_ids=(mint_run_id(),), verdict_id=uuid4()),
            Provenance(cls=ProvenanceClass.PARSER, trace_ids=(mint_run_id(),), verdict_id=uuid4()),
        )


def test_merge_provenance_rejects_provenance_with_no_evidence() -> None:
    """Invariant 6 at the merge boundary: a PARSER provenance with no
    trace_ids points at nothing, and a merge of two of them would hand the
    caller a complete-looking row to persist."""
    with pytest.raises(ProvenanceIncomplete):
        merge_provenance(
            Provenance(cls=ProvenanceClass.PARSER, trace_ids=()),
            Provenance(cls=ProvenanceClass.PARSER, trace_ids=(mint_run_id(),)),
        )
    with pytest.raises(ProvenanceIncomplete):
        merge_provenance(
            Provenance(cls=ProvenanceClass.PARSER, trace_ids=(mint_run_id(),)),
            Provenance(cls=ProvenanceClass.PARSER, trace_ids=()),
        )


def test_merge_provenance_rejects_non_parser_classes() -> None:
    with pytest.raises(ValueError):
        merge_provenance(
            Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(mint_run_id(),)),
            Provenance(cls=ProvenanceClass.PARSER, trace_ids=(mint_run_id(),)),
        )
    with pytest.raises(ValueError):
        merge_provenance(
            Provenance(cls=ProvenanceClass.PARSER, trace_ids=(mint_run_id(),)),
            Provenance(cls=ProvenanceClass.PROPOSAL, run_id=mint_run_id()),
        )


# --------------------------------------------------------------------------- #
# NoveltyDecision construction guards.
# --------------------------------------------------------------------------- #


def test_novelty_decision_rejects_merge_action_without_a_merge_update() -> None:
    with pytest.raises(ValueError):
        NoveltyDecision(
            action="merge", structural_signature=structural_signature(_note()), merge=None
        )


def test_novelty_decision_rejects_a_new_action_carrying_a_merge_update() -> None:
    """The mirror guard. Without it a caller branching on `.merge is not None`
    instead of on `.action` would silently apply a merge the gate declined."""
    note = _note()
    with pytest.raises(ValueError):
        NoveltyDecision(
            action="new",
            structural_signature=structural_signature(note),
            merge=MergeUpdate(
                memory_id=mint_memory_id(), note=note, provenance=_provenance(mint_run_id())
            ),
        )


def test_novelty_decision_rejects_a_wrong_length_signature() -> None:
    with pytest.raises(ValueError):
        NoveltyDecision(action="new", structural_signature=b"too-short", merge=None)


def test_existing_signature_rejects_a_wrong_length_signature() -> None:
    with pytest.raises(ValueError):
        ExistingSignature(
        project_id=_PROJECT,
            memory_id=mint_memory_id(),
            note=_note(),
            provenance=_provenance(mint_run_id()),
            structural_signature=b"too-short",
        )


def test_existing_signature_rejects_a_signature_that_does_not_match_its_note() -> None:
    """`note` and `structural_signature` come from two columns of one row. If
    they disagree the index has drifted from what it indexes, and merging under
    that pairing would fold one condition's observations and provenance into a
    row describing a different one."""
    with pytest.raises(ValueError):
        ExistingSignature(
        project_id=_PROJECT,
            memory_id=mint_memory_id(),
            note=_note(tool_id="search-tool"),
            provenance=_provenance(mint_run_id()),
            structural_signature=structural_signature(_note(tool_id="a-different-tool")),
        )


# --------------------------------------------------------------------------- #
# Invariant 4 at the gate's own seam
# --------------------------------------------------------------------------- #


def test_a_foreign_projects_signature_is_refused_not_merged() -> None:
    """The signature space is GLOBAL: `structural_signature` hashes
    (error_class, tool_id, tool_version, payload_class_hash) and nothing in it
    names a project, so two projects running the same tool produce byte-equal
    signatures. Nothing else in this module could have caught it -- the
    identity fields are identical by construction in exactly the case that
    matters, so a store query that lost its project scope would be told to
    merge and would graft one project's trace_ids onto the other's memory."""
    gate = NoveltyGate()
    note = _note()
    foreign = ExistingSignature(
        project_id=_OTHER_PROJECT,
        memory_id=mint_memory_id(),
        note=note,
        provenance=_provenance(mint_run_id()),
        structural_signature=structural_signature(note),
    )

    with pytest.raises(TracebedError):
        gate.decide(_PROJECT, note, _provenance(mint_run_id()), [foreign])


def test_the_identical_note_in_the_callers_own_project_still_merges() -> None:
    """Guard the guard: the refusal above must be about the project, not about
    the note. Byte-identical inputs, same project, and the merge happens."""
    gate = NoveltyGate()
    note = _note()
    own = ExistingSignature(
        project_id=_PROJECT,
        memory_id=mint_memory_id(),
        note=note,
        provenance=_provenance(mint_run_id()),
        structural_signature=structural_signature(note),
    )

    assert gate.decide(_PROJECT, note, _provenance(mint_run_id()), [own]).action == "merge"


def test_one_foreign_row_refuses_the_whole_call_rather_than_being_skipped() -> None:
    """Invariant 4 is not a filter. A store query that returned another
    project's row is a control that has stopped holding, and silently dropping
    the row leaves the caller writing to a vault it has already been given
    wrong answers about -- so the mixed batch is refused entirely, including
    the legitimate rows in it."""
    gate = NoveltyGate()
    note = _note()
    own = ExistingSignature(
        project_id=_PROJECT,
        memory_id=mint_memory_id(),
        note=note,
        provenance=_provenance(mint_run_id()),
        structural_signature=structural_signature(note),
    )
    other_note = _note(tool_id="some-other-tool")
    foreign = ExistingSignature(
        project_id=_OTHER_PROJECT,
        memory_id=mint_memory_id(),
        note=other_note,
        provenance=_provenance(mint_run_id()),
        structural_signature=structural_signature(other_note),
    )

    with pytest.raises(TracebedError):
        gate.decide(_PROJECT, note, _provenance(mint_run_id()), [own, foreign])
