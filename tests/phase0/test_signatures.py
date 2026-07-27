"""PHASE0-CONTRACT.md §3.8 — `domain.signatures`: input_signature_hash, simhash64, hamming.

Backs shadow-confirmation independence (invariant 7 / D-020): "independent"
corroboration requires distinct authenticated principals AND distinct
input-signature clusters. If `same_cluster` is too permissive the machine
promotes on one principal's rewording; if the signature ignores a feature,
two genuinely different runs collapse into one cluster and legitimate
corroboration is refused. Both directions are asserted below.
"""

from __future__ import annotations

import pytest

from tracebed.domain.ids import AgentTypeId
from tracebed.domain.signatures import (
    ABSENT_SIGNATURE,
    MAX_TOOL_MANIFEST_ENTRIES,
    SAME_CLUSTER_MAX_HAMMING,
    SIG_HASH_LEN,
    SIMHASH_HEAD_CHARS,
    hamming,
    input_signature_hash,
    same_cluster,
    simhash64,
)

pytestmark = pytest.mark.phase0

_AGENT = AgentTypeId.parse("55555555-5555-5555-5555-555555555555")
_OTHER_AGENT = AgentTypeId.parse("66666666-6666-6666-6666-666666666666")


def _sig(**overrides: object) -> bytes:
    kwargs: dict[str, object] = {
        "agent_type_id": _AGENT,
        "query_text": "how do I retry a failed payment capture?",
        "workflow_template": "payments/capture",
        "tool_manifest": ["stripe.charge", "stripe.refund"],
    }
    kwargs.update(overrides)
    return input_signature_hash(**kwargs)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# simhash64
# --------------------------------------------------------------------------- #


def test_simhash_empty_text_is_zero() -> None:
    assert simhash64("") == 0
    assert simhash64("   ") == 0  # whitespace-only collapses to empty


def test_simhash_is_deterministic() -> None:
    text = "The retriever timed out on the embedding call and fell back to lexical-only."
    assert simhash64(text) == simhash64(text)


def test_simhash_fits_in_64_bits() -> None:
    value = simhash64("some moderately long sentence about retries and backoff")
    assert 0 <= value < 1 << 64


def test_simhash_near_duplicates_cluster() -> None:
    a = "The retriever timed out on the embedding call and fell back to lexical-only."
    b = "The retriever timed out on the embedding call, and fell back to lexical only."
    dist = hamming(simhash64(a), simhash64(b))
    assert dist <= SAME_CLUSTER_MAX_HAMMING, f"near-duplicate texts should cluster, hamming={dist}"


def test_simhash_unrelated_text_does_not_cluster() -> None:
    a = "The retriever timed out on the embedding call and fell back to lexical-only."
    b = "Invoice #4471 was rejected because the vendor tax id failed checksum validation."
    dist = hamming(simhash64(a), simhash64(b))
    assert dist > SAME_CLUSTER_MAX_HAMMING, f"unrelated texts should not cluster, hamming={dist}"


def test_simhash_stable_across_whitespace_and_case() -> None:
    a = "Retry Budget Exceeded For Tool payments.charge"
    b = "  retry   budget exceeded for tool   payments.charge  "
    assert simhash64(a) == simhash64(b)


def test_simhash_reads_only_the_first_head_chars() -> None:
    # SIMHASH_HEAD_CHARS is the documented window; a mutation that widened or
    # narrowed it would change which submissions count as independent.
    head = "x" * SIMHASH_HEAD_CHARS
    assert simhash64(head) == simhash64(head + " a completely different tail sentence")


def test_simhash_is_sensitive_within_the_head() -> None:
    # The flip side of the window test: a change inside the window must move
    # the hash, or every long query would share one cluster.
    base = "restart the failed ingest job for project alpha " + "y" * 100
    changed = "cancel the pending payout batch for vendor omega " + "y" * 100
    assert hamming(simhash64(base), simhash64(changed)) > SAME_CLUSTER_MAX_HAMMING


def test_simhash_resists_filler_padding_of_identical_wording() -> None:
    # THE Sybil bypass this module exists to close (D-020 / invariant 7): the
    # same request submitted twice with different filler appended must remain
    # one cluster. With per-occurrence shingle votes these landed 26 bits
    # apart — two "independent" confirmations from one piece of wording.
    body = "the retriever timed out and fell back to lexical only "
    a = simhash64(body + "a" * 400)
    b = simhash64(body + "b" * 400)
    assert hamming(a, b) <= SAME_CLUSTER_MAX_HAMMING


def test_simhash_is_not_dominated_by_repeated_filler() -> None:
    # The mirror failure: two genuinely different requests sharing a long run
    # of one character must not collapse into one cluster (which would refuse
    # legitimate corroboration from two principals doing different work).
    a = simhash64("restart the failed ingest job for project alpha " + "y" * 100)
    b = simhash64("cancel the pending payout batch for vendor omega " + "y" * 100)
    assert hamming(a, b) > SAME_CLUSTER_MAX_HAMMING


def test_simhash_handles_text_shorter_than_the_shingle_size() -> None:
    # The shingler special-cases text shorter than 3 characters; that path must
    # not raise and must still discriminate.
    assert simhash64("ab") != 0
    assert simhash64("ab") != simhash64("cd")


def test_simhash_bounds_the_text_it_normalises() -> None:
    # query_text arrives from an attacker-controlled run_start payload, and NFC
    # normalisation + casefolding allocate proportionally to the WHOLE string
    # even though only SIMHASH_HEAD_CHARS of it can reach the shingler. The
    # implementation therefore pre-slices at _MAX_NORMALISE_CHARS.
    #
    # That bound is behaviour-preserving for every input except one that is
    # almost entirely whitespace inside the window, which is what this pins:
    # a query padded with _MAX_NORMALISE_CHARS spaces has no content the
    # bounded implementation can see, and hashes to 0 (clustering with
    # ABSENT_SIGNATURE — the conservative direction, since a 0 signature can
    # only ever refuse independence, never manufacture it). Without the bound
    # the padding is collapsed away and the tail shows through.
    from tracebed.domain.signatures import _MAX_NORMALISE_CHARS

    padded = " " * _MAX_NORMALISE_CHARS + "restart the failed ingest job"
    assert simhash64(padded) == 0


def test_simhash_completes_on_a_multi_megabyte_query() -> None:
    # Companion smoke check: the bound above must actually be reached on a
    # realistic hostile payload rather than dying in normalisation.
    huge = "retry the capture " * 1_000_000  # ~18 MB
    assert simhash64(huge) == simhash64("retry the capture " * 100)


# --------------------------------------------------------------------------- #
# hamming
# --------------------------------------------------------------------------- #


def test_hamming_identity_is_zero() -> None:
    value = simhash64("some text")
    assert hamming(value, value) == 0


def test_hamming_all_bits_flipped_is_64() -> None:
    assert hamming(0, (1 << 64) - 1) == 64


def test_hamming_counts_single_bit_differences() -> None:
    assert hamming(0b1010, 0b1011) == 1
    assert hamming(0b0000, 0b1111) == 4


def test_hamming_is_symmetric() -> None:
    a, b = simhash64("alpha"), simhash64("beta")
    assert hamming(a, b) == hamming(b, a)


# --------------------------------------------------------------------------- #
# input_signature_hash — layout and feature sensitivity
# --------------------------------------------------------------------------- #


def test_input_signature_hash_length_is_sig_hash_len() -> None:
    assert len(_sig()) == SIG_HASH_LEN == 40


def test_input_signature_hash_layout_is_sha256_then_simhash() -> None:
    # C-07 pins the layout (32 structured bytes ‖ 8 simhash bytes) because
    # `same_cluster` reads the trailing 8 bytes and nothing else. A swapped
    # concatenation order would silently make clustering compare digest bytes.
    query = "restart the failed job"
    sig = _sig(query_text=query)
    assert int.from_bytes(sig[-8:], "big") == simhash64(query)
    assert len(sig[:-8]) == 32


def test_absent_signature_is_forty_zero_bytes() -> None:
    assert bytes(SIG_HASH_LEN) == ABSENT_SIGNATURE
    assert len(ABSENT_SIGNATURE) == SIG_HASH_LEN


def test_input_signature_hash_independent_of_tool_manifest_order() -> None:
    # C-07: sorted(tool_manifest) inside the canonical feature set — a run
    # whose tool_manifest arrives in a different order must hash identically.
    assert _sig(tool_manifest=["b.tool", "a.tool", "c.tool"]) == _sig(
        tool_manifest=["c.tool", "a.tool", "b.tool"]
    )


def test_input_signature_hash_accepts_any_sequence_type() -> None:
    # trace_writer may hand this a tuple off a parsed payload; the signature
    # must not depend on the concrete container.
    assert _sig(tool_manifest=("a.tool", "b.tool")) == _sig(tool_manifest=["a.tool", "b.tool"])


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("agent_type_id", _OTHER_AGENT),
        ("query_text", "a completely different question about invoices"),
        ("workflow_template", "payments/refund"),
        ("tool_manifest", ["stripe.charge"]),
    ],
)
def test_input_signature_hash_depends_on_every_feature(field: str, value: object) -> None:
    # Without this, an implementation that silently dropped `workflow_template`
    # or `tool_manifest` from the feature set would pass every other test here
    # while collapsing distinct runs into one signature.
    assert _sig() != _sig(**{field: value})


def test_input_signature_hash_treats_missing_optionals_consistently() -> None:
    # C-07 spells the defaults as `workflow_template or ""` and
    # `tool_manifest or []`, so None and the empty form are the same run.
    assert _sig(workflow_template=None, tool_manifest=None) == _sig(
        workflow_template="", tool_manifest=[]
    )
    assert len(_sig(workflow_template=None, tool_manifest=None)) == SIG_HASH_LEN


def test_input_signature_hash_is_pure_across_repeated_calls() -> None:
    # No accumulated state: recomputing the same features at any point in a
    # replay must be byte-identical (Task 14's reordering-stability property,
    # whose event-level half belongs to `tests/phase0/test_trace_writer.py`).
    assert len({_sig() for _ in range(5)}) == 1


def test_input_signature_hash_does_not_mutate_the_caller_s_manifest() -> None:
    manifest = ["z.tool", "a.tool"]
    input_signature_hash(
        agent_type_id=_AGENT, query_text="q", workflow_template=None, tool_manifest=manifest
    )
    assert manifest == ["z.tool", "a.tool"], "sorting must not happen in place"


# --------------------------------------------------------------------------- #
# input_signature_hash — untrusted-input rejection
# --------------------------------------------------------------------------- #


def test_input_signature_hash_rejects_a_bare_string_tool_manifest() -> None:
    # A `str` IS a Sequence[str], so `sorted("abc")` would happily signature
    # the individual characters of a manifest sent as a string.
    with pytest.raises(ValueError, match="tool_manifest"):
        input_signature_hash(
            agent_type_id=_AGENT,
            query_text="q",
            workflow_template=None,
            tool_manifest="stripe.charge",  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("bad", [[1, 2], ["ok", None], [["nested"]], [{"a": 1}]])
def test_input_signature_hash_rejects_non_string_manifest_entries(bad: list[object]) -> None:
    # `sorted()` on a homogeneous list of ints succeeds, producing a
    # plausible-looking signature from type-confused input; on a mixed list it
    # raises TypeError deep inside the ingest consumer. Neither is acceptable.
    with pytest.raises(ValueError, match="tool_manifest"):
        input_signature_hash(
            agent_type_id=_AGENT,
            query_text="q",
            workflow_template=None,
            tool_manifest=bad,  # type: ignore[arg-type]
        )


def test_input_signature_hash_rejects_an_unbounded_tool_manifest() -> None:
    too_many = [f"tool.{i}" for i in range(MAX_TOOL_MANIFEST_ENTRIES + 1)]
    with pytest.raises(ValueError, match="tool_manifest"):
        input_signature_hash(
            agent_type_id=_AGENT, query_text="q", workflow_template=None, tool_manifest=too_many
        )


def test_input_signature_hash_accepts_the_manifest_limit_exactly() -> None:
    at_limit = [f"tool.{i}" for i in range(MAX_TOOL_MANIFEST_ENTRIES)]
    assert (
        len(
            input_signature_hash(
                agent_type_id=_AGENT,
                query_text="q",
                workflow_template=None,
                tool_manifest=at_limit,
            )
        )
        == SIG_HASH_LEN
    )


def test_input_signature_hash_rejects_an_overlong_manifest_entry() -> None:
    with pytest.raises(ValueError, match="tool_manifest"):
        input_signature_hash(
            agent_type_id=_AGENT,
            query_text="q",
            workflow_template=None,
            tool_manifest=["x" * 5000],
        )


# --------------------------------------------------------------------------- #
# same_cluster — the D-020 independence test
# --------------------------------------------------------------------------- #


def test_same_cluster_groups_reworded_queries() -> None:
    # The Sybil case: one principal resubmitting the same request in slightly
    # different words must NOT read as two independent confirmations.
    a = _sig(query_text="the retriever timed out and fell back to lexical only")
    b = _sig(query_text="the retriever timed out, and fell back to lexical-only")
    assert same_cluster(a, b)


def test_same_cluster_separates_genuinely_different_queries() -> None:
    # The opposite failure: over-clustering would refuse legitimate
    # corroboration from two principals doing different work.
    a = _sig(query_text="the retriever timed out and fell back to lexical only")
    b = _sig(query_text="invoice 4471 was rejected because the vendor tax id failed checksum")
    assert not same_cluster(a, b)


def test_same_cluster_is_reflexive_and_symmetric() -> None:
    a, b = _sig(query_text="alpha query"), _sig(query_text="beta query entirely unrelated")
    assert same_cluster(a, a)
    assert same_cluster(a, b) == same_cluster(b, a)


def test_same_cluster_ignores_the_structured_prefix_by_design() -> None:
    # §3.8 defines cluster membership on the trailing simhash bytes only.
    # Documented here so the asymmetry with input_signature_hash's feature set
    # is a decision on the record, not an accident someone "fixes" later:
    # differing structured features do not make two identical queries
    # independent, which is the conservative direction for invariant 7.
    a = _sig(agent_type_id=_AGENT, query_text="identical wording")
    b = _sig(agent_type_id=_OTHER_AGENT, query_text="identical wording")
    assert a[:32] != b[:32]
    assert same_cluster(a, b)


def test_same_cluster_at_the_threshold_boundary() -> None:
    # Off-by-one on `<=` vs `<` decides whether an 8-bit-apart pair counts as
    # independent, i.e. whether a promotion happens.
    base = bytes(32) + (0).to_bytes(8, "big")
    at_limit = bytes(32) + ((1 << SAME_CLUSTER_MAX_HAMMING) - 1).to_bytes(8, "big")
    just_over = bytes(32) + ((1 << (SAME_CLUSTER_MAX_HAMMING + 1)) - 1).to_bytes(8, "big")
    assert hamming(0, (1 << SAME_CLUSTER_MAX_HAMMING) - 1) == SAME_CLUSTER_MAX_HAMMING
    assert same_cluster(base, at_limit)
    assert not same_cluster(base, just_over)


@pytest.mark.parametrize("bad", [b"", b"short", bytes(SIG_HASH_LEN - 1), bytes(SIG_HASH_LEN + 1)])
def test_same_cluster_rejects_wrong_length(bad: bytes) -> None:
    # A truncated signature must not be silently zero-padded into "same
    # cluster as everything"; the state machine reads these straight from
    # ShadowConfirmation records.
    with pytest.raises(ValueError, match="40-byte"):
        same_cluster(bad, ABSENT_SIGNATURE)
    with pytest.raises(ValueError, match="40-byte"):
        same_cluster(ABSENT_SIGNATURE, bad)


def test_absent_signatures_cluster_with_each_other() -> None:
    # C-07's sweeper fallback: two runs with no run_start carry no distinguishing
    # signal, so they must not count as independent confirmations.
    assert same_cluster(ABSENT_SIGNATURE, ABSENT_SIGNATURE)
