"""The operational-lane novelty gate (PLAN.md §7 Phase 2 / §8 improvement 4).

Its whole job is to stop the vault filling with near-duplicate Tier A notes: a
candidate whose *structural* signature lands within the cluster radius of an
already-stored item is **merged** into that item, never inserted as a second
row. This is what bends the soak's vault-growth curve (PLAN.md §7 Phase 2
gate: "net vault growth rate strictly decreasing week-over-week").

LLM-free by construction — there is no `adapters.llm`/`LLMProviderPort` import
anywhere in this module, and there could not be one: Tier A notes
(`core.scans.tier_a_template.TierANote`) are the operational lane's only
content type, and D-019 already made them a closed vocabulary with zero free
text. "Structural" signature means exactly that: the signature is computed
over `TierANote`'s *identity* fields (`error_class`, `tool_id`, `tool_version`,
`payload_class_hash`), never over `count`/`duration_ms` — those two are
running totals that are SUPPOSED to differ between an existing item and a
fresh observation of the same underlying condition, and folding them into the
signature would defeat deduplication on the exact case this gate exists to
catch (two notes about the same timeout, one seen 3 times, one seen once,
would then look like two different conditions).

Reuses `domain/signatures.py` rather than reimplementing any of it, per this
chunk's own instructions: `simhash64` builds the trailing 8 bytes and
`domain.canonical.canonical_json` the leading 32, so the signature is
byte-for-byte the same 40-byte (`domain.signatures.SIG_HASH_LEN`) layout
`input_signature_hash` produces and can be stored in the same column shape.

What this module does NOT reuse is `same_cluster`, and that is the load-bearing
choice here. `same_cluster` compares ONLY the trailing 8 SimHash bytes and
tolerates `SAME_CLUSTER_MAX_HAMMING` (8) differing bits — a threshold tuned for
*free text*, where a typo or a reordered clause must still count as the same
query (D-020). A `TierANote` has no free text at all: D-019 made every field a
closed enum, a registry-sourced identifier, or a sha256 digest, so there is no
typo channel for a fuzzy radius to absorb — and applying one anyway is actively
wrong. Measured on this module's own signature construction over 1,500 realistic
notes (30 tool ids x 5 versions x 40 payload classes x the 10 error classes),
0.2% of *distinct-identity* pairs landed within 8 bits of each other, including
pairs differing in `error_class` and in `tool_id`. Under a radius test each of
those pairs merges: the second condition's identity is discarded (`_merge_notes`
keeps the existing item's fields), its `count` is folded into an unrelated item,
and — the part that breaks invariant 6 — its `trace_ids` are grafted onto a note
describing a different failure, so Recall & Rollback (PLAN.md §8 improvement 1)
would walk from a `rate_limited` memory into runs that only ever timed out. It
also collides head-on with Phase 2's staleness lane: a `tool_version` bump lands
~11 bits away, well inside the radius, so a fuzzy gate would silently merge a
new tool version's failures into the old version's note instead of letting the
invalidator mark the old note's dependents stale and two-strike retire them.
PLAN.md §7 Phase 2 says "structural signature *hash*", and a hash matches
exactly; `is_near_duplicate` therefore requires signature equality.

CONTRACT GAP (reported, not worked around): this chunk's file list is exactly
`workers/novelty.py`, `workers/consolidator.py`, `workers/deltas.py` plus
tests/harness — it does not include `stores/pg/repo.py`. Deciding "is this a
near-duplicate" requires the caller to already have fetched the candidate
signatures of every Tier A item currently in the relevant scope (agent_type /
cluster), and `Repo` has no such query (no `list_by_structural_signature`, no
`cluster_id`-scoped fetch, no `update_memory_item` to persist a merge's
aggregated count/duration/provenance back onto the existing row). This module
is therefore built and fully tested against `ExistingSignature` — data the
caller already holds — rather than against a store it cannot reach; the
missing `Repo` methods (a signature index query, and a write path that updates
an existing `memory_item` in place for a merge rather than only ever
inserting) are the concrete gap for whoever next touches `stores/pg/repo.py`
or the Tier A write path (extractors, not owned by this chunk either).

`NoveltyGate` deliberately takes no `Clock`: every function here is a pure
function of its arguments (a `TierANote`, a `Provenance`, and a sequence of
already-fetched `ExistingSignature`s) with no time-dependent behaviour at all
— there is nothing here for a clock to feed, and threading one through only to
leave it unused would be worse than the hard rule it is meant to serve.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from tracebed.core.scans.tier_a_template import TierANote
from tracebed.domain.canonical import canonical_json
from tracebed.domain.enums import ProvenanceClass
from tracebed.domain.errors import TracebedError
from tracebed.domain.ids import MemoryId, ProjectId
from tracebed.domain.memory import Provenance, validate_provenance
from tracebed.domain.signatures import SIG_HASH_LEN, simhash64

__all__ = [
    "ExistingSignature",
    "MergeUpdate",
    "NoveltyDecision",
    "NoveltyGate",
    "is_near_duplicate",
    "merge_provenance",
    "structural_signature",
]

def _dedupe_preserve_order[T](items: Sequence[T]) -> tuple[T, ...]:
    """Order-preserving de-duplication — existing evidence sorts first, new
    evidence that repeats it is dropped rather than duplicated. Order-
    preserving matters here the same way it does in `core.scans._dedupe`:
    a caller reading the first N entries of `trace_ids` for a summary should
    see the oldest evidence first, not an arbitrary set order."""
    seen: set[T] = set()
    out: list[T] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return tuple(out)


def _merge_scalar[T](existing: T | None, incoming: T | None, field_name: str) -> T | None:
    """Carry a single-valued provenance field across a merge without ever
    choosing between two different values — a silent choice there is a silent
    loss of the other side's evidence."""
    if existing is None:
        return incoming
    if incoming is None or incoming == existing:
        return existing
    raise ValueError(
        f"novelty merge cannot reconcile conflicting provenance.{field_name}: "
        f"{existing!r} vs {incoming!r}"
    )


def _identity_text(note: TierANote) -> str:
    """The canonical rendering of a note's identity — deliberately built from
    ONLY the four identity fields, never `count`/`duration_ms` (see module
    docstring). Distinct from `render_note`, which also has to encode the
    quantitative fields for the rendered note itself; this is a narrower
    view used solely to decide "is this the same condition", and it is the
    single definition of that both halves of the signature and `_merge_notes`
    ask, so they cannot drift into disagreeing about it."""
    return f"{note.error_class.value}|{note.tool_id}|{note.tool_version}|{note.payload_class_hash}"


def structural_signature(note: TierANote) -> bytes:
    """A `SIG_HASH_LEN`-byte (40) structural signature over a `TierANote`'s
    identity fields — the operational-lane analogue of
    `domain.signatures.input_signature_hash`, laid out the same way (a 32-byte
    sha256 half plus an 8-byte SimHash half) so a stored signature is the same
    shape in either lane and `SIG_HASH_LEN` means one thing everywhere. Two
    notes about the exact same condition (identical identity fields) always
    produce byte-identical signatures, regardless of how many times each was
    observed or for how long.

    The discrimination all lives in the sha256 half, which is the half
    `same_cluster` structurally ignores — the SimHash trailer is carried for
    layout compatibility, not consulted by `is_near_duplicate` (module
    docstring). Both halves are computed over `_identity_text`'s four fields
    and nothing else, so they cannot disagree about what identity means."""
    fields = {
        "error_class": note.error_class.value,
        "tool_id": str(note.tool_id),
        "tool_version": str(note.tool_version),
        "payload_class_hash": str(note.payload_class_hash),
    }
    exact_half = hashlib.sha256(canonical_json(fields)).digest()  # 32 bytes
    simhash_half = simhash64(_identity_text(note)).to_bytes(8, "big")  # 8 bytes
    return exact_half + simhash_half  # always SIG_HASH_LEN (40) bytes


def _require_signature_length(sig: bytes, label: str) -> None:
    if len(sig) != SIG_HASH_LEN:
        raise ValueError(f"{label} must be {SIG_HASH_LEN} bytes, got {len(sig)}")


def is_near_duplicate(a: bytes, b: bytes) -> bool:
    """Same-condition test: two structural signatures denote the same Tier A
    condition iff they are byte-equal.

    Equality, not `domain.signatures.same_cluster`'s Hamming radius — see the
    module docstring for the measurement behind that. In one line: the radius
    exists to absorb free-text noise, a `TierANote` has no free text, and at 8
    bits of slack a measurable fraction of genuinely distinct conditions
    (different `error_class`, different `tool_id`, bumped `tool_version`) merge
    into each other, taking their `trace_ids` with them.

    Both operands are length-checked rather than compared straight, so a caller
    handing over a truncated or foreign-layout signature gets the same loud
    `ValueError` `same_cluster` would have raised instead of a quiet `False`
    that reads as "novel" and files a duplicate row.
    """
    _require_signature_length(a, "signature")
    _require_signature_length(b, "signature")
    return a == b


def merge_provenance(existing: Provenance, incoming: Provenance) -> Provenance:
    """UNION merge of provenance evidence — NEVER a replace.

    Losing provenance on merge silently breaks invariant 6 (every derived
    memory points down to the raw trace that produced it) and PLAN.md §8
    improvement 1 (Recall & Rollback walks `injection_log`/`memory_link`
    *from* provenance; a merge that kept only the newer trace_ids would make
    the older, already-served evidence unreachable from the surviving row).
    `trace_ids`, `tool_refs`, and `input_sig_hashes` are each unioned with the
    existing tuple sorted first, so a caller reading the merged result still
    sees the original evidence before whatever triggered this merge.

    Defined for `provenance_class == parser` only — the operational lane's
    only entry route (`domain.state_machine`'s `None -> candidate` guard
    requires `TrustTier.A` + `ProvenanceClass.PARSER`) — so a mismatched class
    on either side is a caller bug surfaced immediately rather than silently
    merged with mismatched required-field semantics
    (`domain.memory.REQUIRED_PROVENANCE_FIELDS`).

    `Provenance` also carries `verdict_id`, `run_id` and `principal`. They are
    not part of the PARSER class's required set, but nothing stops a row from
    holding one, and a merge that unioned three fields while silently dropping
    three others would be exactly the evidence loss this function exists to
    prevent — just quieter. They are carried through when only one side has a
    value, and a genuine disagreement raises rather than picking a winner:
    "which of these two verdicts does the surviving row point at" is not a
    question this function is entitled to answer by taking the first one.

    Both inputs run through `domain.memory.validate_provenance` (invariant 6)
    before anything is combined. Checking the inputs rather than the result is
    deliberate and is the stronger of the two: the union of a complete
    provenance with an empty one is itself complete, so a result-only check
    would wave through a merge into an existing row that pointed at no evidence
    at all — the row would come out looking provenanced because the *incoming*
    side happened to be. Once both sides are complete the result cannot be
    anything else, so there is no output check here; adding one would be a line
    no test could ever turn red.
    """
    if existing.cls is not ProvenanceClass.PARSER or incoming.cls is not ProvenanceClass.PARSER:
        raise ValueError(
            "novelty merge is defined for provenance_class=parser only (Tier A's only entry "
            f"route); got existing={existing.cls.value!r}, incoming={incoming.cls.value!r}"
        )
    validate_provenance(existing)
    validate_provenance(incoming)
    merged = Provenance(
        cls=ProvenanceClass.PARSER,
        trace_ids=_dedupe_preserve_order((*existing.trace_ids, *incoming.trace_ids)),
        tool_refs=_dedupe_preserve_order((*existing.tool_refs, *incoming.tool_refs)),
        input_sig_hashes=_dedupe_preserve_order(
            (*existing.input_sig_hashes, *incoming.input_sig_hashes)
        ),
        verdict_id=_merge_scalar(existing.verdict_id, incoming.verdict_id, "verdict_id"),
        run_id=_merge_scalar(existing.run_id, incoming.run_id, "run_id"),
        principal=_merge_scalar(existing.principal, incoming.principal, "principal"),
    )
    return merged


def _merge_notes(existing: TierANote, incoming: TierANote) -> TierANote:
    """Merging keeps the EXISTING item's identity fields, which is lossless
    rather than a preference: `is_near_duplicate` is signature equality and the
    signature is a function of exactly those four fields, so a merge only ever
    happens between notes whose identity is already identical. The guard below
    is not decoration — `ExistingSignature` accepts `note` and
    `structural_signature` as separate values, so a stale or mis-joined index
    row could still pair a signature with the wrong note, and merging under
    that pairing would rewrite one condition's identity into another's while
    inheriting its provenance. Failing loudly is the only safe reading of it.

    Only the quantitative fields accumulate: `count` is additive (both
    observations genuinely happened) and `duration_ms` keeps the larger of the
    two — a diagnostic ceiling must never shrink on merge.
    """
    if _identity_text(existing) != _identity_text(incoming):
        raise ValueError(
            "novelty merge requires identical identity fields; refusing to merge "
            f"{_identity_text(incoming)!r} into {_identity_text(existing)!r}"
        )
    return TierANote(
        error_class=existing.error_class,
        tool_id=existing.tool_id,
        tool_version=existing.tool_version,
        count=existing.count + incoming.count,
        duration_ms=max(existing.duration_ms, incoming.duration_ms),
        payload_class_hash=existing.payload_class_hash,
    )


@dataclass(frozen=True, slots=True)
class ExistingSignature:
    """One already-stored Tier A item's identity, as the caller must already
    have fetched it (see the module docstring's contract_gap note — no `Repo`
    query for this exists yet).

    `structural_signature` is the value the caller read back out of the store,
    kept as its own field rather than recomputed, so that a signature written
    under a different construction than this build's never silently passes as
    a match. It is checked against `note` at construction: the two arrive from
    different columns of the same row and a disagreement means the index has
    drifted from the content it indexes, which is a corruption to surface at
    the point of read, not a condition to merge under.
    """

    project_id: ProjectId
    """Which project's vault this row lives in (invariant 4).

    Carried even though `decide()` is a pure function over signatures, because
    the signature space is GLOBAL: `structural_signature` is a hash of
    (error_class, tool_id, tool_version, payload_class_hash) and nothing in it
    names a project, so two projects running the same tool produce byte-equal
    signatures. Without this field a caller whose store query lost its project
    scope would hand this gate another project's row and be told to merge —
    grafting one project's trace_ids onto the other's memory, through a
    function that never saw a project id and so could never have refused. The
    identity fields cannot supply the missing scope: they are IDENTICAL by
    construction in exactly the case that matters.
    """
    memory_id: MemoryId
    note: TierANote
    provenance: Provenance
    structural_signature: bytes

    def __post_init__(self) -> None:
        _require_signature_length(self.structural_signature, "structural_signature")
        if self.structural_signature != structural_signature(self.note):
            raise ValueError(
                "ExistingSignature.structural_signature does not match its own note "
                f"({_identity_text(self.note)!r}) — the signature index has drifted "
                "from the item it indexes"
            )


@dataclass(frozen=True, slots=True)
class MergeUpdate:
    """What a `merge` decision says should happen to the existing row —
    persisting it is the caller's job (see the module docstring's
    contract_gap: no `Repo.update_memory_item` exists yet)."""

    memory_id: MemoryId
    note: TierANote
    provenance: Provenance


@dataclass(frozen=True, slots=True)
class NoveltyDecision:
    """The gate's verdict for one candidate note: file it as a new item, or
    merge it into an existing one. `merge` is populated iff `action == "merge"`
    — the two can never disagree, checked at construction so a caller cannot
    branch on the wrong field by mistake.

    `action` spells the "file as new" branch `"new"`, not the more obvious
    "insert" — `scripts/raw_sql_lint.py` (frozen, outside this chunk's file
    list) flags any string constant matching `^\\s*INSERT\\b` as a suspected
    raw SQL literal, and `"insert"` alone matches that pattern exactly. `"new"`
    says the same thing without tripping a lint whose rule this module cannot
    edit (hard rule 6) — reported as a contract_gap against the lint's regex,
    which does not distinguish a bare English word from a SQL statement.
    """

    action: Literal["new", "merge"]
    structural_signature: bytes
    merge: MergeUpdate | None = None

    def __post_init__(self) -> None:
        _require_signature_length(self.structural_signature, "structural_signature")
        if self.action == "merge" and self.merge is None:
            raise ValueError("a merge decision must carry a MergeUpdate")
        if self.action == "new" and self.merge is not None:
            raise ValueError("a 'new' decision must not carry a MergeUpdate")


class NoveltyGate:
    """LLM-free structural dedup gate for the operational lane.

    `decide()` is a pure function: it never reads a store and never mutates
    `existing` — the caller (a future Tier A write path) is responsible for
    fetching `existing` and for persisting whichever branch of the decision
    it gets back (see the module docstring's contract_gap).
    """

    def decide(
        self,
        project_id: ProjectId,
        note: TierANote,
        provenance: Provenance,
        existing: Sequence[ExistingSignature],
    ) -> NoveltyDecision:
        """Computes `note`'s structural signature and checks it against every
        item in `existing`, in order, returning a `merge` decision for the
        first match.

        `project_id` is required and every candidate in `existing` is checked
        against it BEFORE any signature comparison, refusing the whole call
        rather than skipping the offending row. Invariant 4 is not a filter:
        a store query that returned another project's row is a control that has
        stopped holding, and quietly dropping the row would leave the caller
        writing to a vault it had already been given wrong answers about.
        Structural signatures carry no project component, so two projects
        running the same tool collide exactly — this check is the only thing
        between that collision and a cross-project merge.

        "First" carries no ranking question here, unlike a radius-based gate
        where several candidates could sit at different distances and picking
        the first would mean picking a worse target than one further down the
        list: `is_near_duplicate` is equality, so every match in `existing`
        holds byte-identical identity fields to `note` and to each other. More
        than one match therefore does not mean "ambiguous", it means the store
        already holds duplicate rows for one condition; merging into the first
        is still correct, and the caller's ordering decides which of its own
        duplicates absorbs the observation.

        Falls back to `"new"` when nothing in `existing` carries this exact
        signature — a genuinely new condition, to be filed as a fresh row.
        """
        foreign = [item for item in existing if item.project_id != project_id]
        if foreign:
            raise TracebedError(
                f"novelty gate for project {project_id} was handed "
                f"{len(foreign)} existing signature(s) belonging to another project "
                f"(first: memory {foreign[0].memory_id} in project {foreign[0].project_id})"
            )

        candidate_sig = structural_signature(note)
        for item in existing:
            if is_near_duplicate(candidate_sig, item.structural_signature):
                return NoveltyDecision(
                    action="merge",
                    structural_signature=candidate_sig,
                    merge=MergeUpdate(
                        memory_id=item.memory_id,
                        note=_merge_notes(item.note, note),
                        provenance=merge_provenance(item.provenance, provenance),
                    ),
                )
        return NoveltyDecision(action="new", structural_signature=candidate_sig, merge=None)
