"""The connective tissue: fused candidates -> abstention -> calibrated score -> packed slots.

Every other piece of the hot read plane already existed and was tested in isolation
(`hotpath.retriever` retrieves and fuses, `hotpath.abstention` gates, `hotpath.calibration`
scores, `hotpath.assembler` packs a budget, `hotpath.renderer` renders). Nothing joined them:
`hotpath.fusion.FusedCandidate` carries a `memory_id` and the two arms' raw scores and
deliberately nothing else, while `hotpath.assembler.Candidate` needs the memory's actual text,
its `mem_type`, a token count and a calibrated score, and `hotpath.abstention.RarityEvidence`
needs per-term document frequencies and the corpus size. Four modules each documented that gap as
someone else's; this module is that someone.

It implements `hotpath.pipeline.CandidateAssemblyPort` structurally (no import of `pipeline`, so
the dependency runs one way only) and does exactly four things, in order:

  1. **Fetch** the candidate rows in ONE statement (`SearchStore.fetch_candidates`), which
     re-applies the retrievability predicate — a memory quarantined between the arm query and this
     one simply does not come back, so the window between two statements cannot put a
     no-longer-retrievable memory into a prompt.
  2. **Gate** each candidate through `abstention.decide` on its raw, pre-fusion arm signals
     (D-015: never an RRF rank), with rarity evidence built from `document_frequency` /
     `corpus_size`.
  3. **Score** each candidate with `calibration.calibrated_score` — the ranking composite, used
     only to order and to fill the budget, never to decide whether to inject (that is step 2's
     job, and only step 2's).
  4. **Pack** the injectable candidates into `budget.*` via `assembler.assemble`.

Three Postgres round trips, not one per candidate: the content fetch, the document-frequency
lookup for the query's terms, and the corpus count. That is a fixed cost independent of
`retrieval.fused_top_n`, which is the property that keeps this inside a 300ms p99 budget.

BUDGET NOTE (honest limitation, not a silent one): this module has no deadline of its own — its
signature comes from `CandidateAssemblyPort` and carries no budget. `hotpath.pipeline` checks the
total budget before the retriever, after the retriever, and again after this call, so an assembly
that overruns is correctly REPORTED (the call degrades to `timeout_prefix_only` rather than
claiming `injected` at 400ms) but is not PRE-EMPTED mid-statement. Pre-empting needs a
`statement_timeout` derived from the remaining deadline, which is a `stores.pg` concern and is
recorded as remaining work rather than faked here.

SCOPE VISIBILITY: every fetched row is also checked against `domain.visibility.scope_visible`
before it can become a `Candidate` (MEMORY_PLAN §5's ownership model). The arms return ids only,
so this is the first point at which `scope_type`/`scope_id` are known; until it landed, a
memory scoped to one agent type or one end user was retrievable by every run in the project.

INVARIANT 7, THIRD TIME: every fetched row is re-checked with
`stores.pg.search.assert_dynamically_retrievable` before it can become a `Candidate`. The SQL
predicate is the control, the store's own row parsers assert it held, and this asserts it held
on the last hop before `renderer.render()` — the only one of the three that no alternative
retrieval driver could bypass.

Purity (invariant 1): imports `domain`, `stores`, and `hotpath` only. No worker, no ingest, no
crypto, no provider SDK — `scripts/purity_check.py` proves it by reachability.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final, Protocol, runtime_checkable

from tracebed.domain.canonical import sha256_hex
from tracebed.domain.clock import Clock
from tracebed.domain.config import EffectiveConfig
from tracebed.domain.enums import MemType, OutcomeCode, Slot
from tracebed.domain.events import ContextSlot
from tracebed.domain.ids import MemoryId, ProjectId
from tracebed.domain.scope import ProjectScope
from tracebed.domain.state_machine import Status
from tracebed.domain.visibility import RunVisibility, scope_visible
from tracebed.hotpath.abstention import AbstentionDecision, CandidateSignals, RarityEvidence, decide
from tracebed.hotpath.assembler import Candidate, assemble
from tracebed.hotpath.calibration import CalibratedSignals, calibrated_score
from tracebed.hotpath.fusion import FusedCandidate
from tracebed.stores.pg.rows import InjectionRow
from tracebed.stores.pg.search import CandidateRow, assert_dynamically_retrievable

__all__ = [
    "CandidateAssembly",
    "CandidateSetResult",
    "CandidateStorePort",
    "killswitched",
    "query_terms",
    "slot_for",
]

# Word characters only, lowercased, order-preserving-unique. NOT pg_textsearch's tokenizer: this
# one does no stemming and drops no stopwords, and the pg one is not reachable from a pure
# function. The mismatch is deliberately in the strict direction. "Shared term" is computed with
# THIS tokenizer on both the query and the candidate's content, so it is self-consistent; the
# document frequency of each term is computed by the SERVER (`content @@@ term`) under the real
# tokenizer, so the df number is the real one. The only effect of the difference is that a query
# term and a candidate term that differ only by inflection are not counted as shared here even
# though the index would match them — i.e. the rarity gate sees FEWER shared rare terms than a
# stemming tokenizer would, and `rarity_min_shared_terms` is a `>=` bar. Undercounting can only
# turn an inject into an abstain, never the reverse (D-066).
_TERM_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-z]+")

# Which slot a retrieved memory occupies. A Tier-A `candidate` row overrides this to
# CANDIDATE_NOTE regardless of mem_type (PLAN.md §5: "candidate (Tier A only, labelled
# lower-trust, cap 1/run)" — the lower-trust label is the slot, and `templates.SECTION_LABELS`
# carries the wording). `Slot.JIT_LESSON` is deliberately unreachable here: it belongs to the
# just-in-time SDK hook whose trigger logic is a Phase 2 deliverable (PLAN.md §8.5), not to the
# ordinary retrieval path.
_SLOT_BY_MEM_TYPE: Final[dict[MemType, Slot]] = {
    MemType.SEMANTIC: Slot.FACT,
    MemType.EPISODIC: Slot.EXEMPLAR,
    MemType.LESSON: Slot.PITFALL,
    MemType.PREFERENCE: Slot.STATIC_PREFIX,
}

if set(_SLOT_BY_MEM_TYPE) != set(MemType):  # pragma: no cover - import-time totality guard
    raise RuntimeError(
        "_SLOT_BY_MEM_TYPE does not cover every MemType; a memory of the missing type would be "
        "retrieved and then silently discarded with no slot to place it in"
    )


@runtime_checkable
class CandidateStorePort(Protocol):
    """The three read queries this module needs. `stores.pg.search.SearchStore` satisfies it.

    Narrowed to three methods rather than depending on `SearchStore` itself so an offline test
    can supply fixed rows without a Postgres pool — the same reason every other seam in
    `hotpath/` is a Protocol.
    """

    def fetch_candidates(
        self, project_id: ProjectId, memory_ids: Sequence[MemoryId]
    ) -> list[CandidateRow]: ...

    def document_frequency(self, project_id: ProjectId, terms: Sequence[str]) -> dict[str, int]: ...

    def corpus_size(self, project_id: ProjectId) -> int: ...


@dataclass(frozen=True, slots=True)
class CandidateSetResult:
    """Structural match for `hotpath.pipeline.CandidateSetResult`, plus `injections`.

    Declared here rather than imported from `pipeline` so the dependency edge runs one way
    (`pipeline` -> this module's instances, never this module -> `pipeline`); a frozen dataclass
    satisfies `pipeline`'s Protocol-free consumption by attribute, and
    `tests/phase1/test_assembly.py` pins the two field sets against each other so they cannot
    drift apart.
    """

    outcome_code: OutcomeCode
    slots: Sequence[ContextSlot]
    top_score: float | None
    injections: tuple[InjectionRow, ...]
    """One `injection_log` row per placed memory (PLAN.md §5) — the only record
    of which memories entered a given run's prompt, and what score won each its
    slot. `Pipeline` writes them; nothing else can, because `score` exists
    nowhere in the rendered `ContextBlock`."""


def query_terms(text: str) -> tuple[str, ...]:
    """Order-preserving unique lowercase word tokens (see `_TERM_RE`)."""
    return tuple(dict.fromkeys(_TERM_RE.findall(text.lower())))


def killswitched(mem_type: MemType, cfg: EffectiveConfig) -> bool:
    """Is this memory type currently disabled by the kill-switch overlay?

    One definition, exported, because there are now two injection paths that
    must agree — `CandidateAssembly.run` (every `/v1/retrieve`) and
    `hotpath.jit.JitGate` — and a kill switch honoured by one of them and not
    the other is worse than none: it moves injection volume onto the
    unmeasured path instead of stopping it.

    Keyed on `MemType.value` because `killswitch_overlay` arrives from
    `killswitch_state`'s jsonb, where the keys are the enum's wire strings.
    A mem_type absent from the overlay is enabled — a kill switch that
    defaulted to "off" would make an empty overlay disable everything.
    """
    return cfg.killswitch_overlay.get(mem_type.value, False)


def slot_for(row: CandidateRow) -> Slot:
    """Which context slot this memory occupies (see `_SLOT_BY_MEM_TYPE`)."""
    if row.status is Status.CANDIDATE:
        return Slot.CANDIDATE_NOTE
    return _SLOT_BY_MEM_TYPE[row.mem_type]


class CandidateAssembly:
    """`CandidateAssemblyPort`: fused candidates -> a decided outcome + packed slot list."""

    def __init__(self, store: CandidateStorePort, clock: Clock) -> None:
        self._store = store
        self._clock = clock

    def run(
        self,
        scope: ProjectScope,
        *,
        query_text: str,
        candidates: Sequence[FusedCandidate],
        cfg: EffectiveConfig,
    ) -> CandidateSetResult:
        """Never returns a degradation code: `degraded_lexical` / `timeout_prefix_only` /
        `store_error` are rungs of the ladder, which is `hotpath.pipeline`'s to stamp. This
        method's whole vocabulary is `injected` / `abstained_threshold` / `abstained_rarity` /
        `empty_result` — the four outcomes of a retrieval that WORKED.

        Any exception raised here is caught by `Pipeline` as the store-error rung, so a failing
        query degrades the call rather than failing the agent's run (invariant 2).
        """
        if not candidates:
            return CandidateSetResult(
                outcome_code=OutcomeCode.EMPTY_RESULT, slots=(), top_score=None, injections=()
            )

        rows = {
            row.memory_id: row
            for row in self._store.fetch_candidates(
                scope.project_id, [c.memory_id for c in candidates]
            )
        }
        if not rows:
            # Every fused id was filtered out by the content fetch's retrievability predicate
            # (status changed under us) or has been deleted. Nothing was found, and nothing
            # abstained — "empty" is the honest code, not an abstention nobody made.
            return CandidateSetResult(
                outcome_code=OutcomeCode.EMPTY_RESULT, slots=(), top_score=None, injections=()
            )

        rarity = self._rarity_lookup(scope.project_id, query_text, list(rows.values()))
        now_ms = self._clock.now_ms()
        # `agent_type_id` is server-derived (`Repo.resolve_project`), never caller-asserted;
        # the other two references have no resolver yet and therefore match nothing (see
        # `domain.visibility`'s module docstring and PLAN.md's known-gaps section).
        visibility = RunVisibility(agent_type_id=scope.agent_type_id)

        injectable: list[Candidate] = []
        abstentions: list[OutcomeCode] = []
        best_score: float | None = None

        # `candidates` order is the RRF-fused order, so the abstention code reported below when
        # nothing injects is the best-ranked candidate's — deterministic, and the one an operator
        # reading the Abstention dashboard would ask about first.
        for fused in candidates:
            row = rows.get(fused.memory_id)
            if row is None:
                continue
            # Invariant 7, re-asserted on the LAST hop before anything can be rendered. The SQL
            # predicate is the control and `stores.pg.search` already checks its own rows, but
            # every one of those guarantees is a property of THAT module: a second arm, a cache
            # in front of the arms, or PLAN.md §9's Qdrant driver would satisfy
            # `CandidateStorePort` and bypass all of them while still reaching `render()`. This
            # raises (the ladder's store-error rung) rather than skipping the row, exactly as the
            # store's own post-condition does: a breached predicate is not one bad candidate, it
            # is a control that is no longer holding.
            assert_dynamically_retrievable(row.memory_id, row.status, row.trust_tier)
            if not scope_visible(row.scope_type, row.scope_id, visibility):
                # MEMORY_PLAN §5's ownership model, enforced. Retrieval used to filter on
                # `project_id` and the retrievability predicate and on NOTHING else, so an
                # `agent_type`-scoped memory written for one agent — or a `user`-scoped memory
                # written for one end user — was retrievable by every agent and every user in
                # the project. Skipped rather than raised: a row this run may not see is a
                # normal outcome of a query that does not yet carry the predicate (the arms
                # return ids only), not a breached control like a non-retrievable status.
                continue
            if killswitched(row.mem_type, cfg):
                # PLAN.md §2: a memory type on sustained negative lift is
                # auto-disabled. Until this landed, `killswitch_overlay` was
                # read by exactly one module in the tree — `hotpath.jit` —
                # so a killswitched mem_type was still retrieved and injected
                # by every ordinary /v1/retrieve call and disabled only on the
                # side channel. A kill switch honoured on one path out of two
                # is not a kill switch.
                #
                # Skipped, not counted as an abstention: `abstained_threshold`
                # and `abstained_rarity` are statements about this query's
                # evidence, and an operator reading the Abstention dashboard
                # would be misled into tuning thresholds against a row that was
                # never eligible. With nothing placed and no abstention made,
                # `_outcome_code` reports `empty_result`, which is the same
                # honest answer `hotpath.jit` gives for the identical
                # condition. That both must say "empty" is the shared contract
                # gap: `OutcomeCode` has no "feature disabled" member.
                continue
            decision = decide(_signals_for(fused, rarity[fused.memory_id]), cfg.abstention)
            score = calibrated_score(
                CalibratedSignals(
                    # The vector arm never evaluated this candidate on the ladder's
                    # `degraded_lexical` rung, so there is no cosine to weigh. 0.0 is the
                    # additive identity of the similarity TERM, not a claim that the candidate is
                    # orthogonal to the query: it removes the term's contribution rather than
                    # inventing one, and it keeps every candidate in the list on one ruler
                    # (re-normalising the remaining weights per-candidate would make two
                    # candidates' scores incomparable, which is worse for the thing this number
                    # is for — ordering them). Abstention is unaffected: `decide` SKIPS a gate
                    # with no evidence rather than reading this substitute (D-065).
                    cos_sim=0.0 if fused.vector is None else fused.vector.raw_score,
                    q_value=row.q_value,
                    age_days=_age_days(now_ms, row),
                    # `confidence` is the row's own stored validity term. PLAN.md §6 has no
                    # `score.validity_*` field to derive one from `trust_tier`/status, and
                    # inventing a literal here is exactly what hard rule 4 forbids; reported as a
                    # contract gap instead (D-067).
                    validity=row.confidence,
                ),
                cfg.score,
            )
            best_score = score if best_score is None else max(best_score, score)

            if not decision.inject:
                abstentions.append(_abstention_code(decision))
                continue
            injectable.append(
                Candidate(
                    slot=slot_for(row),
                    memory_id=row.memory_id,
                    mem_type=row.mem_type,
                    text=row.content,
                    tokens=row.token_count,
                    score=score,
                    # Content identity, not row identity: two different memory_ids carrying the
                    # same text (a Tier A candidate note duplicating an already-validated fact)
                    # must not both spend the budget. `assembler._dedup` collapses on this.
                    dedup_key=sha256_hex(row.content.encode("utf-8")),
                )
            )

        assembled = assemble(injectable, cfg=cfg)
        # Built from the CANDIDATES the assembler kept, not from the rendered `ContextSlot`s: a
        # `ContextSlot.memory_id` is optional (a static-prefix entry need not name a memory) and
        # carries no score, so reconstructing an `injection_log` row from one would mean
        # inventing the score column. Matching on the placed id set keeps both honest.
        placed_ids = {slot.memory_id for slot in assembled.slots if slot.memory_id is not None}
        injections = tuple(
            InjectionRow(
                memory_id=candidate.memory_id,
                slot=candidate.slot,
                score=candidate.score,
                tokens=candidate.tokens,
            )
            for candidate in injectable
            if candidate.memory_id.value in placed_ids
        )

        return CandidateSetResult(
            outcome_code=_outcome_code(bool(assembled.slots), abstentions),
            slots=assembled.slots,
            # The best calibrated score among everything CONSIDERED, not only among what was
            # injected: on an abstaining call that number is the whole diagnostic ("how close did
            # the best candidate get"), and reporting `None` there would erase it.
            top_score=best_score,
            injections=injections,
        )

    def _rarity_lookup(
        self, project_id: ProjectId, query_text: str, rows: Sequence[CandidateRow]
    ) -> dict[MemoryId, RarityEvidence]:
        """Per-candidate rarity evidence, from ONE `document_frequency` call for the whole query.

        Document frequency is a property of a TERM and the corpus, not of a candidate, so the
        lookup is per query, not per candidate; what differs per candidate is only WHICH of the
        query's terms it shares.
        """
        terms = query_terms(query_text)
        corpus = self._store.corpus_size(project_id)
        if corpus <= 0 or not terms:
            # No corpus is the cold-start case `abstention.rarity_gate_passes` already refuses
            # unconditionally; issuing a df query against it would be work whose answer cannot
            # change the decision.
            return {
                row.memory_id: RarityEvidence(shared_term_doc_freq_pct=(), corpus_doc_count=corpus)
                for row in rows
            }

        frequencies = self._store.document_frequency(project_id, terms)
        evidence: dict[MemoryId, RarityEvidence] = {}
        for row in rows:
            content_terms = set(query_terms(row.content))
            shared = tuple(
                # `min(..., 100.0)`: df and the corpus count come from two separate statements, so
                # a write landing between them could make the ratio exceed 1 by a row.
                # `RarityEvidence` refuses a percentage outside [0, 100], and a benign race must
                # not become the store-error rung of the ladder.
                min(100.0 * frequencies.get(term, 0) / corpus, 100.0)
                for term in terms
                if term in content_terms
            )
            evidence[row.memory_id] = RarityEvidence(
                shared_term_doc_freq_pct=shared, corpus_doc_count=corpus
            )
        return evidence


def _signals_for(fused: FusedCandidate, rarity: RarityEvidence) -> CandidateSignals:
    """The raw pre-fusion signals, `None` where the arm produced none (D-065)."""
    return CandidateSignals(
        cos_sim=None if fused.vector is None else fused.vector.raw_score,
        bm25_raw=None if fused.lexical is None else fused.lexical.raw_score,
        rarity=rarity,
    )


def _abstention_code(decision: AbstentionDecision) -> OutcomeCode:
    """`decide` returns a code on every non-inject decision; this is the type narrowing."""
    if decision.outcome_code is None:  # pragma: no cover - AbstentionDecision's own invariant
        raise ValueError("an abstaining decision must carry an outcome code")
    return decision.outcome_code


def _outcome_code(anything_placed: bool, abstentions: Sequence[OutcomeCode]) -> OutcomeCode:
    """`injected` if anything reached a slot; else the first abstention reason; else `empty`.

    "Else empty" is reachable without any abstention: every candidate cleared its gates and the
    budget still fit none of them (a `budget.*` override of 0, or one memory larger than its whole
    slot cap). Reporting `injected` for a block containing nothing would be a lie, and reporting
    an abstention would invent a decision nobody made.
    """
    if anything_placed:
        return OutcomeCode.INJECTED
    if abstentions:
        return abstentions[0]
    return OutcomeCode.EMPTY_RESULT


def _age_days(now_ms: int, row: CandidateRow) -> float:
    """Age in days from `created_at`, floored at 0.

    Floored rather than trusted: `created_at` is a server timestamp and `now_ms` comes from an
    injected `Clock`, so a clock skew of either sign is possible, and
    `CalibratedSignals.__post_init__` refuses a negative age — a skewed clock must cost recency
    precision, not the whole retrieval.
    """
    created_ms = row.created_at.timestamp() * 1000.0
    return max(0.0, (now_ms - created_ms) / 86_400_000.0)
