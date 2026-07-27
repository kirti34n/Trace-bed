"""JIT (just-in-time) retrieval trigger logic (PLAN.md §7 Phase 2 / §8 improvement 5).

CUTTABLE improvement 5. The SDK-side hook this backs (`sdk.client.TracebedClient
.on_operational_event`) shipped in Phase 1 as a stub that always returns `None` — "this
ships the hook, not a placeholder decision" (that module's own docstring). This module is
the trigger logic that hook was left for: given ONE operational trace event, decide whether
it is the FIRST tool error or FIRST schema failure this run has seen and, if so, run a single
narrow retrieval for the one matching lesson.

WHY ONLY ONE, EVER, PER RUN (PLAN.md §7, verbatim): "a second retrieval mid-run competing
with the model's own recovery is worse than none." `JitGate` enforces this by CLAIMING the
run — an atomic test-and-set under a lock — the instant an event classifies as a trigger,
before the retrieval it causes is even attempted, and regardless of whether that retrieval
injects, abstains, or fails. The lock is not decoration: an agent runtime that issues two
tool calls concurrently delivers two `on_operational_event` callbacks concurrently, and a
plain `if run_id in self._fired: ... self._fired.add(run_id)` is a check-then-act that both
threads pass, producing exactly the two competing mid-run retrievals the rule forbids.

Reuses the existing abstention path exactly, not a JIT-specific approximation of it:
`hotpath.abstention.decide` (raw, pre-fusion signals, never an RRF rank — D-015) and
`hotpath.calibration.calibrated_score` gate and rank candidates the same way the ordinary
retrieval path does; only the input population differs (candidates are additionally filtered
to `MemType.LESSON` at `Status.VALIDATED`, and the winner is capped at one). If nothing
clears the bar, this injects nothing — abstention is a working outcome, not a failure.

WHY A JIT LESSON MUST BE `VALIDATED`, NOT MERELY RETRIEVABLE: `assert_dynamically_retrievable`
admits a Tier A `candidate` row as well, but the ordinary path renders such a row into
`Slot.CANDIDATE_NOTE` (`hotpath.assembly.slot_for`) precisely because PLAN.md §5 says a
candidate is "Tier A only, labeled lower-trust, cap 1/run". `Slot.JIT_LESSON` carries no
lower-trust label, and this second checkpoint has no visibility into whether the run's
`tier_a.candidate_cap_per_run` was already spent by `/v1/retrieve` — so admitting candidates
here would both strip the label and breach a PER-RUN cap that no component could then
enforce. That matters beyond bookkeeping: Tier A notes are parsed straight out of a run's own
tool errors and enter at `candidate` with no quarantine, so "fail a tool, get your own note
back on the next failure, unlabeled" would be a same-day self-poisoning loop. Restricting to
`validated` closes it by construction; the outer `assert_dynamically_retrievable` call stays
as the store-side predicate check it already was.

CONTRACT GAPS (reported, not silently guessed — none of these are pinned by PLAN.md or
PHASE0-CONTRACT.md, so the choices below are this chunk's inference, not an invented
"magic number"):

  * There is no wire-level definition of "a tool error" or "a schema failure" distinct from
    the ordinary `ToolResult` trace event. `classify_trigger` reads `payload["ok"]` (the same
    key `harness/fake_runtime.py` already writes for a successful call) and, when it is
    falsy, `payload["error_class"]` against `core.scans.tier_a_template.ErrorClassEnum` — the
    one closed vocabulary this codebase already uses for operational error classification —
    to split TOOL_ERROR from the narrower SCHEMA_FAILURE. A `ToolResult` with no `ok` key is
    treated as successful (`payload.get("ok", True)`), matching that same fixture's shape.
  * `domain.enums.OutcomeCode` (frozen Phase-0 surface) has no "feature disabled" member, so
    the killswitch-off path reuses `OutcomeCode.EMPTY_RESULT` — the same reuse-and-report
    move D-046 already made for the abstention gates, for the same reason (adding a member
    means touching a frozen file this chunk does not own).
  * No schema exists for a JIT-specific telemetry row: `retrieval_event`'s primary key is
    `(project_id, run_id)` (PLAN.md §5), so a second, JIT-triggered retrieval mid-run cannot
    get its own row without either colliding with the run's ordinary `/v1/retrieve` row or a
    schema change outside this chunk's file list. `JitTelemetryPort` is therefore an injected
    seam with no concrete Postgres-backed implementation shipped here; wiring one is future,
    cross-chunk work. `injection_log` is NOT in that position and is therefore written for
    real (see `JitInjectionRecorderPort`): its primary key is `(project_id, run_id,
    memory_id)`, so a JIT injection gets its own row without colliding with anything the
    ordinary retrieval wrote for the same run.
  * The killswitch holdout arm (D-027) is not consulted here, deliberately. `hotpath.holdout`
    states that Phase 1/2 assign and log the arm but do not act on it — withholding injection
    for the holdout arm is Phase 3 — so a `JitGate` that withheld today would be the ONLY
    component acting on the arm, making a holdout run memory-off for JIT and memory-on for
    `/v1/retrieve`. Reported rather than pre-empted: whoever makes the kill switch act must
    wire the arm into this class at the same time, or JIT becomes an unmeasured injection
    path into the holdout arm and the stratified lift D-027 computes is contaminated.

Purity (invariant 1): imports `domain`, `stores`, `hotpath`, and `core` only —
`scripts/purity_check.py` proves no generative client and no `workers`/`ingest`/`crypto`
module is reachable from here.
"""

from __future__ import annotations

import contextlib
import threading
from collections.abc import Sequence
from enum import StrEnum
from typing import Final, Protocol, runtime_checkable

from tracebed.core.scans.tier_a_template import ErrorClassEnum
from tracebed.domain.clock import Clock
from tracebed.domain.config import EffectiveConfig, RetrievalConfig
from tracebed.domain.enums import MemType, OutcomeCode, Slot
from tracebed.domain.events import ContextBlock, ContextSlot, ToolResult, TraceEvent
from tracebed.domain.ids import MemoryId, ProjectId, RunId
from tracebed.domain.scope import ProjectScope
from tracebed.domain.state_machine import Status
from tracebed.domain.visibility import RunVisibility, scope_visible
from tracebed.hotpath.abstention import AbstentionDecision, CandidateSignals, RarityEvidence, decide
from tracebed.hotpath.assembly import CandidateStorePort, killswitched, query_terms
from tracebed.hotpath.calibration import CalibratedSignals, calibrated_score
from tracebed.hotpath.fusion import FusedCandidate
from tracebed.hotpath.renderer import render
from tracebed.stores.pg.rows import InjectionRow
from tracebed.stores.pg.search import CandidateRow, assert_dynamically_retrievable

__all__ = [
    "JitGate",
    "JitInjectionRecorderPort",
    "JitRetrieverPort",
    "JitTelemetryPort",
    "JitTrigger",
    "RetrievalOutcomeLike",
    "classify_trigger",
]

# Minutes -> milliseconds. A unit conversion, not a policy constant: the policy number is
# `session.idle_ttl_min` (PLAN.md §6), read from `EffectiveConfig` on every call.
_MS_PER_MINUTE: Final[int] = 60_000


class JitTrigger(StrEnum):
    """Which of the two qualifying event shapes fired (module docstring). Internal to this
    chunk — not a member of `domain.enums`, which owns only cross-chunk wire vocabulary."""

    TOOL_ERROR = "tool_error"
    SCHEMA_FAILURE = "schema_failure"


@runtime_checkable
class RetrievalOutcomeLike(Protocol):
    """Structural mirror of `hotpath.retriever.RetrievalOutcome`, narrowed to the one field
    this module reads. Declared locally rather than imported, matching `hotpath.pipeline`'s
    own `RetrievalOutcomeLike` (same rationale: the real `Retriever` holds a live thread pool
    and a `SearchStore`, and a JIT test has no more reason to construct one than the pipeline
    tests do)."""

    @property
    def candidates(self) -> tuple[FusedCandidate, ...]: ...


@runtime_checkable
class JitRetrieverPort(Protocol):
    """Exactly `hotpath.retriever.Retriever.retrieve`'s call shape — the real `Retriever`
    satisfies this structurally with no change."""

    def retrieve(
        self, project_id: ProjectId, query_text: str, *, cfg: RetrievalConfig
    ) -> RetrievalOutcomeLike: ...


@runtime_checkable
class JitTelemetryPort(Protocol):
    """Records the outcome of one JIT trigger. See the module docstring's contract gap on
    why no concrete Postgres-backed implementation ships in this chunk."""

    def record_jit(
        self,
        project_id: ProjectId,
        run_id: RunId,
        *,
        trigger: JitTrigger,
        outcome_code: OutcomeCode,
    ) -> None: ...


@runtime_checkable
class JitInjectionRecorderPort(Protocol):
    """Writes the `injection_log` row for a JIT injection (PLAN.md §5).

    Exactly `stores.pg.telemetry.Telemetry.record_injections`'s call shape (and identical to
    `hotpath.pipeline.InjectionRecorderPort`, declared here rather than imported so this
    module keeps no dependency on the orchestrator it is a side channel to). Typed on the
    real `stores.pg.rows.InjectionRow` for the same reason `pipeline` gives: a mirrored
    Protocol would be contravariant in the wrong direction and the real implementation would
    stop satisfying its own port.

    Optional, and its call is individually guarded, so a deployment with no writer degrades
    to no forensics rather than to a failed injection. But it is NOT optional in the sense
    of "nice to have": `injection_log` is the only record of which memories entered a run's
    prompt, and it is what Phase 3's Recall & Rollback enumerates a poisoned memory's blast
    radius from. A JIT lesson that reached a prompt with no row here is a memory that
    forensics can never trace, which is precisely the case JIT most needs traced.
    """

    def record_injections(
        self, project_id: ProjectId, run_id: RunId, rows: Sequence[InjectionRow]
    ) -> None: ...


def classify_trigger(event: TraceEvent) -> JitTrigger | None:
    """Is this event a qualifying JIT trigger, and which kind (module docstring)?

    Only `ToolResult` events are ever classified — every other trace-event type (in
    particular `run_start`, `llm_call_meta`, `state_note`, `run_end`) is never a trigger,
    which is why this returns `None` for them unconditionally rather than inspecting their
    payloads at all.
    """
    if not isinstance(event, ToolResult):
        return None
    if event.payload.get("ok", True):
        return None
    error_class = event.payload.get("error_class")
    if error_class == ErrorClassEnum.SCHEMA_VALIDATION.value:
        return JitTrigger.SCHEMA_FAILURE
    return JitTrigger.TOOL_ERROR


def _jit_query_text(event: ToolResult, trigger: JitTrigger) -> str:
    """A short search query derived from the triggering event — never the event's raw
    payload verbatim (that would be exactly the free-text-passthrough D-019 forbids for
    Tier A; this text only ever reaches a BM25/ANN query, never a stored note, but the same
    discipline of "identifier-shaped fields only" is followed here too)."""
    parts = [trigger.value]
    tool_id = event.payload.get("tool_id")
    if isinstance(tool_id, str) and tool_id:
        parts.append(tool_id)
    error_class = event.payload.get("error_class")
    if isinstance(error_class, str) and error_class:
        parts.append(error_class)
    return " ".join(parts)


def _abstention_code(decision: AbstentionDecision) -> OutcomeCode:
    if decision.outcome_code is None:  # pragma: no cover - AbstentionDecision's own invariant
        raise ValueError("an abstaining decision must carry an outcome code")
    return decision.outcome_code


def _age_days(now_ms: int, row: CandidateRow) -> float:
    """Age in days from `created_at`, floored at 0 — identical rationale to
    `hotpath.assembly._age_days`: a skewed clock must cost recency precision, not this
    retrieval."""
    created_ms = row.created_at.timestamp() * 1000.0
    return max(0.0, (now_ms - created_ms) / 86_400_000.0)


class JitGate:
    """The trigger logic proper: classify, enforce the one-shot-per-run rule, retrieve,
    gate, and render at most one `Slot.JIT_LESSON` entry.

    `_fired` is in-process, per-instance state — the smallest amount of state that can make
    "only on the first occurrence" true across more than one `evaluate()` call for the same
    run. Two properties it must have and now does:

    * **Atomic.** Every read and write goes through `_claim`/`forget` under `_lock`. The
      check and the set are one critical section, so two concurrent callbacks for one run
      cannot both observe "not fired yet" (module docstring).
    * **Bounded.** This object lives for the lifetime of a server process while `RunId`s
      are unbounded, so an ever-growing set is a hot-path memory leak that no deployment
      would notice until it OOMed. Entries are dropped once they are older than
      `session.idle_ttl_min` (PLAN.md §6 — the config surface's own statement of how long a
      run's state is worth keeping; the same knob Valkey working memory expires on), read
      from `EffectiveConfig` on every call, never a literal here. The cost is bounded and
      stated: a single run still alive after its idle TTL can spend a second shot. That is
      strictly better than the alternative, which is that the process eventually dies.

    `forget(run_id)` releases a run's claim early; the natural call site is the
    SDK/pipeline integration's own `run_end()` handling, which is future, cross-chunk work.
    Nothing in this codebase calls it yet, which is exactly why the TTL bound above cannot
    be left to it.
    """

    def __init__(
        self,
        *,
        retriever: JitRetrieverPort,
        store: CandidateStorePort,
        clock: Clock,
        telemetry: JitTelemetryPort | None = None,
        injections: JitInjectionRecorderPort | None = None,
    ) -> None:
        self._retriever = retriever
        self._store = store
        self._clock = clock
        self._telemetry = telemetry
        self._injections = injections
        self._lock = threading.Lock()
        # Insertion-ordered by construction (dict), and inserted in non-decreasing
        # `now_ms` order, so expiry can stop at the first live entry instead of scanning —
        # or copying — every run this instance has ever seen. That matters: this runs on
        # the hot path once per triggering event.
        self._fired: dict[RunId, int] = {}

    def forget(self, run_id: RunId) -> None:
        """Drops this run's fired-state, so a future run reusing a recycled `RunId` (it
        never should, but nothing here assumes it cannot) is never mistaken for one that
        already spent its shot. See the class docstring on where this is meant to be called."""
        with self._lock:
            self._fired.pop(run_id, None)

    def _claim(self, run_id: RunId, cfg: EffectiveConfig) -> bool:
        """Atomically: expire stale entries, then test-and-set this run's one shot.

        Returns True exactly once per run per TTL window, for exactly one caller, even when
        several threads race here with the same `run_id` — which is the whole content of
        "only the FIRST tool error fires" once an agent runtime can make two tool calls at
        the same time.
        """
        now_ms = self._clock.now_ms()
        cutoff_ms = now_ms - cfg.session.idle_ttl_min * _MS_PER_MINUTE
        with self._lock:
            while self._fired:
                oldest = next(iter(self._fired))
                if self._fired[oldest] > cutoff_ms:
                    break
                del self._fired[oldest]
            if run_id in self._fired:
                return False
            self._fired[run_id] = now_ms
            return True

    def evaluate(
        self,
        scope: ProjectScope,
        run_id: RunId,
        event: TraceEvent,
        *,
        cfg: EffectiveConfig,
    ) -> ContextBlock | None:
        """`None` on every path except a real, budget-fitting injection: not a trigger, an
        already-fired run, the lesson mem_type killswitched off, an abstention, an empty
        result, or a retrieval/store failure all return `None` here — the caller (the SDK
        hook) has exactly one thing to do with a non-`None` result: append it."""
        trigger = classify_trigger(event)
        if trigger is None or not isinstance(event, ToolResult):
            return None
        # Claimed BEFORE anything below runs (module docstring): the one-shot guarantee is
        # about this run never ATTEMPTING a second JIT retrieval, not about the first
        # attempt having succeeded. A plain `assert` would have narrowed `event` above, but
        # `python -O` strips asserts, and a type narrowing that evaporates under a runtime
        # flag is not a narrowing — hence the explicit `isinstance` in the guard.
        if not self._claim(run_id, cfg):
            return None

        try:
            outcome_code, injection = self._retrieve_one_lesson(scope, event, trigger, cfg)
        except Exception:
            outcome_code, injection = OutcomeCode.STORE_ERROR, None

        self._record(scope.project_id, run_id, trigger, outcome_code)
        if injection is None:
            return None
        slot, row = injection
        self._record_injection(scope.project_id, run_id, row)
        return render((slot,))

    def _retrieve_one_lesson(
        self,
        scope: ProjectScope,
        event: ToolResult,
        trigger: JitTrigger,
        cfg: EffectiveConfig,
    ) -> tuple[OutcomeCode, tuple[ContextSlot, InjectionRow] | None]:
        # Shared with the ordinary path's own check (`assembly.killswitched`)
        # so the two injection paths cannot drift into disagreeing about what
        # "disabled" means for the same mem_type.
        if killswitched(MemType.LESSON, cfg):
            # Contract gap (module docstring): OutcomeCode has no "feature disabled" member.
            return OutcomeCode.EMPTY_RESULT, None

        query_text = _jit_query_text(event, trigger)
        outcome = self._retriever.retrieve(scope.project_id, query_text, cfg=cfg.retrieval)
        if not outcome.candidates:
            return OutcomeCode.EMPTY_RESULT, None

        rows = {
            row.memory_id: row
            for row in self._store.fetch_candidates(
                scope.project_id, [c.memory_id for c in outcome.candidates]
            )
            # `validated` only, never a Tier A `candidate` — see the module docstring's
            # "WHY A JIT LESSON MUST BE VALIDATED" note. This is a narrowing of, not a
            # replacement for, `assert_dynamically_retrievable` below.
            if row.mem_type is MemType.LESSON
            and row.status is Status.VALIDATED
            # MEMORY_PLAN §5's ownership model, the same predicate the ordinary path applies
            # (`hotpath.assembly`). Both injection paths must agree about who may see a scoped
            # memory, for the same reason both must agree about the kill switch.
            and scope_visible(row.scope_type, row.scope_id, RunVisibility(scope.agent_type_id))
        }
        if not rows:
            return OutcomeCode.EMPTY_RESULT, None

        rarity = self._rarity_lookup(scope.project_id, query_text, list(rows.values()))
        now_ms = self._clock.now_ms()

        best_row: CandidateRow | None = None
        best_score = float("-inf")
        abstentions: list[OutcomeCode] = []

        for fused in outcome.candidates:
            row = rows.get(fused.memory_id)
            if row is None:
                continue
            assert_dynamically_retrievable(row.memory_id, row.status, row.trust_tier)
            signals = CandidateSignals(
                cos_sim=None if fused.vector is None else fused.vector.raw_score,
                bm25_raw=None if fused.lexical is None else fused.lexical.raw_score,
                rarity=rarity[row.memory_id],
            )
            decision = decide(signals, cfg.abstention)
            score = calibrated_score(
                CalibratedSignals(
                    cos_sim=0.0 if fused.vector is None else fused.vector.raw_score,
                    q_value=row.q_value,
                    age_days=_age_days(now_ms, row),
                    validity=row.confidence,
                ),
                cfg.score,
            )
            if not decision.inject:
                abstentions.append(_abstention_code(decision))
                continue
            if best_row is None or score > best_score or (
                score == best_score and str(row.memory_id) < str(best_row.memory_id)
            ):
                best_row, best_score = row, score

        if best_row is None:
            return (abstentions[0] if abstentions else OutcomeCode.EMPTY_RESULT), None

        cap = cfg.budget.slot_caps.get(Slot.JIT_LESSON.value, 0)
        if best_row.token_count > cap:
            # A lesson too large for its own slot is dropped whole, never truncated —
            # identical rule to `hotpath.assembler._pack`. `>` and not `>=`: a lesson of
            # exactly `cap` tokens fits its cap, the same boundary `_pack`'s
            # `used + tokens > cap` draws.
            return OutcomeCode.EMPTY_RESULT, None

        slot = ContextSlot(
            slot=Slot.JIT_LESSON,
            memory_id=best_row.memory_id.value,
            tokens=best_row.token_count,
            text=best_row.content,
        )
        injection_row = InjectionRow(
            memory_id=best_row.memory_id,
            slot=Slot.JIT_LESSON,
            score=best_score,
            tokens=best_row.token_count,
        )
        return OutcomeCode.INJECTED, (slot, injection_row)

    def _rarity_lookup(
        self, project_id: ProjectId, query_text: str, rows: Sequence[CandidateRow]
    ) -> dict[MemoryId, RarityEvidence]:
        """Per-candidate rarity evidence for the (small) lesson-only candidate set — same
        computation as `hotpath.assembly.CandidateAssembly._rarity_lookup`, kept as its own
        copy rather than reused across that private method so this module has no dependency
        on `CandidateAssembly`'s instance state (only on the `CandidateStorePort` shape, via
        `query_terms`, which IS shared)."""
        terms = query_terms(query_text)
        corpus = self._store.corpus_size(project_id)
        if corpus <= 0 or not terms:
            return {
                row.memory_id: RarityEvidence(shared_term_doc_freq_pct=(), corpus_doc_count=corpus)
                for row in rows
            }

        frequencies = self._store.document_frequency(project_id, terms)
        evidence: dict[MemoryId, RarityEvidence] = {}
        for row in rows:
            content_terms = set(query_terms(row.content))
            shared = tuple(
                min(100.0 * frequencies.get(term, 0) / corpus, 100.0)
                for term in terms
                if term in content_terms
            )
            evidence[row.memory_id] = RarityEvidence(
                shared_term_doc_freq_pct=shared, corpus_doc_count=corpus
            )
        return evidence

    def _record(
        self, project_id: ProjectId, run_id: RunId, trigger: JitTrigger, outcome_code: OutcomeCode
    ) -> None:
        """Guarded like every telemetry write elsewhere in `hotpath/` (e.g.
        `pipeline.Pipeline._record_telemetry`): recording what happened must never itself
        become a second failure mode."""
        if self._telemetry is None:
            return
        with contextlib.suppress(Exception):
            self._telemetry.record_jit(
                project_id, run_id, trigger=trigger, outcome_code=outcome_code
            )

    def _record_injection(self, project_id: ProjectId, run_id: RunId, row: InjectionRow) -> None:
        """Write the one `injection_log` row for a JIT injection (see
        `JitInjectionRecorderPort`). Guarded for the same reason `_record` is: the memory is
        already in the caller's hands by the time this runs, so a failure here must cost
        forensics, never the injection itself."""
        if self._injections is None:
            return
        with contextlib.suppress(Exception):
            self._injections.record_injections(project_id, run_id, (row,))
