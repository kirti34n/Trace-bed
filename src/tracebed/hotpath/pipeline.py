"""The orchestrator: `retrieve(scope, run_ctx, *, session_id=None) -> RetrieveResult`
(PLAN.md §2 invariant 2, §3 hot read plane, §7 Phase 1).

Wires together, in order: holdout arm assignment (`holdout.assign_arm`), the
degradation ladder (`budget.Deadline`), retrieval (the already-built
`hotpath.retriever.Retriever` — BM25 + ANN + RRF fusion + its own embed sub-budget),
abstention + assembly (an injected `CandidateAssemblyPort`, implemented by
`hotpath.assembly.CandidateAssembly`), and rendering (`hotpath.renderer.render`, already built and pure). Writes a
`retrieval_event` for every call, including abstentions and failures
(`TelemetryPort.record_retrieval`).

THE DEGRADATION LADDER, exactly (PLAN.md §2 invariant 2):

    query-embed timeout (`embed_timeout_ms`)  -> lexical-only retrieval
                                               -> outcome_code = degraded_lexical
    total budget (`total_budget_ms`) exceeded -> static prefix only
                                               -> outcome_code = timeout_prefix_only
    store error (anything else unexpected)    -> nothing
                                               -> outcome_code = store_error

A run never blocks and never fails because of Tracebed: `retrieve()` does not
propagate any exception, including one raised by the code that records the
degradation (the telemetry write itself is individually guarded).

`CandidateAssemblyPort` is the seam between "which memories" and "which of them fit":
it receives the fused candidates this module retrieved and returns a decided outcome
code plus an ordered slot list ready for `renderer.render()`. It stayed unimplemented
through the whole parallel Phase 1 build — four modules each documented the gap as
someone else's — and `hotpath.assembly.CandidateAssembly` is the implementation
(fetch content, gate by abstention, score by calibration, pack by assembler). It is
injected rather than imported so this module never depends on `stores.pg` and stays
testable against a fake with no Postgres.

BUDGET, STATED PRECISELY: the total budget is checked THREE times, never derived from
how long a stage took — before the retriever, after the retriever, and after the
assembly seam. The third check is not redundant: the assembly seam issues its own
store round trips (candidate content, per-term document frequency, corpus size), and
without it a call could answer `injected` well past `total_budget_ms` while recording
a `retrieval_event` that says the budget held.
"""

from __future__ import annotations

import contextlib
import math
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from tracebed.domain.clock import Clock
from tracebed.domain.config import EffectiveConfig, RetrievalConfig
from tracebed.domain.enums import Arm, OutcomeCode
from tracebed.domain.events import (
    ContextBlock,
    ContextSlot,
    RetrieveResult,
    RunContext,
    empty_context_block,
)
from tracebed.domain.ids import AgentTypeId, ProjectId, RunId, mint_run_id
from tracebed.domain.scope import ProjectScope
from tracebed.hotpath.budget import Deadline
from tracebed.hotpath.fusion import FusedCandidate
from tracebed.hotpath.holdout import assign_arm
from tracebed.hotpath.renderer import render
from tracebed.stores.pg.rows import InjectionRow

__all__ = [
    "CandidateAssemblyPort",
    "CandidateSetResult",
    "CandidateSetResultLike",
    "ConfigProvider",
    "HybridRetrieverPort",
    "InjectionRecorderPort",
    "Pipeline",
    "RetrievalOutcomeLike",
    "StaticPrefixPort",
    "TelemetryRecorderPort",
]


@runtime_checkable
class ConfigProvider(Protocol):
    """What `Pipeline` needs to resolve per-(project, agent_type) settings.

    `domain.config.ConfigResolver` satisfies this structurally. The narrower
    Protocol is what lets pipeline tests supply a trivial fake — including one
    that raises, to prove config-resolution failure degrades to `store_error`
    rather than propagating — without constructing a full `TracebedSettings` /
    `ConfigStorePort` pair.
    """

    def effective(
        self, project_id: ProjectId, agent_type_id: AgentTypeId | None = None
    ) -> EffectiveConfig: ...


@runtime_checkable
class RetrievalOutcomeLike(Protocol):
    """Structural mirror of `hotpath.retriever.RetrievalOutcome`'s four fields.

    Declared locally, and NOT imported from `hotpath.retriever`, so that constructing a
    `Pipeline` in a test never drags in `hotpath.retriever`'s own dependencies (a live
    `ThreadPoolExecutor`, a `SearchStore`, an `EmbeddingPort`) just to name a result
    type. The real, frozen `RetrievalOutcome` dataclass satisfies this structurally — a
    Protocol matches a dataclass by shape, not by import identity — with zero change to
    `retriever.py`. `tests/phase1/test_pipeline.py` compares the two field sets, so the
    mirror cannot drift.

    (This Protocol and `TelemetryRecorderPort` below were originally introduced to route
    around a `scripts/purity_check.py` false positive on `TYPE_CHECKING`-guarded imports;
    that root cause is fixed — D-064 — and the reason recorded above is the one that
    still holds.)
    """

    # Read-only (`@property`, not plain annotations): a Protocol's plain attribute
    # annotations are implicitly read-WRITE, which the real `RetrievalOutcome` (a
    # frozen dataclass) cannot satisfy — frozen fields have no setter. Declaring
    # these as properties matches "readable, never mutated", which is exactly what
    # a frozen dataclass provides and all this module ever does with the result.
    @property
    def candidates(self) -> tuple[FusedCandidate, ...]: ...
    @property
    def degraded(self) -> bool: ...
    @property
    def embed_latency_ms(self) -> int: ...
    @property
    def candidates_considered(self) -> int: ...


@runtime_checkable
class HybridRetrieverPort(Protocol):
    """Exactly `hotpath.retriever.Retriever`'s call shape.

    A narrow, locally-declared Protocol rather than importing `Retriever` itself:
    `Retriever` is a concrete class holding a live `ThreadPoolExecutor` and a real
    `SearchStore`/`EmbeddingPort` pair, which would make every offline pipeline test
    drag in a thread pool and a fake Postgres pool just to satisfy a constructor.
    Structural typing means the real `Retriever` satisfies this Protocol with no
    change.
    """

    def retrieve(
        self, project_id: ProjectId, query_text: str, *, cfg: RetrievalConfig
    ) -> RetrievalOutcomeLike: ...


@runtime_checkable
class TelemetryRecorderPort(Protocol):
    """Exactly `adapters.ports.TelemetryPort`'s one method.

    Narrowed to the single method this module calls, so an offline pipeline test
    satisfies it with a three-line fake. The real `stores.pg.telemetry.Telemetry`
    satisfies it structurally with no change, exactly like every other Protocol in this
    file. (Originally declared locally to route around the `scripts/purity_check.py`
    `TYPE_CHECKING` false positive, now fixed — D-064.)
    """

    def record_retrieval(
        self,
        project_id: ProjectId,
        run_id: RunId,
        *,
        outcome_code: OutcomeCode,
        latency_ms: int,
        embed_latency_ms: int | None,
        candidates_considered: int,
        top_score: float | None,
        arm: Arm,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class CandidateSetResult:
    """What abstention + assembly hands back for one non-degraded call.

    `hotpath.assembly.CandidateAssembly` declares its own equivalent rather than
    importing this one (so `assembly` never imports `pipeline`); `Pipeline` reads
    either through `CandidateSetResultLike`."""

    outcome_code: OutcomeCode
    """One of INJECTED, ABSTAINED_THRESHOLD, ABSTAINED_RARITY, EMPTY_RESULT —
    never a degradation code; the ladder rungs are `Pipeline`'s job, not this
    seam's."""
    slots: Sequence[ContextSlot]
    """Already budget-packed, deduped, tier_a-capped, and ordered — exactly what
    `hotpath.renderer.render()` accepts as-is."""
    top_score: float | None
    injections: Sequence[InjectionRow] = ()
    """What to write to `injection_log`, one entry per placed memory. Defaulted
    so a seam that does not produce them (a fake in a test) is still valid; the
    real `hotpath.assembly.CandidateAssembly` always does."""


@runtime_checkable
class CandidateAssemblyPort(Protocol):
    """Seam for turning RRF-fused candidates into a decided outcome + ordered slot
    list: abstention (`hotpath.abstention.decide`, per candidate) and budget-packed
    assembly (`hotpath.assembler.assemble`) — both already built and pure, but wiring
    them needs each candidate's `memory_item` content/mem_type/tokens and rarity
    evidence (`stores.pg.search.SearchStore.document_frequency`/`corpus_size`), which
    is not yet built anywhere in this codebase (module CONTRACT GAP note).

    Raising ANY exception from `run` is treated by `Pipeline` as a store error
    (PLAN.md §2 invariant 2's third ladder rung): "nothing",
    `outcome_code=store_error`.
    """

    def run(
        self,
        scope: ProjectScope,
        *,
        query_text: str,
        candidates: Sequence[FusedCandidate],
        cfg: EffectiveConfig,
    ) -> CandidateSetResultLike: ...


@runtime_checkable
class CandidateSetResultLike(Protocol):
    """What `CandidateAssemblyPort.run` returns, by shape.

    `hotpath.assembly.CandidateAssembly` — the real implementation — returns its own frozen
    dataclass rather than importing `CandidateSetResult` from here, so that the dependency edge
    runs one way only (`pipeline` never appears in `assembly`'s import graph). Reading the result
    through a Protocol is what makes those two independent declarations one contract;
    `tests/phase1/test_assembly.py` pins the field sets against each other.
    """

    @property
    def outcome_code(self) -> OutcomeCode: ...
    @property
    def slots(self) -> Sequence[ContextSlot]: ...
    @property
    def top_score(self) -> float | None: ...
    @property
    def injections(self) -> Sequence[InjectionRow]: ...


@runtime_checkable
class StaticPrefixPort(Protocol):
    """Seam for the cached static prefix (`stores.valkey.keys.static_prefix_key`;
    the writer, `prefix_builder`, is a Phase 2 deliverable per PLAN.md §7). Absent,
    raising, or returning anything that is not a `ContextBlock`, `Pipeline` falls
    back to `empty_context_block()` while still reporting `timeout_prefix_only`."""

    def get(self, scope: ProjectScope) -> ContextBlock: ...


@runtime_checkable
class InjectionRecorderPort(Protocol):
    """Writes the `injection_log` rows for one retrieval (PLAN.md §5).

    Separate from `TelemetryRecorderPort` and optional, rather than a second method on it,
    because `adapters.ports.TelemetryPort` — Phase 0's frozen surface — declares only
    `record_retrieval`. `stores.pg.telemetry.Telemetry` already implements
    `record_injections(project_id, run_id, rows)` and satisfies this structurally with no change;
    until Phase 0's port is widened, this is how the row that answers "what was actually in that
    prompt, and why did it win its slot" gets written without editing frozen surface.

    Typed on the real `stores.pg.rows.InjectionRow` rather than on a locally-mirrored Protocol:
    a mirror would be contravariant in the wrong direction here (the concrete `Telemetry` method
    accepts `Sequence[InjectionRow]`, which is NOT a `Sequence[SomeProtocol]`), so the mirror
    would have made the real implementation fail to satisfy its own port — a duplicate type that
    is worse than no type. `hotpath` importing `stores.pg.rows` is explicitly permitted
    (invariant 1's allowlist) and that module imports `domain` only.
    """

    def record_injections(
        self, project_id: ProjectId, run_id: RunId, rows: Sequence[InjectionRow]
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class _LadderResult:
    outcome_code: OutcomeCode
    context_block: ContextBlock
    embed_latency_ms: int | None
    candidates_considered: int
    top_score: float | None
    injections: Sequence[InjectionRow] = ()


class Pipeline:
    """The orchestrator: holdout assignment, the degradation ladder, retrieval,
    abstention, assembly, and rendering (PLAN.md §2 invariant 2 / §3 hot read plane).

    `retrieve()` never propagates an exception. Every dependency call — config
    resolution, holdout assignment, the retriever, the candidate-assembly seam, the
    static-prefix fallback, the injected `Clock` itself, the construction of the
    response model, and the telemetry write that records the outcome — is
    individually guarded, so there is no path through this class that raises past
    `retrieve()`'s own boundary. That is the entire content of "a run never blocks
    and never fails because of Tracebed". The single boundary this class does NOT
    own is `mint_run_id()` failing outright (i.e. `os.urandom` failing), which is
    the one condition under which no `RetrieveResult` can be constructed at all;
    the SDK already covers it, which is exactly why `run_id_origin="sdk"` exists
    (D-018 / C-26: "the SDK had to mint its own run_id after a dead retrieve()").

    `agent_type_id` is deliberately NOT a parameter: it is read from
    `scope.agent_type_id`, which `Repo.resolve_project()` derived from the
    `agent_registration` row of the authenticated principal. `/v1/retrieve`'s body
    does carry an `agent_type` string, and taking a second, caller-influenced
    agent-type here would reopen invariant 4's wall one dimension in — agent-scoped
    memories and the per-agent-type static prefix (whose Valkey key,
    `stores.valkey.keys.static_prefix_key`, is built from the agent_type_id)
    would be selectable by whatever the caller asserted. `routes_v1.py` already
    follows this rule everywhere else (`_trace_envelope` stamps
    `str(scope.agent_type_id)`, never `body.agent_type`); this matches it.

    `session_id` is accepted as an optional keyword argument rather than read off
    `run_ctx`: `domain.events.RunContext` (owned by another chunk, not modified here)
    carries no session identity, only the wire-level `RunCtxIn` does (PHASE0-CONTRACT
    §9.3), where it is `str | None`. Absent, the minted run_id becomes the session
    key — a run with no session is its own session, which is trivially session-stable
    and keeps the holdout draw uniform, whereas a shared placeholder key would put
    every session-less run of an agent_type into one arm (see `holdout.assign_arm`).
    """

    def __init__(
        self,
        *,
        clock: Clock,
        config: ConfigProvider,
        telemetry: TelemetryRecorderPort,
        retriever: HybridRetrieverPort,
        assembly: CandidateAssemblyPort,
        static_prefix: StaticPrefixPort | None = None,
        injections: InjectionRecorderPort | None = None,
        holdout_salt: str,
    ) -> None:
        self._clock = clock
        self._config = config
        self._telemetry = telemetry
        self._retriever = retriever
        self._assembly = assembly
        self._static_prefix = static_prefix
        self._injections = injections
        self._holdout_salt = holdout_salt

    def retrieve(
        self,
        scope: ProjectScope,
        run_ctx: RunContext,
        *,
        session_id: str | None = None,
    ) -> RetrieveResult:
        """Mint the run id server-side (D-018) and run the full ladder.

        Defaults — `arm=memory_on`, `outcome_code=store_error`,
        `context_block=empty_context_block()` — are the answer returned when
        *nothing* downstream could even be attempted (e.g. config resolution
        itself failed); every guarded step below only ever narrows from there
        toward a more specific, successfully-computed outcome.
        """
        run_id = self._mint_run_id()
        mono_start = self._monotonic_ms()

        arm = Arm.MEMORY_ON
        outcome_code = OutcomeCode.STORE_ERROR
        context_block = empty_context_block()
        embed_latency_ms: int | None = None
        candidates_considered = 0
        top_score: float | None = None
        injections: Sequence[InjectionRow] = ()

        cfg: EffectiveConfig | None = None
        try:
            cfg = self._config.effective(scope.project_id, scope.agent_type_id)
        except Exception:
            cfg = None  # no budgets to read; nothing else this call can attempt

        # `mono_start is None` means the injected clock refused to report monotonic
        # time, so no stage below could be budgeted at all. Unbudgeted work on the
        # synchronous path is precisely what invariant 2 exists to forbid, so the
        # call degrades to the third rung instead of running the ladder blind.
        if cfg is not None and mono_start is not None:
            try:
                arm = assign_arm(
                    session_key=self._session_key(session_id, run_id),
                    agent_type_id=scope.agent_type_id,
                    salt=self._holdout_salt,
                    holdout_pct=cfg.killswitch.holdout_pct,
                )
            except Exception:
                # Holdout assignment failing must not block retrieval: it is
                # bookkeeping about learning, not learning itself (PLAN.md §2
                # invariant 2). Failing to `memory_on` also fails OPEN on the
                # withholding branch below — a broken hash silently withholding
                # memory from every run would be the worse of the two errors.
                arm = Arm.MEMORY_ON

            try:
                ladder = self._run_ladder(scope, run_ctx, cfg, started_at_ms=mono_start)
                outcome_code = ladder.outcome_code
                context_block = ladder.context_block
                embed_latency_ms = ladder.embed_latency_ms
                candidates_considered = ladder.candidates_considered
                top_score = ladder.top_score
                injections = ladder.injections
            except Exception:
                # Anything unexpected anywhere in the ladder — including inside
                # the retriever, the candidate-assembly seam, or the
                # static-prefix fallback — degrades to "nothing happened",
                # never an exception the caller sees (PLAN.md §2 invariant 2's
                # third ladder rung).
                outcome_code = OutcomeCode.STORE_ERROR
                context_block = empty_context_block()
                embed_latency_ms = None
                candidates_considered = 0
                top_score = None
                injections = ()

            if arm is Arm.HOLDOUT:
                # THE HOLDOUT ARM IS MEMORY-OFF (MEMORY_PLAN §5 "5% of runs execute memory-off";
                # PLAN.md §7 Phase 3 "kill switch acting"). Until this landed the pipeline
                # computed the arm, logged it, and then returned the identical rendered block on
                # both arms -- which made every lift number a comparison of memory-on against
                # memory-on, i.e. the earn-your-context loop could not fail because there was no
                # counterfactual. `workers.lift` reported it as a contract gap it could not fix
                # from its own module ("returns the rendered block to the caller on the holdout
                # arm ... which makes the holdout arm not a holdout at all").
                #
                # SHADOW-RETRIEVED, NOT UN-RETRIEVED. The ladder above has already run, and its
                # `injections` are still recorded: PLAN.md §7 stratifies lift on "runs where
                # something was actually injected vs SHADOW-RETRIEVED holdout", and
                # `workers.lift.is_shadow_control` uses the presence of an `injection_log` row --
                # not the outcome code -- to decide that a holdout run would have placed a
                # memory. A holdout arm that skipped retrieval entirely would empty the control
                # bucket and make the kill switch unable to fire.
                #
                # What the AGENT gets is nothing: the block is dropped here, after the record is
                # written and before `_result` builds the response. `OutcomeCode.HOLDOUT` --
                # carried by the schema since Phase 0 and emitted by nothing until now -- is what
                # marks the row; per `workers.lift` it is deliberately ambiguous about placement,
                # which is why the injection rows above remain the discriminator.
                outcome_code = OutcomeCode.HOLDOUT
                context_block = empty_context_block()

        return self._finish(
            scope,
            run_id,
            arm=arm,
            outcome_code=outcome_code,
            block=context_block,
            mono_start=mono_start,
            embed_latency_ms=embed_latency_ms,
            candidates_considered=candidates_considered,
            top_score=top_score,
            injections=injections,
        )

    def _finish(
        self,
        scope: ProjectScope,
        run_id: RunId,
        *,
        arm: Arm,
        outcome_code: OutcomeCode,
        block: ContextBlock,
        mono_start: float | None,
        embed_latency_ms: int | None,
        candidates_considered: int,
        top_score: float | None,
        injections: Sequence[InjectionRow],
    ) -> RetrieveResult:
        """The one exit. Invariant 2 says exactly one `retrieval_event` row per call on every
        path, including the holdout arm and every failure -- so there is exactly one place that
        writes it and builds the response."""
        self._record_injections(scope.project_id, run_id, injections)
        self._record_telemetry(
            scope.project_id,
            run_id,
            outcome_code=outcome_code,
            latency_ms=self._latency_ms(mono_start),
            embed_latency_ms=embed_latency_ms,
            candidates_considered=candidates_considered,
            top_score=top_score,
            arm=arm,
        )
        return self._result(run_id, arm=arm, outcome_code=outcome_code, block=block)

    # ----------------------------------------------------------------- #
    # Boundary guards. Each exists because the thing it wraps is the last
    # remaining way `retrieve()` could raise into an agent runtime.
    # ----------------------------------------------------------------- #

    def _mint_run_id(self) -> RunId:
        try:
            return mint_run_id(now_ms=self._clock.now_ms())
        except Exception:
            # `Clock` is an injected Protocol, so `now_ms()` is third-party code on
            # the hot path. UUIDv7 minting falls back to `ids.uuid7`'s own time
            # source (the same one `SystemClock.now_ms` reads) rather than costing
            # the caller its run; only the FakeClock-driven determinism of the
            # embedded timestamp is lost, and nothing on this path depends on it.
            return mint_run_id()

    def _monotonic_ms(self) -> float | None:
        try:
            return self._clock.monotonic_ms()
        except Exception:
            return None

    def _latency_ms(self, mono_start: float | None) -> int:
        """Elapsed milliseconds, or 0 when the clock could not be read.

        A row is still written in that case: invariant 2 says one `retrieval_event`
        per call with no exceptions, and a missing row would erase the evidence of
        exactly the failure that produced it. 0 is the honest "unmeasurable" value —
        it cannot be mistaken for a plausible latency the way an invented one could.
        """
        if mono_start is None:
            return 0
        try:
            return max(0, int(self._clock.monotonic_ms() - mono_start))
        except Exception:
            return 0

    @staticmethod
    def _session_key(session_id: str | None, run_id: RunId) -> str:
        """The holdout draw's session dimension (D-027, `holdout.assign_arm`).

        A blank or absent `session_id` is not a session — it is the absence of one
        (`api.models.RunCtxIn.session_id` is `str | None`). Substituting the minted
        run_id makes each session-less run its own session: still deterministic for
        that run, still uniform across runs. Reusing one placeholder key instead
        would hash every session-less run of an agent_type into a single arm.
        """
        if session_id is not None and session_id.strip():
            return session_id
        return str(run_id)

    def _result(
        self,
        run_id: RunId,
        *,
        arm: Arm,
        outcome_code: OutcomeCode,
        block: ContextBlock,
    ) -> RetrieveResult:
        """Build the response model, which is Pydantic and therefore validates.

        `block` originates either from `renderer.render()` (always a valid
        `ContextBlock`) or from the injected `StaticPrefixPort` — a seam whose real
        implementation is a Phase 2 deliverable and whose return value is therefore
        unvalidated third-party data today. `_timeout_prefix_only` already rejects a
        non-`ContextBlock`; this is the second line, so that a validation error here
        can never be the thing that fails an agent's run.
        """
        try:
            return RetrieveResult(
                run_id=run_id.value,
                run_id_origin="server",
                arm=arm,
                outcome_code=outcome_code,
                context_block=block,
            )
        except Exception:
            return RetrieveResult(
                run_id=run_id.value,
                run_id_origin="server",
                arm=Arm.MEMORY_ON,
                outcome_code=OutcomeCode.STORE_ERROR,
                context_block=empty_context_block(),
            )

    def _run_ladder(
        self,
        scope: ProjectScope,
        run_ctx: RunContext,
        cfg: EffectiveConfig,
        *,
        started_at_ms: float,
    ) -> _LadderResult:
        """The degradation ladder proper. Every stage checks
        `deadline.remaining_ms()` / `total_exceeded()` BEFORE it starts
        (`budget.py`'s own docstring): a stage that starts with 5ms left and
        takes 80ms has already blown the budget, so the check happens first,
        never derived from how long the stage took.

        The deadline is anchored at `started_at_ms` — the reading `retrieve()`
        took on entry, before config resolution and holdout assignment — not at
        this method's own entry. `ConfigResolver.effective()` reads
        `project_config` / `agent_type_config`, so it can stall; a deadline
        anchored here would exclude that stall from the very budget it blew.

        `Retriever.retrieve()` (PLAN.md §7) already owns the embed sub-budget
        internally — it degrades to lexical-only and reports
        `RetrievalOutcome.degraded=True` on an `EmbeddingTimeout`, which this
        method maps straight to `OutcomeCode.DEGRADED_LEXICAL` (the ladder's
        first rung) regardless of what the fused candidates ultimately decide,
        exactly like every other rung: the recorded code describes *why*
        degradation happened, not what was found afterward.
        """
        deadline = Deadline(
            clock=self._clock,
            total_budget_ms=cfg.retrieval.total_budget_ms,
            embed_timeout_ms=cfg.retrieval.embed_timeout_ms,
            started_at_ms=started_at_ms,
        )

        if deadline.total_exceeded():
            return self._timeout_prefix_only(scope, embed_latency_ms=None)

        outcome: RetrievalOutcomeLike = self._retriever.retrieve(
            scope.project_id, run_ctx.query_text, cfg=self._embed_bounded(cfg.retrieval, deadline)
        )

        if deadline.total_exceeded():
            # Re-checked after the retriever call: total-budget exhaustion always
            # wins over a merely-degraded embed, because "nothing was retrieved
            # at all" is the worse degradation of the two.
            return self._timeout_prefix_only(
                scope, embed_latency_ms=outcome.embed_latency_ms
            )

        assembled = self._assembly.run(
            scope,
            query_text=run_ctx.query_text,
            candidates=outcome.candidates,
            cfg=cfg,
        )

        if deadline.total_exceeded():
            # Checked a THIRD time, after assembly. The assembly seam fetches candidate content,
            # per-term document frequencies and the corpus size — three more store round trips
            # that the two earlier checks cannot have covered, because they happened before the
            # work existed. Without this the call would answer `injected` at 400ms and record a
            # `retrieval_event` saying the budget held. `timeout_prefix_only` is what actually
            # happened, and returning the prefix instead of a block assembled past the deadline
            # is what invariant 2 means by degrading.
            return self._timeout_prefix_only(scope, embed_latency_ms=outcome.embed_latency_ms)

        outcome_code = (
            OutcomeCode.DEGRADED_LEXICAL if outcome.degraded else assembled.outcome_code
        )
        context_block = render(assembled.slots)
        return _LadderResult(
            outcome_code=outcome_code,
            context_block=context_block,
            embed_latency_ms=outcome.embed_latency_ms,
            candidates_considered=outcome.candidates_considered,
            top_score=assembled.top_score,
            injections=assembled.injections,
        )

    @staticmethod
    def _embed_bounded(retrieval: RetrievalConfig, deadline: Deadline) -> RetrievalConfig:
        """`retrieval.embed_timeout_ms`, clamped to what is left of the total budget.

        The two budgets in PLAN.md §6 are nested, not independent: an embed call
        allowed its full `embed_timeout_ms` when only 40ms of `total_budget_ms`
        remain overruns the budget the caller is actually waiting on, and the
        overrun is only detectable afterwards — the exact "budget checked after the
        work" shape this ladder exists to avoid. Both numbers still come from
        config; this only ever narrows, never widens (`embed_sub_budget_ms` is
        `min(embed_timeout_ms, remaining)`), and it is reached only after
        `total_exceeded()` was false, so the clamped value is at least 1ms and can
        never be handed to `EmbeddingPort.embed` as a degenerate `timeout_ms=0`.
        """
        bounded = math.ceil(deadline.embed_sub_budget_ms())
        if bounded >= retrieval.embed_timeout_ms:
            return retrieval
        return retrieval.model_copy(update={"embed_timeout_ms": bounded})

    def _timeout_prefix_only(
        self,
        scope: ProjectScope,
        *,
        embed_latency_ms: int | None,
    ) -> _LadderResult:
        context_block = empty_context_block()
        if self._static_prefix is not None:
            try:
                fetched = self._static_prefix.get(scope)
            except Exception:
                # A failing prefix fetch does not escalate the outcome code: we
                # already know why we are here (the total budget), and "nothing
                # to serve" is a legitimate answer to "what does the prefix
                # cache hold right now" — not a second failure mode.
                fetched = None
            # Type-checked, not trusted: `StaticPrefixPort` has no implementation in
            # this phase, so its return value is unvalidated data. Handing a
            # non-ContextBlock to the Pydantic response model would raise from
            # OUTSIDE every ladder guard, which is the one shape of "Tracebed failed
            # the run" the guards above cannot catch.
            if isinstance(fetched, ContextBlock):
                context_block = fetched
        return _LadderResult(
            outcome_code=OutcomeCode.TIMEOUT_PREFIX_ONLY,
            context_block=context_block,
            embed_latency_ms=embed_latency_ms,
            candidates_considered=0,
            top_score=None,
        )

    def _record_injections(
        self, project_id: ProjectId, run_id: RunId, rows: Sequence[InjectionRow]
    ) -> None:
        """Write one `injection_log` row per placed memory (PLAN.md §5).

        This is the only record of WHICH memories entered a given run's prompt, and it is what
        Phase 3's Recall & Rollback forensics enumerates a blast radius from; a run whose
        injections were never logged is a run whose poisoned memory can never be traced. Skipped
        entirely — not called with an empty list — when nothing was placed, so an abstaining call
        costs no statement.
        """
        if self._injections is None or not rows:
            return
        # Guarded like every other dependency call: logging what was injected must never become
        # the reason the agent's run fails (invariant 2).
        with contextlib.suppress(Exception):
            self._injections.record_injections(project_id, run_id, rows)

    def _record_telemetry(
        self,
        project_id: ProjectId,
        run_id: RunId,
        *,
        outcome_code: OutcomeCode,
        latency_ms: int,
        embed_latency_ms: int | None,
        candidates_considered: int,
        top_score: float | None,
        arm: Arm,
    ) -> None:
        """Write one `retrieval_event` row for every call, including abstentions
        and failures (PLAN.md §2 invariant 2). Guarded on its own: recording the
        degradation must never itself become a failure the caller sees."""
        # Deliberately silent: a telemetry outage recording the degradation must
        # never itself surface as a second failure (see the docstring above).
        with contextlib.suppress(Exception):
            self._telemetry.record_retrieval(
                project_id,
                run_id,
                outcome_code=outcome_code,
                latency_ms=latency_ms,
                embed_latency_ms=embed_latency_ms,
                candidates_considered=candidates_considered,
                top_score=top_score,
                arm=arm,
            )
