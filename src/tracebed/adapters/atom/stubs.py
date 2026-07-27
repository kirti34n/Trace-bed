"""Documented interface stubs for the Atom integration seam (PLAN.md §3 ports table, §7
Phase 4). NO INTEGRATION CODE — every class below raises `NotImplementedError` on
construction; the human writes the real implementation (PLAN.md §4: "atom/ — documented
interface stubs ONLY — the human writes the integration").

Each stub names exactly one Atom component and exactly one `adapters.ports` Protocol it
would satisfy, with the method signature the host implementation must provide. This is the
full mapping this module ships — see `README.md` for the two ports (`ProjectResolverPort`,
`TraceStorePort`) that are deliberately NOT stubbed here because the shipped default already
covers Atom's shape with configuration alone, and for why `AgentArmor` and `policy-executor`
both map to `FeedbackPort` rather than to a port of their own.

Read `../../../../docs/ADAPTER-GUIDE.md` before writing a real implementation of any of
these — it is the document that specifies, per port, what the shipped default does, what a
host implementation must guarantee, and the failure mode if it gets that guarantee wrong.

Every constructor raises `_stub()` immediately. Nothing here should ever be instantiated —
these classes exist to be read, copy-pasted, and rewritten from scratch by the person doing
the real Atom integration; a class that "worked" enough to survive a test run would be the
one bit of integration code this seam is explicitly not supposed to contain.

That is why the three `FeedbackPort` stubs below declare an explicit no-argument `__init__`
that raises even though they take no construction parameters: without one they inherit
`object.__init__`, construct silently, and — because `adapters.ports.FeedbackPort` is
`@runtime_checkable` — pass an `isinstance(..., FeedbackPort)` wiring check, deferring the
failure to the first real outcome event instead of to the line that wired a documentation
artifact into a live deployment. `tests/phase4/test_archetype_configs.py` asserts every
exported stub refuses construction, so this cannot regress into "most of them do".
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from tracebed.adapters.identity import Principal
    from tracebed.domain.events import FeedbackEvent

__all__ = [
    "AtomAgentArmorFeedbackAdapter",
    "AtomBuilderInvalidationSource",
    "AtomGateEmbeddingProvider",
    "AtomGateLLMProvider",
    "AtomKeycloakPrincipalPort",
    "AtomMinioAuditSink",
    "AtomPolicyExecutorVerdictAdapter",
    "AtomWorkflowFeedbackAdapter",
]

_SEE: Final = "see docs/ADAPTER-GUIDE.md for what a real implementation must guarantee"


def _stub(component: str, port: str) -> NotImplementedError:
    """One message shape for every stub in this file — the Atom component, the Tracebed
    port it must satisfy, and where the contract for that port is written down."""
    return NotImplementedError(
        f"{component} is a documented interface stub for `adapters.ports.{port}` — "
        f"it is not an implementation. {_SEE}."
    )


# --------------------------------------------------------------------------- #
# Keycloak / NHI  ->  PrincipalPort
# --------------------------------------------------------------------------- #


class AtomKeycloakPrincipalPort:
    """Maps to `adapters.ports.PrincipalPort`.

    Atom's identity plane is Keycloak (realm ``atom``) for human/OIDC callers plus an NHI
    (non-human identity) client-credentials flow for service agents — both terminate in an
    OIDC-shaped bearer token, so both are one `PrincipalPort` implementation, not two.

    The shipped default (`adapters.identity.OidcJwksVerifier`) already speaks exactly this
    protocol against any RS256 JWKS endpoint, Keycloak included — a real Atom integration is
    expected to be **configuration**, not a rewrite: point `AuthConfig.oidc_jwks_url` at
    Keycloak's realm JWKS endpoint and `oidc_issuer` at the realm issuer URL. This stub exists
    for the one case configuration cannot cover: an NHI token whose claim shape (service
    account identifier, workload identity, or a custom private claim in place of `sub`) does
    not match `OidcJwksVerifier`'s "principal looked up by `sub`" assumption, and a host needs
    its own `PrincipalPort` to normalise it before the registry lookup.
    """

    def __init__(self, *, keycloak_realm_jwks_url: str, nhi_audience: str) -> None:
        raise _stub("AtomKeycloakPrincipalPort", "PrincipalPort")

    def authenticate(self, *, authorization: str | None, api_key: str | None) -> Principal:
        """Signature fixed by `PrincipalPort.authenticate`. Must raise
        `domain.errors.AuthenticationFailed` for every rejection path — never return an
        unauthenticated `Principal`, and never distinguish "wrong credential" from "unknown
        credential" in the raised message (that distinction is a principal-enumeration
        oracle — see `adapters.identity.ApiKeyVerifier` for the constant-time precedent)."""
        raise _stub("AtomKeycloakPrincipalPort", "PrincipalPort")


# --------------------------------------------------------------------------- #
# GATE muxes  ->  LLMProviderPort, EmbeddingPort
# --------------------------------------------------------------------------- #


class AtomGateLLMProvider:
    """Maps to `adapters.ports.LLMProviderPort`.

    GATE fronts a LiteLLM mux at ``gate:8083`` that every Atom agent's generative calls
    already flow through. The judge/distiller/shadow-validator workers (the only callers of
    this port — `scripts/purity_check.py` proves no hot-path module can reach it) should be
    pointed at that same mux rather than a second, parallel credential and routing path, so
    Tracebed's worker spend shows up in the same place Atom's own LLM spend does.

    The shipped default (`adapters.llm.openai_compat.OpenAiCompatibleLLMProvider`) already
    speaks OpenAI-compatible `/chat/completions` — LiteLLM's own wire format — so pointing
    `LLMProviderConfig.base_url` at ``http://gate:8083`` is very likely sufficient with zero
    code. This stub exists for the case GATE's mux adds its own envelope (an auth header
    shape, a request-id correlation field) the shipped driver does not produce.
    """

    def __init__(self, *, gate_base_url: str) -> None:
        raise _stub("AtomGateLLMProvider", "LLMProviderPort")

    def complete(self, *, model: str, prompt: str, temperature: float, max_tokens: int) -> str:
        """Signature fixed by `LLMProviderPort.complete`. No hot-path module may ever hold a
        reference to an instance of this class — it is a workers-only dependency, and
        `scripts/purity_check.py` is CI-blocking on that reachability property, not merely
        documentation of it."""
        raise _stub("AtomGateLLMProvider", "LLMProviderPort")


class AtomGateEmbeddingProvider:
    """Maps to `adapters.ports.EmbeddingPort`.

    The same GATE mux fronts embedding calls. Permitted on the hot path under its own 200ms
    sub-budget (PLAN.md §2 invariant 1: "Query embedding is permitted only through
    `EmbeddingPort` with its own sub-budget — it is a vector endpoint, not a generative
    client"); this is the one Atom-facing stub a hot-path module is allowed to reach.

    `model_id`/`model_version` MUST be the real, currently-pinned values GATE's mux is
    routing to, not placeholders — they are stamped on every embedded row
    (`memory_item.embedding_model_id`/`embedding_model_version`), and re-pointing the mux to
    a different embedding model without bumping them is exactly the silent re-embedding
    PLAN.md §10 forbids ("Swap the embedding model silently").
    """

    def __init__(self, *, gate_base_url: str, model_id: str, model_version: str) -> None:
        raise _stub("AtomGateEmbeddingProvider", "EmbeddingPort")

    def embed(self, texts: Sequence[str], *, timeout_ms: int) -> list[list[float]]:
        """Signature fixed by `EmbeddingPort.embed`. Must raise `domain.errors.
        EmbeddingTimeout` at `timeout_ms` and must NOT retry internally — the retriever owns
        the 200ms sub-budget and degrades to lexical-only on timeout; an internal retry here
        would silently spend that budget and turn a `degraded_lexical` outcome into a
        `timeout_prefix_only` one instead."""
        raise _stub("AtomGateEmbeddingProvider", "EmbeddingPort")

    @property
    def model_id(self) -> str:
        raise _stub("AtomGateEmbeddingProvider", "EmbeddingPort")

    @property
    def model_version(self) -> str:
        raise _stub("AtomGateEmbeddingProvider", "EmbeddingPort")


# --------------------------------------------------------------------------- #
# builder-backend  ->  InvalidationPort
# --------------------------------------------------------------------------- #


class AtomBuilderInvalidationSource:
    """Maps to `adapters.ports.InvalidationPort`.

    Tool definitions, agent schemas, and workflow templates are authored in Atom's
    builder-backend. Every edit there is exactly the class of platform event PLAN.md §7
    Phase 2 names as what makes memory stale — "tool changed, env fact changed, workflow
    edited" — so builder-backend is the natural emitter, whether that means it POSTs to
    `/v1/invalidation` directly on save, or this class polls the builder's own change log
    through the shipped `adapters.invalidation.PollingInvalidationSource` skeleton.

    `poll()`'s returned mappings become `invalidation_event(project_id, event_type, selector,
    fired_at)` rows (`Repo.insert_invalidation_event`) via whichever HTTP route or worker
    drains this port — a `selector` too narrow silently leaves dependent memories `validated`
    past the change; one too broad marks unrelated memories stale for no reason, discarding
    real coverage. Neither failure raises — both are numbers-only regressions, visible only
    in the staleness dashboard view and the R-day revalidation backstop.
    """

    def __init__(self, *, builder_backend_base_url: str) -> None:
        raise _stub("AtomBuilderInvalidationSource", "InvalidationPort")

    def poll(self) -> Sequence[Mapping[str, object]]:
        """Signature fixed by `InvalidationPort.poll`. Each mapping's shape is `{"event_type":
        str, "selector": Mapping[str, object]}` (`adapters.invalidation`'s documented raw
        payload shape) — `selector` must resolve to the same `provenance.tool_refs` /
        `trace_ids` / `input_sig_hashes` terms `workers.invalidator` matches against, or
        nothing this method returns will ever invalidate anything."""
        raise _stub("AtomBuilderInvalidationSource", "InvalidationPort")


# --------------------------------------------------------------------------- #
# workflow-backend, AgentArmor, policy-executor  ->  FeedbackPort
#
# Three different Atom components, one port, three different adapter CLASSES
# (`domain.enums.AdapterClass`) and trust weights — exactly what FeedbackPort exists to let
# coexist (PLAN.md §3: "verdict (1.0), correction_adapter (0.8), downstream (0.3), implicit
# (0.0, logged only)").
# --------------------------------------------------------------------------- #


class AtomWorkflowFeedbackAdapter:
    """Maps to `adapters.ports.FeedbackPort`, `AdapterClass.DOWNSTREAM` (weight 0.3).

    Workflow-backend owns workflow-run resolution: a deployment approved or rolled back, a
    ticket closed, a case reopened, an alert re-fired. These are exactly the "downstream
    event... weak, delayed, joins whenever it arrives" examples PLAN.md §3 gives for the
    `downstream` adapter class — the outcome is real but only loosely attributable to
    whichever memory was injected on the originating run, which is why the class is trusted
    at 0.3, not 1.0.

    `to_outcome` MUST NOT accept or forward a caller-supplied weight under any key: invariant
    8 is enforced at the API (`FeedbackEvent`'s `extra="forbid"` rejects an unmodelled
    `weight` field with a 422) precisely so that the server, never a caller, derives `w` from
    `AdapterClass.DOWNSTREAM`. A workflow-backend event that carries its own confidence score
    belongs in `payload`, read by a human later, never mapped onto `w`.
    """

    def __init__(self) -> None:
        raise _stub("AtomWorkflowFeedbackAdapter", "FeedbackPort")

    def to_outcome(self, raw: Mapping[str, object]) -> FeedbackEvent:
        """Signature fixed by `FeedbackPort.to_outcome`. Raise
        `adapters.feedback.base.AmbiguousSignal` or `.NoSignal` for anything that is not an
        unambiguous positive/negative resolution — invariant 8's "a guessed reward is worse
        than none" applies to this adapter exactly as it does to the shipped ones."""
        raise _stub("AtomWorkflowFeedbackAdapter", "FeedbackPort")


class AtomAgentArmorFeedbackAdapter:
    """Maps to `adapters.ports.FeedbackPort`, `AdapterClass.DOWNSTREAM` (weight 0.3).

    AgentArmor is Atom's per-tool-call policy guard — MEMORY-FLOW.md §8 already rules out
    routing memory retrieval THROUGH AgentArmor ("AgentArmor's 5s pre-call timeout alone is
    16x the whole retrieval budget"). Its relevant signal here runs the other direction:
    every policy-violation-flagged tool call is exactly the raw material
    `workers.safety_lift` (PLAN.md §8 improvement 2, "safety-aware kill switch") needs —
    memory-on vs memory-off policy-violation rate, not merely task-quality lift. Feed a
    violation as a `downstream`-class negative outcome; `workers.safety_lift` reads
    `outcome_event` rows the same way `workers.lift` does, keyed on the same `(agent_type_id,
    mem_type)` cells.

    A policy violation is a WEAK, delayed signal about whether an injected memory
    contributed to the violated call — hence `downstream`, not `verdict` — even though the
    detection itself (AgentArmor's rule match) is deterministic. Determinism of the detector
    is not the same thing as certainty of attribution to the memory in play, and it is the
    latter `AdapterClass` weights.
    """

    def __init__(self) -> None:
        raise _stub("AtomAgentArmorFeedbackAdapter", "FeedbackPort")

    def to_outcome(self, raw: Mapping[str, object]) -> FeedbackEvent:
        """Signature fixed by `FeedbackPort.to_outcome`."""
        raise _stub("AtomAgentArmorFeedbackAdapter", "FeedbackPort")


class AtomPolicyExecutorVerdictAdapter:
    """Maps to `adapters.ports.FeedbackPort`, `AdapterClass.VERDICT` (weight 1.0).

    Atom's policy-executor makes an explicit, adjudicated allow/deny decision on an agent's
    proposed action — the same shape as "analyst approve/reject with reasoning" PLAN.md §3
    gives as the `verdict` adapter's own example, and the one class this port ships trusted
    at full weight. A policy-executor deny that names *why* (which rule fired, which memory's
    guidance the agent followed into the denied action) is rejection-reasoning that can feed
    `workers.distiller` the same way a human verdict's rejection reason does.

    Do not conflate this with `AtomAgentArmorFeedbackAdapter` above: AgentArmor's rule match
    is a downstream signal about an already-executed call; policy-executor's decision is the
    gating decision itself, made with full context before or in place of execution — which is
    exactly the "explicit verdict" shape `AdapterClass.VERDICT` exists for.
    """

    def __init__(self) -> None:
        raise _stub("AtomPolicyExecutorVerdictAdapter", "FeedbackPort")

    def to_outcome(self, raw: Mapping[str, object]) -> FeedbackEvent:
        """Signature fixed by `FeedbackPort.to_outcome`."""
        raise _stub("AtomPolicyExecutorVerdictAdapter", "FeedbackPort")


# --------------------------------------------------------------------------- #
# MinIO audit  ->  AuditSinkPort
# --------------------------------------------------------------------------- #


class AtomMinioAuditSink:
    """Maps to `adapters.ports.AuditSinkPort`.

    PLAN.md §3 ships JSON-lines-to-stdout plus a Postgres audit table as the default, with
    "optional S3 sink" named explicitly. **No shipped implementation of any kind exists in
    this codebase yet** — grep confirms `AuditSinkPort` has zero concrete implementations
    anywhere under `src/tracebed/`, referenced only by its own Protocol definition and by a
    docstring in `workers.killswitch`. This is a real contract_gap this chunk reports rather
    than papers over: the default half of this port ("Postgres audit table") has no writer,
    and this stub is therefore not "one more option alongside a working one" the way the
    other seven stubs in this file are — it is Atom's only path to a durable audit sink until
    that gap is closed by whichever chunk owns `stores/pg` or `workers` next.

    Atom already runs MinIO (or SeaweedFS — the same generic-S3 target
    `stores.tracestore.s3.S3TraceStore` speaks) as object storage. This stub documents the S3
    sink specifically: every kill-switch trigger, promotion, retirement, and operator edit
    this module would emit becomes one object per event (or one append-only NDJSON object per
    day/project — a host's choice, not this port's), bucket-separate from the trace archive
    `TraceStoreConfig` points at, so an audit retention policy can differ from a trace
    retention policy without one erasure operation touching the other's bucket.
    """

    def __init__(self, *, minio_endpoint: str, bucket: str) -> None:
        raise _stub("AtomMinioAuditSink", "AuditSinkPort")

    def emit(self, event: Mapping[str, object]) -> None:
        """Signature fixed by `AuditSinkPort.emit`. Must not raise on a transient sink outage
        in a way that reaches the caller synchronously — an audit sink that can take down a
        kill-switch trigger or a promotion by throwing is a governance action gated on
        object-store availability, which none of PLAN.md §2's eight invariants asks for."""
        raise _stub("AtomMinioAuditSink", "AuditSinkPort")
