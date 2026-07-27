# Tracebed — Adapter & Port Authoring Guide

> How to implement each port in `src/tracebed/adapters/ports.py` correctly. Read this before
> writing a host adapter for any deployment — Atom or otherwise. `src/tracebed/adapters/atom/`
> is the Atom-specific seam (documented stubs only); this document is the port contract every
> one of those stubs, and every other host's adapters, must satisfy.
>
> Rev. 2026-07-26 · Companion to `PLAN.md` §3 (ports table) and `PHASE0-CONTRACT.md` §8–9.

## How to read this document

Tracebed runs fully featured against zero host (`PLAN.md` §1). Every place a real deployment
differs from that zero-host default is exactly one of the eight `Protocol`s below, each with a
shipped default that already works. Implementing a port wrong does not usually crash
anything — most of these failure modes are silent, which is why each section below states its
failure mode explicitly rather than trusting an integrator to infer it.

For each port:

- **What it is for** — the one decision this port exists to let a host make differently.
- **The exact protocol** — copied verbatim from `adapters/ports.py`, not paraphrased. The one
  exception is `TraceStorePort`, which is *defined* in `stores/tracestore/__init__.py` and
  re-exported by `adapters/ports.py`; its block is copied from the definition.
  `tests/phase4/test_archetype_configs.py::TestAdapterGuideMatchesPorts` binds every block
  below to the live `Protocol` by `inspect.signature`, so a signature change in the code makes
  this document fail CI rather than quietly become wrong.
  (Two further Protocols — `crypto.shred.SubjectKeyStore` and `domain.config.ConfigStorePort`
  — deliberately live beside their consumers per C-18 and are *not* host-implements ports;
  they are out of scope for this document.)
- **What the shipped default does** — so "just configure the default" is always considered
  before "implement the port".
- **What a host implementation must guarantee** — the properties this port's callers assume
  and never re-check.
- **Failure mode if it gets it wrong** — concretely, what breaks, and how someone would (or
  would not) notice.

---

## `PrincipalPort` — verify the caller's own credentials

**What it is for.** Tracebed always verifies its own credentials. It never trusts a host's
asserted actor header — PLAN.md §3 is explicit ("it never trusts a host's actor header") —
because that header is exactly what an attacker would forge to cross a project wall
(invariant 4). This port is the *only* place "who is this caller" gets decided.

**The protocol** (`adapters/ports.py`):

```python
class PrincipalPort(Protocol):
    def authenticate(self, *, authorization: str | None, api_key: str | None) -> Principal:
        """Raises AuthenticationFailed. Never returns an unauthenticated principal."""
```

**What the shipped default does.** `adapters.identity.ChainVerifier` dispatches on scheme —
`Bearer` → `OidcJwksVerifier` (RS256 against a fetched JWKS document, `sub`/`iss`/`aud`/`exp`
all required and checked, JWKS refetch on an unknown `kid` throttled to one fetch per 10s
window to stop request-amplification against the IdP); `X-API-Key: tb_sk_<key_id>.<secret>` →
`ApiKeyVerifier` (sha256 of the secret compared with `hmac.compare_digest` against a stored
hash, constant-time even on a miss via a fixed decoy hash). Both verifiers raise the exact
same `AuthenticationFailed` message for "wrong credential" and "unknown credential" — this is
load-bearing, not an accident (see failure mode below).

**What a host implementation must guarantee.**

1. Every rejection path — malformed credential, unknown principal, revoked principal, wrong
   secret, expired token, wrong issuer/audience — raises `AuthenticationFailed`. There is no
   other legal outcome for a call this port cannot authenticate.
2. "Unknown principal" and "wrong credential" must be indistinguishable to the caller, in
   **both** the exception message and the wall-clock time taken to produce it. A verifier
   that returns faster for "no such key_id" than for "key_id exists, secret wrong" is a
   principal-enumeration oracle regardless of what the message says.
3. `Principal` carries no project. Scope is derived in a second, separate step
   (`ProjectResolverPort`, next section) specifically so that authentication and
   authorization cannot be satisfied by one forged value.
4. A token with no `exp` claim (or any other verification PyJWT only checks when present)
   must be rejected, not accepted-by-omission — `OidcJwksVerifier` passes
   `options={"require": [...]}` for exactly this reason.

**Failure mode if it gets it wrong.** A verifier that trusts a host-supplied actor header, or
that ever returns a `Principal` without raising on a bad credential, is a complete bypass of
every downstream isolation control — `ProjectResolverPort`, RLS, the leak suite's by-id
probes, all of it assume the `Principal` handed to them already represents a real,
successfully-verified caller. This does not show up as an error anywhere; it shows up as
project B's data returned to project A's caller, and the leak suite (the only thing that
would catch it) only runs against the *shipped* verifiers in this repo's own tests, not
against a host's replacement.

---

## `ProjectResolverPort` — principal → project (the isolation root)

**What it is for.** The single function that turns "who is calling" into "which project's
data they may see". PLAN.md §2 invariant 4: "`project_id` is derived server-side from the
authenticated principal via the registry — never caller-asserted."

**The protocol:**

```python
class ProjectResolverPort(Protocol):
    def resolve_project(self, principal_id: PrincipalId) -> ProjectScope:
        """Raises ScopeResolutionFailed for an unregistered principal."""
```

**What the shipped default does.** `Repo.resolve_project` reads the `agent_registration`
table, whose `UNIQUE(principal_id)` constraint is what makes the principal→project mapping a
total function rather than a choice a caller or a race could influence. A principal with no
registration row raises `ScopeResolutionFailed` (mapped to HTTP 403), never a default project.

**What a host implementation must guarantee.**

1. The mapping is populated by an **admin-side** action — `POST /admin/agents/register` —
   never inferred from anything in the request being scoped. No implementation of this port
   should accept a project hint from the same call it is resolving scope for.
2. `UNIQUE(principal_id)`-equivalent semantics: one principal maps to exactly one project. A
   port that can return different projects for the same principal on different calls breaks
   every cache key, every RLS GUC set from it, and every audit trail that assumes stable
   scope.
3. Never returns a scope for a revoked or deleted project. A project whose `deleted_at` is
   set (soft-deleted, awaiting `DETACH`/`DROP`) must resolve as if the principal were
   unregistered, not as a live scope pointed at data mid-erasure.

**Failure mode if it gets it wrong.** This is the isolation root every RLS policy, cache key,
and repository builder is built on top of (`PHASE0-CONTRACT.md` §3.3: "the ONLY carrier of
project identity from api to repo"). Getting it wrong here is not a narrower version of the
`PrincipalPort` failure — it is the *same* failure, one layer down: a resolver that can be
made to return the wrong `ProjectScope` for a correctly-authenticated principal defeats RLS,
the per-project Valkey key schema, and the leak suite's premise simultaneously, because all
three trust this port's output unconditionally.

*(No Atom stub ships for this port — see `adapters/atom/README.md`: it is populated by an
admin API call, not a Protocol implementation, and Atom's own project entity is the natural
source of the name/`retention_policy` passed to `POST /admin/projects`.)*

---

## `FeedbackPort` — host events → outcome events

**What it is for.** Turning something that happened in the host platform (an analyst
decision, an edited output, a downstream event, an ambiguous behavioural signal) into the one
thing the scorer is allowed to act on: an unambiguous outcome with a server-derived weight.
Invariant 8 in one sentence: "a guessed reward is worse than none."

**The protocol:**

```python
class FeedbackPort(Protocol):
    def to_outcome(self, raw: Mapping[str, object]) -> FeedbackEvent: ...
```

Four adapter classes exist (`domain.enums.AdapterClass`), each with a fixed server-side trust
weight nothing on the wire can override: `verdict` (1.0), `correction_adapter` (0.8),
`downstream` (0.3), `implicit` (0.0 — logged only, never scored).

**What the shipped default does.** `adapters/feedback/{verdict,correction,downstream,
implicit}.py` implement the four classes; `adapters/feedback/base.py`'s `dispatch_feedback`
is the one function that turns a raw signal into at most one `ScorerPort.record_outcome`
call, with every refusal (`AmbiguousSignal`, `NoSignal`, a caller-supplied weight, `w == 0`)
short-circuiting before that call, never after. `FeedbackEvent.model_config =
ConfigDict(extra="forbid")` is what makes a `weight` key in the wire payload a 422 with zero
adapter code — there is no field to accept it into.

**What a host implementation must guarantee.**

1. `to_outcome` raises `AmbiguousSignal` or `NoSignal` — never fabricates a polarity — for
   anything that is not a genuinely unambiguous positive/negative resolution. "The agent's
   output was regenerated" is ambiguous (retry after a bug? user changed their mind? the
   agent itself decided to redo it?) and belongs to `implicit`, weight 0, logged and never
   scored — not guessed at as a weak negative.
2. Never accepts or derives a weight from the raw host event. The server derives `w` from
   `AdapterClass` alone (`ScoringConfig.adapter_weights`); a host adapter that reads a
   "confidence" field off its own event and threads it through as `w` reintroduces exactly
   the caller-supplied-weight hole invariant 8 exists to close, just one layer removed from
   the API's own 422 check.
3. `event_id` is the dedup key (`outcome_event` PK is `(project_id, event_id)`,
   `ON CONFLICT DO NOTHING`) — a host adapter that mints a new `event_id` on every retry of
   the same underlying host event turns an idempotent replay into N separate Q updates.
4. Correctly picks the adapter class the *evidence* warrants, not the class that is
   convenient to wire. A human-edited output's diff is `correction_adapter` (0.8), not
   `verdict` (1.0) — only an explicit approve/reject with reasoning is `verdict`. Overclaiming
   trust here does not fail loudly; it just makes an under-trusted signal move Q as fast as a
   fully-trusted one.

**Failure mode if it gets it wrong.** An adapter that guesses at ambiguous signals silently
reintroduces the exact failure MEMORY-FLOW.md documents by name: run the Q arithmetic with
`r=0`, `c≈1`, and the shipped `alpha=0.3` — four calendar days at one update per memory per
day is enough to retire *any* memory an attacker (or a badly-written adapter) chooses, using
outcomes the system is designed to trust precisely because they are supposed to be
unambiguous. The retirement principal floor (K, `RetirementConfig.min_distinct_principals`)
bounds the blast radius of one bad *principal*; it does nothing for one bad *adapter*
manufacturing signal from every principal it touches.

---

## `InvalidationPort` — platform events that make memory stale

**What it is for.** A memory is only as good as the world it described. When a tool
definition changes, an environment fact changes, or a workflow template is edited, every
memory whose provenance points at the old version needs to become `stale`, not silently keep
being injected as if nothing changed.

**The protocol:**

```python
class InvalidationPort(Protocol):
    def poll(self) -> Sequence[Mapping[str, object]]: ...
```

**What the shipped default does.** Two skeletons, both in `adapters/invalidation.py`:
`WebhookInvalidationSource` (an in-memory receive/drain buffer a host's own HTTP route feeds,
at-most-once and single-process — durability across a restart is the R-day revalidation
sweep's job, not this buffer's) and `PollingInvalidationSource` (interval-diffs a
host-supplied `JsonSourcePort` against the previous poll's snapshot by a host-supplied stable
key, emitting one raw payload per added/changed/removed item). Both emit the same shape:
`{"event_type": str, "selector": Mapping[str, object]}`.

**What a host implementation must guarantee.**

1. `selector` resolves to the same terms `workers.invalidator` matches memories against
   (`provenance.tool_refs`, `trace_ids`, `input_sig_hashes`) — a selector using the host's own
   internal identifiers with no mapping to those terms invalidates nothing, silently.
2. Coverage is neither too narrow nor too broad. Too narrow leaves a changed dependency's
   memories `validated` (a correctness bug with no visible symptom until someone notices a
   memory citing a tool that no longer works that way); too broad marks unrelated memories
   `stale` for no reason (a availability/quality regression that looks like normal churn on
   the staleness dashboard, not like a bug in this adapter).
3. `poll()` must be safe to call repeatedly and must not re-emit an event already drained —
   `PollingInvalidationSource`'s diff-by-stable-key is what the shipped default relies on for
   this; a host source that instead re-lists "everything currently true" on every poll needs
   its own dedup, or every poll re-invalidates the entire dependent set.

**Failure mode if it gets it wrong.** Both directions are silent. There is no error path for
"an invalidation event should have fired and did not" — the only backstop is
`lifecycle.revalidation_age_days` (R, default 30): a `validated` memory not retrieved (or not
re-verified) for R days gets checked anyway. A host whose `InvalidationPort` misses real
changes is, in effect, running on the R-day backstop alone — which is a much weaker guarantee
than event-driven invalidation, and nothing announces the degradation.

---

## `LLMProviderPort` — generative inference for background workers only

**What it is for.** The judge, distiller, and shadow validator need generation; nothing on
the hot path ever may. This port exists specifically so that boundary is a type-level fact
(`scripts/purity_check.py` walks the import graph and is CI-blocking), not a convention.

**The protocol:**

```python
class LLMProviderPort(Protocol):
    def complete(self, *, model: str, prompt: str, temperature: float, max_tokens: int) -> str: ...
```

**What the shipped default does.** `adapters.llm.openai_compat.OpenAiCompatibleLLMProvider`:
an OpenAI-compatible `/chat/completions` call over `httpx`, spoken against
`LLMProviderConfig.base_url` (default Gemini's OpenAI-compatible endpoint; any
OpenAI-compatible gateway — LiteLLM, Google-direct, a self-hosted proxy — is one config line,
no code change). The response body is buffered under a byte ceiling derived from the
request's own `max_tokens`, and a wall-clock deadline anchored to one `clock.monotonic_ms()`
reading is re-checked after every chunk read — this is what stops a slow-drip response from
staying inside every individual per-operation `httpx` timeout while consuming unbounded total
time. There is no internal retry: the caller owns whatever budget or backoff policy applies.

**What a host implementation must guarantee.**

1. Never reachable from `hotpath/`. This is not merely a code-review request — if a host
   wires an `LLMProviderPort` instance anywhere `hotpath/pipeline.Pipeline` or its
   dependencies can import it, `scripts/purity_check.py` fails the build. A generative call
   the hot path can reach, reachable or not on any given request, is invariant 1 violated
   outright.
2. Enforces a *total* deadline across the whole call, not merely a per-socket-operation
   timeout, exactly like the shipped driver — the judge and distiller run behind a
   `scoring_epoch` and a batch cadence, but an individual call that can block indefinitely
   still stalls whatever worker loop is waiting on it.
3. Every artifact this port's output feeds records the model id, model version, sampling
   parameters, and prompt hash (`scoring_epoch` — PLAN.md §5). A host implementation must
   expose enough about what it actually called (not merely the configured `judge_model`
   string, which could be silently re-pointed at a different backend by the gateway) for that
   stamp to be true.

**Failure mode if it gets it wrong.** A generative call reachable from the hot path is a
purity-gate failure (loud, CI-blocking, caught before merge). A *total*-deadline violation is
quieter — a worker loop that blocks on one hung call stalls the entire batch behind it, which
looks like "the distiller/judge/shadow-validator got slow" in operational metrics, not like a
crash. A `scoring_epoch` that does not reflect what was actually called makes a later
cross-epoch Q comparison (already rejected by `domain.errors.CrossEpochComparison`) rejected
for the wrong reason, or — worse — silently accepted as same-epoch when the model backing it
actually changed underneath the pin.

---

## `EmbeddingPort` — query and index embedding (the one generative-shaped port the hot path may call)

**What it is for.** Vector search needs a vector for the query. This is explicitly *not* the
same category as `LLMProviderPort` — PLAN.md §2 invariant 1: "Query embedding is permitted
only through `EmbeddingPort` with its own sub-budget (200ms) — it is a vector endpoint, not a
generative client."

**The protocol:**

```python
class EmbeddingPort(Protocol):
    def embed(self, texts: Sequence[str], *, timeout_ms: int) -> list[list[float]]: ...
    @property
    def model_id(self) -> str: ...
    @property
    def model_version(self) -> str: ...
```

**What the shipped default does.** `adapters.embedding.gemini.GeminiEmbeddingClient` (primary
— accuracy over latency, per PLAN.md §3) and `adapters.embedding.onnx_local` (secondary,
fully supported, for air-gapped or latency-sensitive deployments: a pinned local model file,
loaded through `onnxruntime`, sha256-checked against its pin *before* the runtime session is
even built — a mismatched file raises `OnnxModelIntegrityError` unconditionally, not a
warning). Both enforce the same total-deadline discipline as `LLMProviderPort`'s driver, and
neither retries internally — the retriever owns the 200ms sub-budget and degrades to
lexical-only on timeout.

**What a host implementation must guarantee.**

1. Raises `domain.errors.EmbeddingTimeout` at `timeout_ms`, never blocks past it, and never
   retries internally. The retriever's degradation ladder (embed timeout → lexical-only;
   total budget exceeded → static-prefix-only; store error → nothing) depends on this port
   failing fast and cleanly, not on it eventually succeeding.
2. Every float returned is finite. A single `NaN` in a stored vector poisons the cosine
   distance of every ANN comparison it ever participates in, silently, forever (until that
   row is re-embedded) — there is no downstream check that would catch it after the fact.
3. `model_id`/`model_version` are the real, currently-serving values, stamped on every row
   that gets embedded (`memory_item.embedding_model_id`/`embedding_model_version`). Re-pointing
   a deployment at a different embedding model without bumping these is the exact silent
   re-embedding PLAN.md §10 forbids by name.
4. Dimension matches the deployment's pin (`EmbeddingConfig.dim`, `<= 768`, stored as
   `halfvec(768)`). A driver that returns a different dimension than the pin fails the
   *insert*, not the embed call — which is the right place for it to fail loudly, but only if
   the driver does not silently pad or truncate to make the shapes match first.

**Failure mode if it gets it wrong.** A driver that blocks past `timeout_ms` (rather than
raising) is invisible in exactly the way that matters most: the retriever's fail-open ladder
exists so a *slow* dependency degrades gracefully, but a driver that hangs past its own
declared timeout without raising defeats the ladder at its first rung, and the caller has no
way to distinguish "embedding is slow today" from "embedding is broken" until the whole
300ms budget is blown too. A `NaN`-poisoned vector is worse precisely because it does not
fail at all — every retrieval that touches it returns a degraded ranking with a `PASS`-shaped
outcome code (`injected`, not `store_error`), so the negative-probe and lift-based
detection this system relies on elsewhere never fires on it.

---

## `TraceStorePort` — object storage for trace payloads

**What it is for.** Where the raw, byte-immutable evidence every derived memory ultimately
points back to actually lives.

**The protocol** (`stores/tracestore/__init__.py`, imported by `adapters/ports.py`):

```python
class TraceStorePort(Protocol):
    def put(self, project_id: ProjectId, run_id: RunId, first_seq: int, payload: bytes) -> PayloadRef: ...
    def get(self, project_id: ProjectId, ref: PayloadRef) -> bytes:
        """Raises NotFound on a missing object AND on a ref outside the caller's
        project prefix — checked BEFORE any network call."""
    def exists(self, project_id: ProjectId, ref: PayloadRef) -> bool: ...
    def delete_project(self, project_id: ProjectId) -> int:
        """Removes every object under the project's prefix; returns the count removed."""
```

**What the shipped default does.** `FsTraceStore` (filesystem, Phase 0 default) and
`S3TraceStore` (generic S3 REST over `httpx` with hand-rolled SigV4 — no boto3, no MinIO SDK;
SeaweedFS is the primary S3 target, legacy MinIO stays usable only because the driver speaks
plain S3, MinIO's own OSS repo having been archived 2026-04-25). Both key every object by
`{project_id}/{run_id}/...`, which is what lets the leak suite's cross-project by-id probe
fail closed on a **string comparison**, before any network call or file open — and both
additionally resolve the path/key and check it is contained within the caller's own project
directory, specifically because a naive prefix check alone is defeated by a
`"{caller}/../{victim}/..."`-shaped ref.

**What a host implementation must guarantee.**

1. Every key embeds `project_id`, and a `get`/`exists` call for a ref outside the caller's
   resolved project fails exactly like a truly-absent ref (`NotFound`) — invariant 4's
   "uniform 404" property, restated at the object-store layer.
2. Byte-immutability. Nothing about crypto-shredding works if the store allows rewriting an
   object in place — erasure is supposed to be *key destruction*, with the object's bytes
   never touched (see `docs/OPERATIONS.md`'s erasure section). A store that supports
   overwrite-in-place is not wrong to use, but a host relying on it for erasure has
   reinvented "delete the payload", which throws away the provenance chain every derived
   memory needs.
3. Path-style addressing / no unintended dot-segment normalisation. `S3TraceStore`'s own
   docstring names the specific hazard: `httpx` applies RFC 3986 dot-segment removal to
   request paths, so an unvalidated ref containing `..` could be silently rewritten onto a
   different project's object *after* a naive prefix check already passed — a host
   implementation using a different HTTP client needs the equivalent structural check
   (`ref_matches_project`, not a substring match) before building any request.

**Failure mode if it gets it wrong.** A store that fails the cross-project isolation
guarantee is a straightforward leak — the exact thing leak-suite probe (e) exists to catch,
though only against the shipped drivers, never against a host's replacement. A store that
allows in-place overwrite quietly turns "erase this subject" into "erase this subject, and
also silently invalidate the provenance chain of everything that cites this trace" — nobody
sees an error; a forensics query (`workers.forensics`) just returns wrong or missing data
about a run that used to exist.

---

## `AuditSinkPort` — where Tracebed's own audit events go

**What it is for.** A record of Tracebed's own governance decisions — kill-switch triggers,
promotions, retirements, operator edits — independent of the memory store itself, so an
auditor can answer "what did the system decide and when" without trusting the same rows that
could themselves be the subject of an investigation.

**The protocol:**

```python
class AuditSinkPort(Protocol):
    def emit(self, event: Mapping[str, object]) -> None: ...
```

**What the shipped default does — CONTRACT GAP, reported, not papered over.** PLAN.md §3
names the default as "JSON-lines to stdout + Postgres audit table; optional S3 sink." **No
concrete implementation of this port exists anywhere in this codebase as of this writing.**
`AuditSinkPort` appears in exactly two places in `src/tracebed/`: its own Protocol definition
in `adapters/ports.py`, and one docstring reference in `workers/killswitch.py` describing
what a caller *would* record. There is no writer for either half of the described default.
This is the one port in this document where "configure the shipped default" is not an
available option — a host (Atom or otherwise) wanting durable audit output today must
implement this port from scratch, and should treat `adapters.atom.stubs.AtomMinioAuditSink`
as a documented signature to fill in, not a partially-working starting point.

**What a host implementation must guarantee.**

1. `emit` must not raise in a way that blocks or fails the governance action it is recording.
   None of PLAN.md §2's eight invariants makes a kill-switch trigger, a promotion, or a
   retirement conditional on audit-sink availability — an audit sink that can take one of
   those down by throwing has turned an observability concern into an availability one.
2. Every event this port is handed should be treated as append-only and durable at the sink's
   own layer (an S3 object-lock policy, a Postgres table with no `UPDATE`/`DELETE` grant for
   the app role) — an audit trail that can be edited after the fact by the same credentials
   that wrote it is not an audit trail.
3. If the sink is also a crypto-shredding subject (an audit event that happens to name a
   subject_tag being erased), it must not become unreadable *itself* purely because that
   subject's KEK was destroyed — an audit record of "we erased subject X" that becomes
   unreadable the moment subject X is erased defeats the record's entire purpose. Keep audit
   payloads free of the subject's raw content; reference it by `run_id`/`memory_id` instead.

**Failure mode if it gets it wrong.** Right now, the failure mode is simply "there is no
audit trail beyond whatever is reconstructible from `memory_item`/`memory_link` provenance
and application logs" — every governance decision this system makes is real and enforced
(the state machine, the kill switch, and the review queue do not depend on this port at all),
but nothing outside the database itself independently attests that it happened. A host that
implements this port carelessly (synchronous, blocking, mutable-in-place) converts a
missing-but-harmless gap into an availability or tamper-evidence problem the moment it is
"fixed" wrong.

---

## Replacing ReMe — what is gained, what is lost, what is not there yet

The instruction this section answers was "replace ReMe — just make sure we are not losing
anything". D-030 waived a ReMe compatibility shim on the grounds that the delta "is documented
in the adapter guide instead". It was not: until this section existed, the word "ReMe" appeared
three times in the entire repository, all three in DECISIONS.md and PLAN.md, and none of them a
parity analysis. This is that analysis, written against the tree as it actually stands rather
than against the plan.

**What ReMe did, as used in the host platform:** conversation-summary storage. A session ends,
its conversation is summarised, the summary is stored against the session/agent, and it is
handed back at the start of the next session. Simple, immediate, and unconditional — anything
stored comes back.

**What Tracebed does instead:** it stores conclusions derived from *runs*, not conversations —
lessons, facts, exemplars, preferences — each pointing down to the raw trace that produced it,
each quarantined until confirmed, each retrieved only when it clears an abstention gate, and
each rendered as a labelled data block rather than as instructions.

| Capability | ReMe | Tracebed today | Verdict |
|---|---|---|---|
| Store something at end of session | conversation summary | trace written, payload encrypted, indexed | **kept**, in a stronger form (provenance, crypto-shred per subject) |
| Hand it back next session | unconditional replay of the summary | **NOT PRESENT** | **LOST — see below** |
| Cross-session continuity for one user | yes, by session key | **NOT PRESENT** — `session_id` reaches no store; working-memory keys are run-scoped (`stores/valkey/keys.py`) | **LOST** |
| Free-text recall into the prompt | yes | refused by design — memory enters only through typed slots after all cacheable content (invariant 3) | changed deliberately |
| Learning from outcomes | none | designed and specified; **no `UPDATE memory_item` exists**, so nothing is learned yet | not yet |
| Scoping/isolation | per-session | per-project wall, RLS backstop, per-agent-type and per-user scope | **gained** |
| Governance (quarantine, promotion, kill switch, review queue) | none | specified and implemented as logic; not yet running as a service | **gained on paper** |
| Retrieval quality controls (abstention, rarity, budgets, dedup) | none | implemented and tested | **gained** |
| Deletion / right-to-erasure | delete the row | crypto-shred by subject key | **gained** |

**The honest headline.** A deployment that switches from ReMe to Tracebed *today* loses the one
thing ReMe actually did — session-to-session recall of a conversation summary — and gains a
governed pipeline that is not yet closed at the far end. Traces go in faithfully; outcome events
go in faithfully; nothing derives, promotes, scores, or retires anything, because the write path
for `memory_item.status` does not exist (PLAN.md, "Known gaps against the original spec", items
M1–M4). Retrieval works and is well tested, but there is nothing in the vault that got there by
learning.

**Three specific things to do before calling ReMe replaced:**

1. **Session-scoped memory.** MEMORY_PLAN's "lifetime knob" (session-scoped and
   paused-workflow working memory) is unbuilt; `SessionConfig` carries only `idle_ttl_min` and
   `offload_threshold_tokens`. Without it there is no cross-session continuity of any kind.
2. **The learning plane.** Extractors, distiller, scorer, shadow validator and promotion exist
   as tested libraries and are constructed nowhere (`workers/runner.py` starts with
   `handlers={}`). Until they run, "Tracebed learns from runs" is a design statement.
3. **A migration story for existing ReMe data.** There is none, deliberately: ReMe summaries are
   conversation text with no trace behind them, and invariant 6 rejects any memory without
   complete provenance at insert. Importing them would require either fabricating provenance or
   relaxing the invariant. The defensible path is to run both for one retention window and let
   ReMe's summaries age out, rather than to import.


---

*See also: `PLAN.md` §3 (the ports table this document expands), `docs/OPERATIONS.md`
(running the service the ports plug into), `src/tracebed/adapters/atom/README.md` (the
Atom-specific mapping of components to these ports).*
