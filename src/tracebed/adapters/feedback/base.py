"""Shared machinery for the four feedback adapter classes (PLAN.md §3/§7, invariant 8).

This module is where invariant 8 -- "no guessed rewards" -- is enforced at the
edge, before any signal has a chance to look like an outcome. Four things live
here:

  - `FeedbackAdapter`: the Protocol every adapter in this package implements
    (verdict / correction / downstream / implicit). It is a strict subset of
    `adapters.ports.FeedbackPort` in behaviour: an adapter may additionally
    raise `AmbiguousSignal` or `NoSignal` instead of always returning an
    event, and both mean "zero events, zero scoring" to `dispatch_feedback`.
  - `ScorerPort` / `AmbiguousSignalSink`: two narrow Protocols scoped to
    exactly what this package calls outward. Neither has a concrete
    implementation in this tree -- the real Q-update scorer (arithmetic,
    contribution judge, `scoring_epoch` persistence) is a separate Phase 3
    chunk this one does not own, and its absence is a contract_gap, not a
    workaround. The pattern mirrors `ingest.outcome_intake.OutcomeRepoPort`:
    declare the narrow interface the consumer needs, let a fake satisfy it
    offline, and let the real implementation slot in later without this
    package changing at all.
  - `dispatch_feedback`: the one function that turns a raw host signal into,
    at most, one call to `ScorerPort.record_outcome` -- with every refusal
    path (caller-supplied weight, ambiguous signal, no-op signal, w=0
    short-circuit) landing before that call, never after it.
  - `operator_edit`: NOT an adapter (D-032). A dashboard action that
    supersedes a memory directly through `state_machine.apply` and never
    touches `ScorerPort`, `AdapterClass`, or `dispatch_feedback` -- its
    signature cannot express any of the three, which is what makes "route an
    operator_edit through the scorer" structurally unreachable rather than
    merely undocumented.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any, ClassVar, Final, Literal, Protocol, runtime_checkable
from uuid import UUID

from tracebed.domain.enums import AdapterClass, ProvenanceClass
from tracebed.domain.events import FeedbackEvent
from tracebed.domain.ids import PrincipalId, ProjectId, RunId
from tracebed.domain.state_machine import Status, TransitionEvidence, TransitionLimits
from tracebed.domain.state_machine import apply as _state_machine_apply

if TYPE_CHECKING:
    from datetime import datetime

    from tracebed.domain.clock import Clock

__all__ = [
    "GRADED_R_PAYLOAD_KEY",
    "MAX_GUARD_DEPTH",
    "NEGATIVE_TOKENS",
    "POSITIVE_TOKENS",
    "AdapterIdentityMismatch",
    "AmbiguousSignal",
    "AmbiguousSignalSink",
    "CallerSuppliedGradedR",
    "CallerSuppliedWeight",
    "FeedbackAdapter",
    "NoSignal",
    "RefusedSignal",
    "ScorerPort",
    "UnscannablePayload",
    "dispatch_feedback",
    "extract_payload",
    "guard_no_caller_weight",
    "operator_edit",
    "optional_datetime",
    "require_event_id",
    "resolve_polarity",
    "resolve_weight",
]


# --------------------------------------------------------------------------- #
# Exceptions.
#
# Two families, and the split is load-bearing. `RefusedSignal` and its
# subclasses mean "this signal is structurally illegal" -- it is raised at the
# caller, nothing is logged as an outcome and nothing is scored, because a
# payload that tries to set its own scoring inputs is a defect (or an attack)
# to be surfaced, not a data point to be recorded. `AmbiguousSignal` /
# `NoSignal` mean the signal was well-formed but carries no scoreable reward;
# those are absorbed by `dispatch_feedback` (logged / dropped), never raised
# at the caller.
# --------------------------------------------------------------------------- #


class RefusedSignal(Exception):
    """Base: the raw signal is structurally illegal and is refused outright."""


class CallerSuppliedWeight(RefusedSignal):
    """A raw host payload named something shaped like a trust weight, at any depth.

    Invariant 8's edge, made structural: `w` comes from the AUTHENTICATED
    adapter class and `scoring.adapter_weights` alone, never from data a
    caller controls. `guard_no_caller_weight` checks every key at every
    depth against the same closed list, so a caller cannot dodge the refusal
    by nesting the key inside `payload`, inside a list entry, or under a
    near-synonym spelling.
    """

    def __init__(self, path: str) -> None:
        super().__init__(f"caller-supplied weight-shaped key at {path!r} is refused")
        self.path = path


class CallerSuppliedGradedR(RefusedSignal):
    """A raw host payload carried a reserved `r` key (`diff_ratio`, or bare `r`).

    `w` is not the only scoring input a caller must never be able to set. `r`
    is the other half of `alpha*w*c*(r-Q)`, and while its BINARY value is
    legitimately caller-asserted (that is what `outcome: positive|negative`
    is), the GRADED value is not: it is derived server-side by
    `CorrectionAdapter` from a real diff, and `dispatch_feedback` prefers it
    over the binary literal. A payload that ships its own `diff_ratio`
    therefore sets `r` to any float in [0,1] it likes on ANY adapter class --
    including sending `outcome: "positive"` with `diff_ratio: 0.0`, which
    drives Q toward retirement (D-021's memory-destruction primitive) while
    every audit view of the event reads "positive". Refused for the same
    reason a caller-supplied weight is.
    """

    def __init__(self, path: str) -> None:
        super().__init__(
            f"caller-supplied graded-r key at {path!r} is refused: the graded r is "
            "server-derived from a real diff, never asserted by the signal's source"
        )
        self.path = path


class AdapterIdentityMismatch(RefusedSignal):
    """A `FeedbackAdapter` returned an event claiming a different adapter class.

    `FeedbackPort` is a HOST-implemented port (PLAN.md §3's ports table), so
    NOTHING that comes back from the adapter object -- neither its own
    `adapter_class` attribute nor the `adapter` field of the event it returns
    -- is trustworthy input to a weight lookup. An implementation the server
    registered as `implicit` (w=0.0) could declare or return `VERDICT` and,
    if `w` were resolved from either, collect the full w=1.0 learning rate.
    `w` is therefore resolved from `registered_class`, which the CALLER (the
    layer holding the authenticated principal) supplies, and both
    self-identifications are checked against it rather than trusted.
    """

    def __init__(self, registered: AdapterClass, claimed: AdapterClass, *, where: str) -> None:
        super().__init__(
            f"adapter registered as {registered.value!r} identifies as {claimed.value!r} "
            f"({where}); an adapter may not re-label its own trust class"
        )
        self.registered = registered
        self.claimed = claimed
        self.where = where


class UnscannablePayload(RefusedSignal):
    """The raw payload is nested too deeply to walk within `MAX_GUARD_DEPTH`.

    `guard_no_caller_weight` is the only thing standing between a caller and
    the scoring inputs, so it must never be the component that fails: an
    unbounded recursion over attacker-shaped JSON raises `RecursionError`,
    which is not a `RefusedSignal`, and a caller's uniform refusal handling
    would not catch it. Refusing an over-nested payload fails closed; letting
    the walk crash fails open at exactly the wrong place.
    """

    def __init__(self, path: str) -> None:
        super().__init__(
            f"raw payload nests deeper than {MAX_GUARD_DEPTH} levels at {path!r}; "
            "refused unscanned"
        )
        self.path = path


class AmbiguousSignal(Exception):
    """The raw signal cannot be resolved to a clear polarity.

    Invariant 8: "a guessed reward is worse than none" -- a caller that
    catches this logs the reason and the raw payload on the trace and
    constructs no Q update from it whatsoever.
    """

    def __init__(self, reason: str, raw: Mapping[str, object]) -> None:
        super().__init__(reason)
        self.reason = reason
        self.raw: dict[str, object] = dict(raw)


class NoSignal(Exception):
    """There is deliberately no outcome to report (e.g. a no-op correction diff).

    Distinct from `AmbiguousSignal`: nothing failed to resolve, nothing
    happened that was worth resolving in the first place. `dispatch_feedback`
    does not log this at all -- there is nothing to log.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# --------------------------------------------------------------------------- #
# Protocols
# --------------------------------------------------------------------------- #


@runtime_checkable
class FeedbackAdapter(Protocol):
    """What every module in this package implements.

    Structurally compatible with `adapters.ports.FeedbackPort.to_outcome` in
    the direction that matters -- anything satisfying this also satisfies
    that Protocol at the method-presence level `runtime_checkable` checks --
    but wider by one contract: `to_outcome` may raise `AmbiguousSignal` or
    `NoSignal` in place of always returning an event. `FeedbackPort`'s own
    docstring only promises a `FeedbackEvent`; this package's tests record
    that widening explicitly rather than assume it away.
    """

    adapter_class: ClassVar[AdapterClass]

    def to_outcome(self, raw: Mapping[str, object]) -> FeedbackEvent: ...


@runtime_checkable
class ScorerPort(Protocol):
    """The one call this package makes toward Q-update scoring.

    Deliberately narrow, mirroring `ingest.outcome_intake.OutcomeRepoPort`'s
    precedent for the same reason: the real scorer (Q arithmetic, the
    contribution judge, `scoring_epoch` stamping) is a separate Phase 3
    chunk not owned here and not present in this tree -- a contract_gap for
    that chunk to satisfy, not something faked beyond what these adapters
    themselves require. `r` and `w` are both keyword-only and separately
    named on purpose: the spec bug this whole invariant exists to correct
    (D-011) was exactly a call site that fed the weight in as the reward.

    `principal_id` is REQUIRED, not optional: `outcome_event.principal_id` is
    `NOT NULL` (PLAN.md §5) because D-021's retirement floor is "Q < 0.25
    after >= 4 scored uses FROM >= K distinct principals". An outcome
    recorded without the authenticated principal that produced it is an
    outcome that cannot be counted toward -- or, worse, cannot be excluded
    from -- that K, which is the whole defence against one attacker-owned
    feedback source retiring any memory in four calendar days. Making it a
    required keyword means no call site can record an anonymous outcome.
    """

    def record_outcome(
        self,
        project_id: ProjectId,
        run_id: RunId,
        *,
        principal_id: PrincipalId,
        adapter: AdapterClass,
        r: float,
        w: float,
        event_id: UUID,
        occurred_at: datetime,
    ) -> None: ...


@runtime_checkable
class AmbiguousSignalSink(Protocol):
    """Where a signal that will never be scored gets logged on the trace.

    Invariant 8: "ambiguous signals are logged on the trace and never
    scored." Also the landing spot for the w=0 short-circuit (IMPLICIT, or
    any adapter class configured to zero) -- from this sink's point of view
    both reasons collapse to the same fact: never scored, logged instead.
    """

    def log_ambiguous(
        self,
        project_id: ProjectId,
        run_id: RunId,
        *,
        adapter: AdapterClass,
        reason: str,
        payload: Mapping[str, object],
    ) -> None: ...


# --------------------------------------------------------------------------- #
# Shared vocabulary + helpers used by verdict / downstream / implicit.
# --------------------------------------------------------------------------- #

POSITIVE_TOKENS: frozenset[str] = frozenset(
    {
        "positive",
        "approved",
        "approve",
        "accept",
        "accepted",
        "pass",
        "passed",
        "correct",
        "success",
        "succeeded",
        "resolved",
        "continued",
        "good",
        "true",
        "up",
        "ok",
    }
)
NEGATIVE_TOKENS: frozenset[str] = frozenset(
    {
        "negative",
        "rejected",
        "reject",
        "fail",
        "failed",
        "failure",
        "incorrect",
        "error",
        "abandoned",
        "reopened",
        "bad",
        "false",
        "down",
    }
)

# Reserved payload key: the graded value a diff-based adapter (correction_adapter)
# computed, read by `dispatch_feedback` in preference to the wire's binary
# `outcome` literal when present and in range. Not a domain/events.py field --
# `FeedbackEvent` is frozen (PHASE0-CONTRACT.md §3.5) and its `outcome` stays
# binary for wire/schema compatibility (D-011: `outcome_event.r` is always the
# server-derived {1.0, 0.0} or this graded float; nothing else).
GRADED_R_PAYLOAD_KEY: Final = "diff_ratio"

_WEIGHT_LIKE_KEYS: frozenset[str] = frozenset(
    {"weight", "w", "trust_weight", "adapter_weight", "score_weight", "q_weight"}
)

# The other half of `alpha*w*c*(r-Q)` a caller must not be able to set. See
# `CallerSuppliedGradedR`. A bare `r` is refused alongside the reserved graded
# key for the same reason `w` is refused alongside `weight`: `outcome_event.r`
# is a server-derived column, and a caller-asserted `r` sitting in the same
# row's jsonb is a shadow copy that disagrees with it -- the shape a dashboard
# or a later predicate reads by mistake.
_SERVER_DERIVED_R_KEYS: frozenset[str] = frozenset({GRADED_R_PAYLOAD_KEY, "r"})

# Depth ceiling for the recursive scan. Deep enough that no plausible webhook
# payload reaches it, shallow enough that the walk cannot exhaust the
# interpreter stack on caller-shaped JSON (see `UnscannablePayload`).
MAX_GUARD_DEPTH: Final = 32

# Control keys this package itself consumes -- never carried into an event's
# auditable payload a second time.
#
# `adapter`/`adapter_class` are dropped rather than refused: a host webhook
# naming its own adapter is ordinary, and refusing it would break honest
# senders. Carrying it into `outcome_event.payload` is what must not happen.
# The row already has an `adapter` COLUMN, resolved from the authenticated
# registration; a caller-asserted string of the same name in the same row's
# jsonb differs from it precisely when someone is lying, and any later
# consumer that reaches for `payload->>'adapter'` (a dashboard facet, a
# promotion predicate counting "outcome-consistent observations") would then
# be keyed on caller input -- the weak-signal false-precedent shape, arrived
# at without anyone deciding to trust the caller.
_CONTROL_KEYS: frozenset[str] = frozenset(
    {"event_id", "occurred_at", "outcome", "verdict", "adapter", "adapter_class"}
)


def resolve_weight(adapter: AdapterClass, weights: Mapping[str, float]) -> float:
    """Fail-closed weight resolution. `w` is legal only in `(0, 1]`.

    This must agree EXACTLY with `workers.scorer.resolve_weight`, which is the
    other producer of a numeric `w`, because the number resolved here is
    handed to `ScorerPort.record_outcome` and the number resolved there is
    the one multiplied into `alpha*w*c*(r-Q)`. Two resolvers that disagree
    about which configured values are legal means the value a deployment sees
    depends on which road an outcome took, which is the same class of bug
    D-011 corrects. `ingest.outcome_intake` only records the `w_zero`
    BOOLEAN, so its `> 0.0` test is not the rule to mirror here.

    Anything outside `(0, 1]` resolves to 0.0 -- the short-circuit, never a
    real weight:

    - absent / 0.0: the class is not configured for scoring.
    - negative: `scoring` is an `OVERRIDABLE_SECTIONS` member, so a
      `project_config` row reaches `adapter_weights` (which carries no
      per-value bound of its own). `w < 0` INVERTS the update -- a negative
      outcome raises Q and a positive one lowers it.
    - NaN: every comparison against it is False, so the same range test
      rejects it without a separate branch.
    - above 1.0: "more than fully trusted" has no meaning, and it is the
      dangerous direction, not merely the meaningless one. With the shipped
      `alpha=0.3`, a `project_config` row setting `verdict: 5.0` makes
      `alpha*w*c = 1.5`, so ONE event overshoots past `r` into `clamp01`:
      Q=0.5 goes straight to 1.0 on a single positive and straight to 0.0 on
      a single negative. That is a one-call promotion (and a one-call
      retirement) primitive reachable from a config row, which is exactly
      what a bounded resolver denies.
    """
    w = weights.get(adapter.value)
    if w is None or not (0.0 < w <= 1.0):
        return 0.0
    return w


def guard_no_caller_weight(raw: Mapping[str, object], *, path: str = "$", depth: int = 0) -> None:
    """Recursively refuse any caller-set scoring input, at any depth, in a raw payload.

    THE thing invariant 8 says must not exist: a scoring input on the wire.
    Two closed key sets are refused -- weight-shaped keys (`w` itself) and
    the reserved graded-`r` key -- because `w` and `r` are the two factors
    the server derives and the caller must never choose (see
    `CallerSuppliedWeight` / `CallerSuppliedGradedR`).

    Every adapter's `to_outcome` calls this first (defense at the adapter
    itself); `dispatch_feedback` calls it again before invoking any adapter,
    so the refusal holds even for an adapter implementation added later that
    forgets to call it.

    The walk descends through nested mappings AND arbitrarily nested
    sequences. Nesting is the whole evasion surface here: a scan that
    descends into `{"a": [{...}]}` but not into `{"a": [[{...}]]}` refuses
    the obvious payload and passes the one an attacker would actually send.
    `str`/`bytes` are sequences too and are deliberately not descended into
    (their "items" are characters, which have no keys).
    """
    if depth > MAX_GUARD_DEPTH:
        raise UnscannablePayload(path)
    for key, value in raw.items():
        key_path = f"{path}.{key}"
        if isinstance(key, str):
            token = key.strip().lower()
            if token in _WEIGHT_LIKE_KEYS:
                raise CallerSuppliedWeight(key_path)
            if token in _SERVER_DERIVED_R_KEYS:
                raise CallerSuppliedGradedR(key_path)
        _guard_value(value, path=key_path, depth=depth + 1)


def _guard_value(value: object, *, path: str, depth: int) -> None:
    """The non-mapping half of `guard_no_caller_weight`'s walk."""
    if depth > MAX_GUARD_DEPTH:
        raise UnscannablePayload(path)
    if isinstance(value, Mapping):
        guard_no_caller_weight(value, path=path, depth=depth)
        return
    if isinstance(value, (str, bytes, bytearray)):
        return
    if isinstance(value, Sequence):
        for i, item in enumerate(value):
            _guard_value(item, path=f"{path}[{i}]", depth=depth + 1)


def resolve_polarity(raw: Mapping[str, object], keys: Sequence[str]) -> Literal["positive", "negative"]:
    """Map the present keys in `keys` to one `"positive"`/`"negative"` polarity.

    Strict by design: a verdict, a downstream status, or an implicit signal
    all *claim* to already be a clear outcome, so loose interpretation here
    converts an ostensibly-clear signal into a guessed one. Anything not in
    the closed vocabulary -- including a present-but-empty value -- raises
    `AmbiguousSignal` rather than defaulting either way.

    EVERY key is examined, not just the first one that resolves. Returning on
    the first hit made `{"outcome": "positive", "status": "failure"}` a clean
    positive: the losing key is then dropped from the event's auditable
    payload by `extract_payload`, so the recorded outcome is a confident
    approval and the contradicting half of the same message no longer exists
    anywhere. Two recognised polarity claims that disagree are the textbook
    ambiguous signal -- "a guessed reward is worse than none" -- so they are
    refused and logged whole.

    An unrecognised value in a LATER key is not a competing claim and does not
    refuse: `result` in particular is as likely to hold a result object as a
    status word, and treating arbitrary data under a colliding key name as a
    contradiction would refuse ordinary host payloads. An unrecognised value
    before anything has resolved is still ambiguous, exactly as before.
    """
    decided: Literal["positive", "negative"] | None = None
    for key in keys:
        if key not in raw:
            continue
        value = raw[key]
        if value is None:
            continue
        token = str(value).strip().lower()
        polarity: Literal["positive", "negative"]
        if token in POSITIVE_TOKENS:
            polarity = "positive"
        elif token in NEGATIVE_TOKENS:
            polarity = "negative"
        elif decided is None:
            raise AmbiguousSignal(f"{key}={value!r} is not a recognised polarity token", raw)
        else:
            continue
        if decided is not None and polarity != decided:
            raise AmbiguousSignal(
                f"polarity keys disagree: {key}={value!r} reads {polarity!r} but an "
                f"earlier key in {tuple(keys)} read {decided!r}",
                raw,
            )
        decided = polarity
    if decided is None:
        raise AmbiguousSignal(f"none of {tuple(keys)} present in raw signal", raw)
    return decided


def require_event_id(raw: Mapping[str, object]) -> UUID:
    """The dedup key every `FeedbackEvent` needs. Absent or malformed is
    treated as unresolvable, not as a reason to mint one on the signal's
    behalf -- minting an id the source never asserted would make replay
    dedup silently untrustworthy."""
    value = raw.get("event_id")
    if value is None:
        raise AmbiguousSignal("no 'event_id' present -- cannot dedupe this signal", raw)
    if isinstance(value, UUID):
        return value
    try:
        return UUID(str(value))
    except ValueError as exc:
        raise AmbiguousSignal(f"'event_id'={value!r} is not a valid UUID", raw) from exc


def optional_datetime(value: object) -> datetime | None:
    """Parse `occurred_at` if present; refuse an unparsable OR a naive value.

    D-043/C-35 reject a naive `occurred_at` at the wire (`api.models.FeedbackIn`)
    and again at the consumer (`ingest.outcome_intake`), for a reason that
    applies verbatim here: the value ends up in a `timestamptz`, Postgres
    reinterprets a naive one in the session TimeZone, the event silently
    moves by hours, and T+2-day feedback attach is a time join. This package
    is a THIRD entry point -- `dispatch_feedback` hands `occurred_at`
    straight to `ScorerPort.record_outcome` without passing through either of
    the other two -- so the rejection has to exist here as well or the one
    path that skips the wire is the one path that accepts the bad value.

    A `tzinfo` whose `utcoffset()` returns `None` is just as unanchored as
    `tzinfo is None`, and Python treats such a value as naive; both are
    refused, matching `domain.events._EventBase._ts_must_be_tz_aware`.
    """
    from datetime import datetime as _datetime

    if value is None:
        return None
    if isinstance(value, _datetime):
        parsed = value
    else:
        try:
            parsed = _datetime.fromisoformat(str(value))
        except ValueError as exc:
            raise ValueError(f"occurred_at={value!r} is not a valid ISO-8601 datetime") from exc
    if parsed.tzinfo is None or parsed.tzinfo.utcoffset(parsed) is None:
        raise ValueError(
            f"occurred_at={value!r} is timezone-naive; the column it lands in is timestamptz"
        )
    return parsed


def extract_payload(raw: Mapping[str, object], *, drop: frozenset[str] = frozenset()) -> dict[str, Any]:
    """Everything in `raw` that is not a control key this package consumes,
    carried forward as the event's auditable payload.

    Safe by construction, twice over: `guard_no_caller_weight` has already
    refused any weight-shaped or graded-`r` key anywhere in `raw` before any
    adapter reaches this function, and the reserved graded-`r` key is dropped
    here as well. The second check is not redundant paranoia -- this function
    is what decides which caller bytes become the event's payload, and
    `dispatch_feedback` reads `r` back out of exactly that payload, so "the
    guard already ran" is a claim about a caller elsewhere. A future adapter
    that builds a payload without the guard still cannot smuggle `r` in.
    """
    excluded = _CONTROL_KEYS | _SERVER_DERIVED_R_KEYS | drop
    return {k: v for k, v in raw.items() if k not in excluded}


# --------------------------------------------------------------------------- #
# The dispatcher -- the edge invariant 8 lives at.
# --------------------------------------------------------------------------- #


def dispatch_feedback(
    raw: Mapping[str, object],
    *,
    project_id: ProjectId,
    run_id: RunId,
    principal_id: PrincipalId,
    adapter: FeedbackAdapter,
    registered_class: AdapterClass,
    weights: Mapping[str, float],
    scorer: ScorerPort,
    sink: AmbiguousSignalSink,
    clock: Clock,
) -> None:
    """Turn one raw host signal into, at most, one call to `ScorerPort.record_outcome`.

    Order matters and is the whole point:

    1. The caller-scoring-input guard runs before the adapter ever sees the
       payload, so neither `w` nor a graded `r` can arrive as data.
    2. `w` is resolved from `registered_class` -- the class the SERVER bound
       to this authenticated source -- and it is resolved BEFORE any adapter
       code runs. Neither `adapter.adapter_class` (an attribute of a
       host-implemented object) nor `event.adapter` (a field of that
       object's return value) ever keys the weights map; both are only ever
       COMPARED against `registered_class`, and a disagreement is refused
       (`AdapterIdentityMismatch`).
    3. `AmbiguousSignal` -> logged, zero scorer calls. `NoSignal` -> dropped,
       zero of either.
    4. `w <= 0` short-circuits: logged, and `scorer` is never touched at all
       ("no update, no row, nothing"). Note what this is NOT: it is not a
       call into the scorer with `w=0` relying on `alpha*0*c*(r-Q) == 0` to
       be harmless. That would still write an outcome row and still spend the
       memory's one-update-per-day slot on a signal invariant 8 says must
       never score.

    Only a signal that clears all four reaches `scorer.record_outcome`, and
    it reaches it with `r` as outcome polarity and `w` as the server-derived
    trust weight -- separate keyword arguments, never swapped (D-011).
    """
    guard_no_caller_weight(raw)

    if adapter.adapter_class is not registered_class:
        raise AdapterIdentityMismatch(
            registered_class, adapter.adapter_class, where="adapter.adapter_class"
        )

    # The only weight lookup, keyed by the authenticated class, before any
    # adapter code runs.
    w = resolve_weight(registered_class, weights)

    try:
        event = adapter.to_outcome(raw)
    except AmbiguousSignal as exc:
        sink.log_ambiguous(
            project_id,
            run_id,
            adapter=registered_class,
            reason=exc.reason,
            payload=exc.raw,
        )
        return
    except NoSignal:
        return

    if event.adapter is not registered_class:
        raise AdapterIdentityMismatch(registered_class, event.adapter, where="event.adapter")

    if w <= 0.0:
        sink.log_ambiguous(
            project_id,
            run_id,
            adapter=registered_class,
            reason="w=0 short-circuit: adapter class carries no trust weight, never scored",
            payload=event.payload,
        )
        return

    r = _extract_r(event, registered_class)
    occurred_at = event.occurred_at if event.occurred_at is not None else clock.now()
    scorer.record_outcome(
        project_id,
        run_id,
        principal_id=principal_id,
        adapter=registered_class,
        r=r,
        w=w,
        event_id=event.event_id,
        occurred_at=occurred_at,
    )


def _extract_r(event: FeedbackEvent, adapter_class: AdapterClass) -> float:
    """Outcome polarity in [0,1].

    Binary from the wire's `Literal["positive","negative"]` field (D-011:
    this is the value the corrected Q update calls `r`, and it is exactly
    what `ingest.outcome_intake` derives on the queue path -- the two paths
    must not disagree about what `r` means).

    The ONE exception is the graded value a correction diff computed, and it
    is gated on `adapter_class` -- the class the caller authenticated, not
    `event.adapter` -- rather than on the key's mere presence:
    PLAN.md §3 says "server maps to r in {1, 0}; graded r RESERVED FOR
    CORRECTION DIFFS". Honouring the key on any other class would mean a
    verdict or downstream signal could carry its own float `r` -- and since
    the payload is built from caller bytes, that float would be caller-chosen
    (`outcome: "positive"` with `diff_ratio: 0.0` reads as approval in every
    audit view while driving Q to the retirement floor). `CorrectionAdapter`
    is the only thing in this package that sets the key, and it sets it from
    a `SequenceMatcher` ratio it computed itself.

    A malformed or out-of-range graded value never overrides the safe binary
    fallback -- a bad graded number must degrade to the conservative binary
    reading, not propagate.
    """
    if adapter_class is not AdapterClass.CORRECTION_ADAPTER:
        return 1.0 if event.outcome == "positive" else 0.0
    graded = event.payload.get(GRADED_R_PAYLOAD_KEY)
    if isinstance(graded, int | float) and not isinstance(graded, bool) and 0.0 <= graded <= 1.0:
        return float(graded)
    return 1.0 if event.outcome == "positive" else 0.0


# --------------------------------------------------------------------------- #
# operator_edit -- NOT an adapter (D-032).
# --------------------------------------------------------------------------- #


def operator_edit(*, current: Status, evidence: TransitionEvidence, limits: TransitionLimits) -> Status:
    """A dashboard action, NOT an adapter (D-032; PLAN.md §7).

    A human editing a memory (as opposed to `correction_adapter`, which
    scores a human editing the agent's *output*) supersedes the memory
    directly through the one state machine -- the same and only mechanism
    every other status change in this codebase uses (invariant 7). It is
    put in this package specifically so the distinction between "an adapter,
    scored, w-weighted" and "an operator action, unscored, direct" is
    visible in one place rather than scattered.

    Structurally cannot reach the scorer: this function's signature carries
    no `AdapterClass`, no `r`, no `w`, no `ScorerPort`, and no `FeedbackEvent`
    -- there is nothing here for a caller to thread into `dispatch_feedback`
    even by mistake. `Status.SUPERSEDED` is the only target (an operator
    edit supersedes; it does not promote, retire, or archive), so the
    (`validated`, `superseded`) guard is the only one this can ever invoke.
    """
    if evidence.provenance_class is not ProvenanceClass.OPERATOR:
        raise ValueError(
            "operator_edit requires TransitionEvidence.provenance_class == OPERATOR; "
            "adapter-sourced evidence must never reach this bypass"
        )
    return _state_machine_apply(current, Status.SUPERSEDED, evidence, limits)
