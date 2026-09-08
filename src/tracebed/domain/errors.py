"""The exception hierarchy every Tracebed chunk raises and catches.

PHASE0-CONTRACT.md §3.1: this is the shared vocabulary that lets parallel
chunks compose without importing each other's internals — a repo error, an
auth error, and a state-machine error are all just ``TracebedError`` to a
caller that only needs to know something went deliberately wrong. Leaf-level
by design (stdlib imports only) so every other domain module — including
``state_machine.py``, which nothing here may import back — can depend on
this module without pulling in the rest of ``domain``.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Deferred on purpose: state_machine.py is owned by chunk
    # domain-state-machine and need not exist yet for this module to import
    # cleanly. `from __future__ import annotations` means the annotations
    # below are never evaluated at runtime — only a type checker resolves
    # this name, and only once state_machine.py lands.
    from tracebed.domain.state_machine import Status

__all__ = [
    "ActivityBusy",
    "AuthenticationFailed",
    "AuthorizationDenied",
    "BudgetExceeded",
    "CapExceeded",
    "ConfigError",
    "CrossEpochComparison",
    "DuplicateRegistration",
    "EmbeddingTimeout",
    "ErasureClosureChanged",
    "ErasureDependencyTimeout",
    "ErasureFenced",
    "ErasureLeaseLost",
    "ErasureOperatorBlocked",
    "ErasureRequestNotFound",
    "ErasureSnapshotStale",
    "ErasureTargetConflict",
    "GuardNotSatisfied",
    "IllegalTransition",
    "MasterKeyMissing",
    "NotFound",
    "ProjectInactive",
    "ProjectProvisioningConflict",
    "ProvenanceIncomplete",
    "QueueFull",
    "RequestDeadlineExceeded",
    "RetrievalAuditUnavailable",
    "RunAuthorityDenied",
    "ScanRejected",
    "ScanVerdictForgery",
    "ScopeResolutionFailed",
    "Tombstoned",
    "TracebedError",
]


class TracebedError(Exception):
    """Root. Every exception Tracebed raises deliberately derives from this.

    Lets `api/main.py`'s single exception handler (§9.4) catch "anything
    Tracebed meant to raise" as one case and fall back to an opaque 500 for
    everything else, so a stray unmapped exception never leaks a stack trace
    or class name to a caller.
    """


class RetrievalAuditUnavailable(TracebedError):
    """Terminal retrieval audit could not be durably recorded."""


# -- config / wiring --------------------------------------------------------


class ConfigError(TracebedError):
    """Bad settings, an unknown override key, or bad config-layer composition.

    Raised by `ConfigResolver.effective()` (PHASE0-CONTRACT §3.4 / C-03) for
    an unknown dotted override key, an override targeting a deployment-level
    section, or an override value that fails field validation.
    """


# -- auth / scope (api-auth raises; api layer maps to HTTP per §9.4) --------


class AuthenticationFailed(TracebedError):
    """No credential, or a credential that failed verification.

    Maps to HTTP 401 (§9.4). Never distinguishes "wrong key" from "unknown
    key" in its message — that distinction is itself a leak.
    """


class ScopeResolutionFailed(TracebedError):
    """Authenticated but no `agent_registration` row exists for this principal.

    Maps to HTTP 403 (§9.4). Distinct from `AuthenticationFailed`: the
    credential was valid, but invariant 4 (server-derived scope) has nowhere
    to derive a project from.
    """


class AuthorizationDenied(TracebedError):
    """Authenticated caller lacks the required project capability.

    Maps to one opaque HTTP 403 shape.  It deliberately accepts no detail so
    callers cannot turn a missing role, grant source, or revoked capability
    into an authorization oracle.
    """

    status_code = 403

    def __init__(self) -> None:
        super().__init__("access denied")


class ProjectInactive(TracebedError):
    """The server resolved a non-active project state (opaque HTTP 403)."""

    status_code = 403

    def __init__(self) -> None:
        super().__init__("access denied")


class RunAuthorityDenied(TracebedError):
    """A run is absent, foreign, or bound to different server-side ownership.

    It maps to the same opaque 404 body as an ordinary by-id miss and accepts
    no identifiers or mismatch details.
    """

    status_code = 404

    def __init__(self) -> None:
        super().__init__("not found")


class ActivityBusy(TracebedError):
    """A keyed activity is already in progress; callers may retry (HTTP 503)."""

    status_code = 503
    retryable = True

    def __init__(self) -> None:
        super().__init__("activity busy")


class ErasureTargetConflict(TracebedError):
    """A different non-terminal erasure target already owns the project.

    The exception deliberately retains no target or request identity.  The
    API maps every such collision to one opaque 409 response so a caller
    cannot use it to enumerate another subject's request.
    """

    status_code = 409

    def __init__(self) -> None:
        super().__init__("erasure target conflict")


class ErasureFenced(TracebedError):
    """A durable erasure/project fence refuses a normal side effect (409)."""

    status_code = 409

    def __init__(self) -> None:
        super().__init__("erasure fence refused activity")


class ErasureSnapshotStale(TracebedError):
    """A worker's claimed attribution snapshot is no longer authoritative.

    This is an internal retry signal. Consumers NACK and reload their
    propagated queue row before any side effect; it is never a public API
    response or a reason to terminally dead-letter valid work.
    """


class ErasureLeaseLost(TracebedError):
    """The E3 executor no longer owns its short-lived database lease.

    This is an internal stop signal.  It must be handled before another
    external I/O operation or a receipt/work mark is attempted.
    """


class ErasureOperatorBlocked(TracebedError):
    """A fail-closed erasure condition needs a fixed-code operator action."""


class ErasureClosureChanged(TracebedError):
    """The authoritative closure revision changed during an E3 step.

    This is neither a store proof failure nor an operator condition.  The
    executor records the closed ``closure_changed`` retry receipt, releases
    its lease through the normal retry path, and a later claim re-runs the
    revision-sensitive pass.
    """


class ErasureDependencyTimeout(TracebedError):
    """A bounded E3 store operation exceeded its configured deadline.

    This is intentionally distinct from an unverifiable store result: the
    executor records the closed ``dependency_timeout`` retry code and leaves
    any externally completed side effect to a successor's idempotent proof.
    """


class DuplicateRegistration(TracebedError):
    """A second `agent_registration` row for a principal that already has one.

    `agent_registration.principal_id` is UNIQUE (PHASE-0 Task 5) — one
    principal binds to exactly one project. Maps to HTTP 409 (§9.4).
    """


class ProjectProvisioningConflict(TracebedError):
    """An idempotency key was replayed with a different project request.

    The API maps this to an opaque 409.  The stored request hash is useful
    only for the transactional comparison and must never be exposed to a
    caller.
    """


# -- lookups ------------------------------------------------------------


class NotFound(TracebedError):
    """By-id miss, deliberately identical for two very different causes.

    "Does not exist" and "exists, but in a project you cannot see" produce
    this exact same exception and the exact same HTTP 404 body (§9.4) — this
    is what leak-suite probe 2 (cross-project by-id fetch) verifies: a
    distinguishable error shape is itself a leak of project existence.
    """


class ErasureRequestNotFound(NotFound):
    """An erasure status row is absent, foreign, or not visible.

    It is intentionally a ``NotFound`` subclass so the wire body is exactly
    identical to every other project-scoped by-id miss.
    """

    def __init__(self) -> None:
        super().__init__()


# -- write-side governance ---------------------------------------------


class ProvenanceIncomplete(TracebedError):
    """A `memory_item` insert whose provenance lacks its class's required field.

    Invariant 6's pure half (`domain.memory.validate_provenance`) raises this
    before any I/O is attempted; `Repo.insert_memory_item` raises it again as
    the DB-adjacent backstop. No insert path may catch and swallow it.
    """


class ScanRejected(TracebedError):
    """The shared scan suite (`core/scans`) refused this content.

    Carries every reason the suite found, not just the first — a caller
    persisting to `review_queue` (PHASE-0 Task 9) needs the full set.
    """

    def __init__(self, reasons: Sequence[str]) -> None:
        # Materialise once, before rendering the message: a caller passing a
        # one-shot iterable (a genexp over scan rules is the obvious way to
        # build this) would otherwise have its reasons consumed by the join
        # and land in review_queue with an empty reason set.
        frozen: tuple[str, ...] = tuple(reasons)
        super().__init__(", ".join(frozen) if frozen else "scan rejected")
        self.reasons: tuple[str, ...] = frozen


class ScanVerdictForgery(TracebedError):
    """A `ScanVerdict` whose HMAC, caller module, or content hash does not check out.

    Covers both directions of §3.7's forgery resistance: a verdict minted
    outside `core.scans` (blocked at construction) and a verdict whose
    signature or bound content hash fails `core.scans.verify_verdict` at
    insert time — the two halves that together make "insert without a real
    scan" structurally impossible, not just discouraged.
    """


# -- state machine -------------------------------------------------------


class IllegalTransition(TracebedError):
    """The `(current, target)` edge does not exist in `TRANSITIONS` at all.

    Distinct from `GuardNotSatisfied`: this is "no such edge in the graph"
    (e.g. `quarantined -> validated` directly), not "the edge exists but the
    evidence doesn't clear its guard".
    """

    def __init__(self, current: Status | None, target: Status) -> None:
        super().__init__(f"illegal transition: {current!r} -> {target!r}")
        self.current = current
        self.target = target


class GuardNotSatisfied(TracebedError):
    """A legal `(current, target)` edge whose guard rejected this evidence.

    `reason` is guard-supplied prose (e.g. "only 1 of 2 required independent
    confirmations") — informational only, never parsed by callers; the
    state machine has no other way to signal "close, but not yet"
    (invariant 7: there is no admin bypass).
    """

    def __init__(self, current: Status | None, target: Status, reason: str) -> None:
        super().__init__(f"guard not satisfied: {current!r} -> {target!r} ({reason})")
        self.current = current
        self.target = target
        self.reason = reason


# -- queue / ingest -------------------------------------------------------


class QueueFull(TracebedError):
    """Producer-side hard cap on `work_queue` depth.

    Opaque, retryable admission backpressure.  Capacity details stay server
    side so a caller cannot use the response as a queue-depth oracle.
    """

    status_code = 503
    retryable = True

    def __init__(self) -> None:
        super().__init__("queue busy")


# -- crypto / trace store --------------------------------------------------


class Tombstoned(TracebedError):
    """API-level access to material whose subject key has been destroyed.

    The crypto-shredding read path (§6.2) returns a `TombstonedSection`
    sentinel internally, not this exception — `Tombstoned` is for the layer
    above that turns "this section is gone" into a definite outcome for a
    caller that asked for one specific thing.
    """


class MasterKeyMissing(TracebedError):
    """`TB_MASTER_KEY` is absent or malformed at startup.

    Raised by `EnvMasterKeyProvider` at construction (§6.2 / C-15) — a
    missing master key must fail the process before it accepts a single
    trace byte, not silently write unencryptable payloads.
    """


# -- reserved for later phases (declared now, raised never in Phase 0) ------


class EmbeddingTimeout(TracebedError):
    """Reserved for Phase 1's embedding-port timeout handling."""


class BudgetExceeded(TracebedError):
    """Reserved for Phase 1's retrieval token-budget enforcement."""


class RequestDeadlineExceeded(TracebedError):
    """A cooperative request boundary had no remaining time to begin work."""

    status_code = 503


class CapExceeded(TracebedError):
    """Reserved for Phase 3's proposal / spend cap enforcement."""


class CrossEpochComparison(TracebedError):
    """Reserved for Phase 3's scoring-epoch comparison guard."""
