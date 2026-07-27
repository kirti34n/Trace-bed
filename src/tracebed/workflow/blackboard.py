"""Run blackboard: shared, transactional coordination state between agents in one run.

PLAN.md §7 Phase 4 ("Workflow memory + polish") / D-038. This module is the *domain*
half — pure logic, no I/O, no SQL (persistence is `tracebed.stores.pg.blackboard`,
which is the only legal place SQL runs, per `scripts/raw_sql_lint.py`). It owns:

  - `BlackboardProposal.create` — the ONE place `author_agent` is derived, from an
    authenticated `ProjectScope`, never from a request body. An agent that could name
    itself as the author of an entry could impersonate another agent inside the same
    run, which is exactly what PLAN.md §7 calls out by name. `BlackboardProposal`'s
    ordinary dataclass constructor is guarded (`__post_init__`) so that `.create()` is
    the only call site that can ever produce one — see `_guard_construction_site`.
    That guard is defence in depth, NOT the security boundary, and this file will not
    pretend otherwise: no Python dataclass can be one, because `object.__setattr__`
    reaches past `frozen=True` and `copy.copy` reconstructs an instance without ever
    running `__init__`. The load-bearing control is
    `stores.pg.blackboard.BlackboardRepo.commit`, which re-checks
    `proposal.author_agent == scope.principal_id` against the authenticated scope that
    opens the transaction: a forged proposal can therefore be *built*, but it can never
    be *committed* under an identity its committer is not authenticated as.
  - `compute_value_ref` — the content address (`sha256` of the value's canonical JSON
    encoding, via `domain.canonical` — THE one serialiser every hash in this codebase
    goes through) that makes two agents proposing byte-identical values *converge*
    instead of *conflicting* (PLAN.md §7: "content addressing means two agents writing
    identical values converge instead of conflicting").
  - `resolve_after_conflict` — the pure decision `stores.pg.blackboard.BlackboardRepo`
    calls after an `INSERT ... ON CONFLICT DO NOTHING` finds the key already taken:
    same value_ref -> `converged`; different value_ref -> `BlackboardKeyConflict`, a
    typed error naming the winner; a row that is not this proposal's key at all ->
    `ValueError`, because that is a repository bug and converging on some other key's
    identical content would report success for a value nobody committed under this name.
    `UNIQUE(project_id, run_id, branch_id, key)` (the
    table's own primary key, migrations/0002_partitioned.sql) is what makes "exactly
    one winner, everyone else conflicts" true at the database level; this function is
    what turns that DB-level fact into the two caller-visible outcomes PLAN.md §7
    describes, without ever touching a connection itself.

NAMED SYNCHRONOUS EXCEPTION (invariant 5, PLAN.md §2 / §7 / D-038). Every other write
path in Tracebed is fire-and-forget through `work_queue` — trace events, outcome
events, derived-memory writes. Blackboard commits are the one deliberate exception:
`BlackboardRepo.commit` opens ONE transaction, attempts the insert, and returns a
result to the caller synchronously. Blackboard entries are *run-state* — coordination
data agents produce and consume WITHIN the lifetime of one run — not a *learning*
write, so invariant 5's "nothing on the write side is awaited by the agent runtime"
does not apply here by its own terms (it governs trace/outcome/derived-memory writes,
which teach the *vault*; a blackboard entry teaches nothing outside its own run and is
gone with it). DO NOT "fix" this into `work_queue`: a queued commit could not promise
"a parallel branch either sees a whole commit or none" (PLAN.md §7) because a second
branch could observe the pre-commit state indefinitely while the write sits in the
queue — reintroducing exactly the key-squatting race this module exists to prevent,
under the banner of "consistency with invariant 5". If a future reviewer proposes that
change, this paragraph is the answer: no.

BLACKBOARD CONTENT IS UNTRUSTED-ORIGIN. A committed `value` is free text (or a JSON
structure) an agent chose to write mid-run — the opposite of Tier A's closed-
vocabulary, parser-derived, zero-byte-passthrough content
(`core.scans.tier_a_template.TierANote`, D-019) or of a `domain.memory.NewMemoryItem`'s
governed provenance. NOTHING DERIVED FROM A BLACKBOARD ENTRY MAY BECOME A MEMORY ITEM,
made structurally true here rather than left as a convention:

  1. This module has ZERO import of `tracebed.domain.memory` (`NewMemoryItem`,
     `Provenance`) or `tracebed.core.scans.tier_a_template` (`TierANote`) — nothing
     here can construct either type, because neither name is even in scope.
     `tests/phase4/test_blackboard.py` AST-walks this file (and
     `stores.pg.blackboard`) to keep that true mechanically, not just by inspection.
  2. None of `BlackboardProposal`, `BlackboardEntryRow`, or `BlackboardCommitResult`
     carries a `trust_tier` or `provenance` field — the two fields
     `NewMemoryItem.__init__` requires. There is no field-for-field path from a
     blackboard type to a memory-item constructor call; building one would require
     fabricating a `Provenance` from nothing, which is a decision left entirely to
     whatever code chose to do that, not something this module offers or implies.

Known residual (recorded honestly, not hidden): `core.scans.tier_a_template`'s own
comment on `ToolIdentifier`'s charset says as much — a short, punctuation-free
blackboard string (say, a single identifier-shaped word) *would* pass that charset
check if some other, unrelated piece of code deliberately fed it into a `TierANote`
field. This module does not close that residual gap (it isn't reachable from here —
see point 1) and neither does D-019's own text claim to; `tests/phase4/test_blackboard.py`
demonstrates the much more common case (free text with spaces/punctuation, which is
what an agent actually writes) is rejected by that same existing validation.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Final, Literal

from tracebed.domain.canonical import canonical_json, sha256_hex
from tracebed.domain.errors import TracebedError
from tracebed.domain.ids import PrincipalId, ProjectId, RunId
from tracebed.domain.scope import ProjectScope

__all__ = [
    "MAX_BLACKBOARD_KEY_BYTES",
    "BlackboardCommitResult",
    "BlackboardCommitUnresolved",
    "BlackboardEntryRow",
    "BlackboardError",
    "BlackboardKeyConflict",
    "BlackboardProposal",
    "CommitOutcome",
    "compute_value_ref",
    "resolve_after_conflict",
]

#: The two outcomes a commit can legally RETURN. There is no third value — a commit
#: either lands as the row (`"committed"`) or discovers an existing row with the identical
#: content address (`"converged"`). Everything else raises: `BlackboardKeyConflict` when
#: another agent owns the key with different content, `BlackboardCommitUnresolved` when the
#: store cannot answer at all.
CommitOutcome = Literal["committed", "converged"]

#: The only status value `stores.pg.blackboard.BlackboardRepo.commit` ever writes.
#: `blackboard_entry.status` (migrations/0002_partitioned.sql) has no CHECK constraint
#: enumerating legal values (unlike `memory_item.status`, which is governed by the one
#: state machine, PLAN.md §5) — this constant is what keeps every row this codebase
#: writes at exactly one literal, without inventing a second governance mechanism for a
#: table invariant 5 explicitly carves out of the learning-memory state machine.
STATUS_COMMITTED: Final[str] = "committed"

# The exact qualified name `.create()` compiles to. Checked against `co_qualname`
# (stable since Python 3.11) rather than by comparing function/code objects, because
# the legitimate factory and the guard live in the SAME module here — unlike
# `domain.scan.ScanVerdict`, whose guard rejects everything from ITS OWN module and
# accepts only a named OTHER module (`core.scans`). That pattern cannot distinguish
# ".create() in this module" from "anything else in this module" when both are true of
# the same frame's `__name__`; qualified-name identity of the specific function does.
_CREATE_QUALNAME: Final[str] = "BlackboardProposal.create"

# `branch_id` and `key` are the two caller-chosen components of
# `PRIMARY KEY (project_id, run_id, branch_id, key)`, and that primary key is a btree
# index whose entries cannot exceed BTMaxItemSize -- 2704 bytes on the default 8 KiB
# page. Without this check an agent-supplied key of a few kilobytes reaches Postgres and
# comes back as `psycopg.errors.ProgramLimitExceeded` from inside an already-open
# transaction on the one write path an agent runtime synchronously awaits (PLAN.md §7's
# named exception to invariant 5). Bounding the two text components here rejects it
# BEFORE `BlackboardRepo.commit` opens anything, as a typed `ValueError` the caller can
# act on. The budget below is that structural btree limit minus the two uuid columns
# (16 bytes each) and generous index-tuple header slack -- a database limit, not a
# tunable policy, which is why it is a named constant here and not a config field
# (PLAN.md §6 declares no blackboard field).
_BTREE_MAX_ITEM_BYTES: Final[int] = 2704
_PK_UUID_COLUMN_BYTES: Final[int] = 16 * 2
_INDEX_TUPLE_HEADER_SLACK_BYTES: Final[int] = 64
MAX_BLACKBOARD_KEY_BYTES: Final[int] = (
    _BTREE_MAX_ITEM_BYTES - _PK_UUID_COLUMN_BYTES - _INDEX_TUPLE_HEADER_SLACK_BYTES
)


class BlackboardError(TracebedError):
    """Root for this chunk's own errors.

    `domain/errors.py` is the Phase 0 exception hierarchy and is frozen by contract
    ("ALL classes are defined in Phase 0 so later phases never touch this file's
    shape", PHASE0-CONTRACT.md §3.1) and is not in this chunk's file list — new
    Phase 4 error types are declared here instead, deriving from `TracebedError` so
    `api/main.py`'s single "anything Tracebed raises deliberately" handler still
    catches them without having to know this module exists.
    """


class BlackboardCommitUnresolved(BlackboardError):
    """A commit neither landed, nor converged, nor lost to a nameable winner.

    `stores.pg.blackboard.BlackboardRepo.commit` raises this when its
    `INSERT ... ON CONFLICT DO NOTHING` inserted nothing and the follow-up read of the
    same key in the same transaction found nothing either. Since no code path in this
    codebase ever deletes a `blackboard_entry` row, the reachable cause is a transaction
    snapshot older than the winner's commit -- an isolation level stricter than READ
    COMMITTED (see that module's docstring). Typed rather than a bare `RuntimeError` so a
    caller can tell "the blackboard could not answer" apart from "another agent owns this
    key" (`BlackboardKeyConflict`) instead of having to match on a message.
    """


class BlackboardKeyConflict(BlackboardError):
    """A commit lost the unique-constraint race for `(project_id, run_id, branch_id,
    key)`, and the row that won holds a DIFFERENT value (a different content hash) than
    this proposal. This is the typed conflict PLAN.md §7's contention test expects for
    N-1 of N racing committers on the same key; the Nth outcome for identical content is
    `"converged"` — this exception is never raised for that case.
    """

    def __init__(
        self, *, key: str, branch_id: str, winning_value_ref: str, winning_author: str
    ) -> None:
        self.key = key
        self.branch_id = branch_id
        self.winning_value_ref = winning_value_ref
        self.winning_author = winning_author
        # Deliberately phrased so no literal text segment of this f-string starts with a
        # SQL keyword (`scripts/raw_sql_lint.py`'s SQL_START regex matches leading
        # "WITH" case-insensitively -- a real false positive this module hit once; kept
        # as a comment so nobody "fixes" the wording back into that trap).
        super().__init__(
            f"blackboard key {key!r} on branch {branch_id!r} is already committed by "
            f"{winning_author}; a different value is proposed "
            f"(winning value_ref={winning_value_ref})"
        )


def compute_value_ref(value: object) -> str:
    """The content address for a blackboard value: sha256 hex of its canonical JSON
    encoding (`domain.canonical.canonical_json` — PHASE0-CONTRACT.md §2/C-01, THE one
    serialiser every content_hash/canonical_args/input_signature_hash in this codebase
    goes through). Two proposals whose `value` serialises identically compute the
    identical `value_ref`, which is what lets two agents writing the same logical value
    converge instead of conflicting (PLAN.md §7).

    Raises `ValueError` for a value `canonical_json` cannot represent (NaN, Infinity, a
    non-JSON-serialisable object, ...) — the same failure mode that function documents
    — rather than silently falling back to `repr()`/`str()`, either of which would make
    two logically-identical values hash differently depending on incidental object
    formatting or identity.
    """
    return sha256_hex(canonical_json(value))


@dataclass(frozen=True, slots=True)
class BlackboardProposal:
    """The 'propose' half (PLAN.md §7: "propose -> commit in transactions"): pure, no
    I/O, computed entirely client-side before a transaction is ever opened.
    `author_agent` is fixed at construction, from `scope.principal_id` — never a
    parameter a caller supplies directly — which is what makes "an agent that can name
    itself can impersonate another agent" structurally impossible rather than merely
    discouraged: `BlackboardProposal(...)` itself refuses to run unless the immediate
    caller is `BlackboardProposal.create` (see `__post_init__`), and `.create()` never
    accepts an `author_agent` argument at all.
    """

    project_id: ProjectId
    run_id: RunId
    branch_id: str
    author_agent: PrincipalId
    key: str
    value_ref: str

    def __post_init__(self) -> None:
        if not self.branch_id:
            raise ValueError("BlackboardProposal.branch_id must be non-empty")
        if not self.key:
            raise ValueError("BlackboardProposal.key must be non-empty")
        # Byte length, not character count: the btree budget is bytes, and one non-ASCII
        # character costs up to four of them (a key of 700 emoji is well under any
        # len()-based cap and well over the index limit).
        pk_text_bytes = len(self.branch_id.encode("utf-8")) + len(self.key.encode("utf-8"))
        if pk_text_bytes > MAX_BLACKBOARD_KEY_BYTES:
            raise ValueError(
                f"BlackboardProposal.branch_id + key is {pk_text_bytes} UTF-8 bytes, over the "
                f"{MAX_BLACKBOARD_KEY_BYTES}-byte budget for blackboard_entry's primary-key "
                "index (see MAX_BLACKBOARD_KEY_BYTES)"
            )
        _guard_construction_site()

    @classmethod
    def create(
        cls,
        scope: ProjectScope,
        run_id: RunId,
        branch_id: str,
        key: str,
        value: object,
    ) -> BlackboardProposal:
        """The ONE legal way to build a commit-able proposal. `author_agent` is read off
        `scope.principal_id` — an authenticated, server-derived identity (see
        `domain.scope.ProjectScope`'s own docstring: constructed in exactly two places,
        neither of which is a request body) — and there is no parameter here through
        which a caller could supply a different one. `project_id` likewise comes from
        `scope`, not from the caller, so a proposal is always scoped to the project the
        caller is actually authenticated into.
        """
        return cls(
            project_id=scope.project_id,
            run_id=run_id,
            branch_id=branch_id,
            author_agent=scope.principal_id,
            key=key,
            value_ref=compute_value_ref(value),
        )


def _guard_construction_site() -> None:
    """Reject `BlackboardProposal(...)` construction from anywhere but its own
    `.create()` classmethod.

    Unlike `domain.scan.ScanVerdict` (whose guard requires the caller to be a module
    OTHER than the one defining the guard, because the legitimate factory lives in
    `core.scans` while the guard lives in `domain.scan`), the legitimate factory here
    (`BlackboardProposal.create`) is defined in THIS SAME module. A module-identity
    check ("caller's `__name__` is not this module") would therefore reject `.create()`
    itself, since `.create()`'s own frame also reports this module's name. The
    discriminator that actually works is *which function*, not *which module*: walk
    outward past this helper's own frame and the dataclass-generated `__init__`'s frame,
    then require the resulting call site's compiled qualified name (`co_qualname`,
    stable since Python 3.11) to be exactly `"BlackboardProposal.create"`. Every other
    caller — test code reaching for the dataclass constructor directly, a route handler,
    a future refactor that inlines field values — raises `TypeError` instead of
    receiving a proposal with an attacker-chosen `author_agent`.

    Scope of the claim (see the module docstring): this stops the *ordinary* ways a field
    gets chosen, not a determined one. `copy.copy` rebuilds a slots dataclass without
    calling `__init__` at all, and `object.__setattr__` writes through `frozen=True`;
    both are demonstrated in `tests/phase4/test_blackboard.py`. Neither buys anything,
    because `BlackboardRepo.commit` independently rejects any proposal whose
    `author_agent` is not the authenticated `scope.principal_id` — that check, not this
    guard, is what makes impersonation impossible.
    """
    # frame 0 (implicit, this function itself) -> frame 1 is this function's caller,
    # i.e. __post_init__ -> frame 2 is __post_init__'s caller, i.e. the dataclass
    # -generated __init__ -> frame 3 is __init__'s caller, i.e. the actual instantiation
    # call site (`cls(...)` inside `.create()`, or anywhere else `BlackboardProposal(...)`
    # is written).
    try:
        caller = sys._getframe(3)
    except ValueError:
        # Stack shallower than the four frames above: whatever that call site is, it is
        # provably not `.create()` reached through them. Fall through to the same typed
        # rejection rather than letting a bare "call stack is not deep enough" escape.
        caller = None
    qualname = (
        getattr(caller.f_code, "co_qualname", caller.f_code.co_name) if caller is not None else ""
    )
    if (
        caller is None
        or caller.f_globals.get("__name__") != __name__
        or qualname != _CREATE_QUALNAME
    ):
        raise TypeError(
            "BlackboardProposal may only be constructed via BlackboardProposal.create() "
            "-- author_agent must be server-derived from ProjectScope, never supplied "
            "directly (PLAN.md §7: 'an agent that can name itself can impersonate "
            "another agent inside the same run')"
        )


@dataclass(frozen=True, slots=True)
class BlackboardEntryRow:
    """A `blackboard_entry` row as stored (contract-style row shape, matching
    `stores.pg.rows`'s convention even though this table's repo lives in a separate
    module owned by this same chunk). `value_ref` is the durable, content-addressed
    pointer `blackboard_entry.value_ref` holds; the byte content it addresses is not a
    column this table has (migrations/0002_partitioned.sql declares `value_ref text`
    only) and resolving it durably is out of this chunk's scope — see
    `stores.pg.blackboard`'s module docstring for the recorded contract_gap.
    """

    project_id: ProjectId
    run_id: RunId
    branch_id: str
    author_agent: PrincipalId
    key: str
    value_ref: str
    status: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class BlackboardCommitResult:
    """What `stores.pg.blackboard.BlackboardRepo.commit` returns on success (either
    outcome). `outcome="converged"` still reports the ORIGINAL committer's
    `author_agent`/`created_at` — a converging caller's own identity is never recorded,
    because no row is written for it; the key stays owned by whoever committed first.
    """

    outcome: CommitOutcome
    project_id: ProjectId
    run_id: RunId
    branch_id: str
    key: str
    value_ref: str
    author_agent: PrincipalId
    created_at: datetime


def resolve_after_conflict(
    proposal: BlackboardProposal, existing: BlackboardEntryRow
) -> BlackboardCommitResult:
    """Pure decision for the case where an INSERT lost the unique-constraint race.
    `existing` is whatever the database (or, offline, a fixture standing in for one)
    returned for `(project_id, run_id, branch_id, key)` immediately after the failed
    insert — a row that, by this table's own design, is never mutated or deleted once
    written (see `stores.pg.blackboard`'s module docstring), so there is no later point
    at which this decision could become stale.

    Content addressing means identical logical values converge (`outcome="converged"`);
    anything else is a genuine conflict, surfaced as `BlackboardKeyConflict` naming the
    winner so the loser can decide what to do next (pick a different key, read the
    winner's value, escalate) — this function never decides that for them.

    `existing` is checked to BE the row for this proposal's key rather than assumed to
    be. Trusting the caller here is what would turn a single wrong predicate in the
    repository's read-back `WHERE` clause (a dropped `branch_id`, a stale `run_id`) into
    a silent cross-key convergence: this function would report `"converged"` — telling a
    caller its value is the committed one — on the strength of some *other* key's
    identical content. A mismatch is a repository bug, not a caller-facing conflict, so
    it raises `ValueError` and never `BlackboardKeyConflict`.
    """
    proposal_pk = (proposal.project_id, proposal.run_id, proposal.branch_id, proposal.key)
    existing_pk = (existing.project_id, existing.run_id, existing.branch_id, existing.key)
    if proposal_pk != existing_pk:
        raise ValueError(
            "resolve_after_conflict: the row read back is not this proposal's key "
            f"(proposal={proposal_pk!r}, row={existing_pk!r})"
        )
    if existing.value_ref == proposal.value_ref:
        return BlackboardCommitResult(
            outcome="converged",
            project_id=existing.project_id,
            run_id=existing.run_id,
            branch_id=existing.branch_id,
            key=existing.key,
            value_ref=existing.value_ref,
            author_agent=existing.author_agent,
            created_at=existing.created_at,
        )
    raise BlackboardKeyConflict(
        key=proposal.key,
        branch_id=proposal.branch_id,
        winning_value_ref=existing.value_ref,
        winning_author=str(existing.author_agent),
    )
