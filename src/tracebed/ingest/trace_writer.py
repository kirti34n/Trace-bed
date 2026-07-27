"""Trace writer: TOPIC_TRACE_EVENT consumer + completeness sweeper.

PHASE0-CONTRACT.md §11 (PHASE-0 Task 14). One queued item = one trace event
(the `TraceIn`-shaped envelope, contract §9.5). `run_once` claims a batch,
groups by `(project_id, run_id)`, and per run: dedups on `(run_id, seq)`
(delivery is at-least-once, contract §5.3/§14), builds `PlainSection`s along
C-24 boundaries (consecutive events sharing an identical `subject_tags` set),
encrypts through `crypto.shred.SubjectKeyManager` BEFORE anything touches
`TraceStorePort` (§14 do-not: "a plaintext payload never reaches
TraceStorePort"), and upserts `trace_index` + `trace_subject` in one
transaction (`Repo.tx`).

Two attacker-facing facts drive the shape of this module. First, `run_id` and
`seq` are CLIENT-chosen: `api.models.TraceIn` takes both straight off the
request body, and only `project_id`/`principal_id`/`agent_type_id` are
injected server-side from `ProjectScope` (§9.5). Second, `trace_index.
submitter_principal` is what `state_machine.independent_confirmations` counts
distinct principals over (PLAN.md invariant 7 / D-020) — if a second principal
in the same project could post events into another principal's run_id and take
over that column, shadow confirmation would be computed over a forgeable
identity. So the run's owner (`submitter_principal` + `agent_type_id`) is
established once, by the first batch that creates the row, and every later
event whose envelope names a different principal is refused (`_resolve_owner`
/ `_classify`) rather than merged in. That also keeps a second principal from
appending fabricated events into someone else's evidence trail.

Completeness (Task 14's central guarantee): `run_end` is the sentinel.
`outcome_status` starts 'pending'; a `run_end` records `end_seq`/`end_status`
into `trace_index.path`, and from then on EVERY batch re-resolves the status
from the run's cumulative seq set. A run resolves to its reported status only
when every seq below the sentinel has actually been recorded; otherwise it is
'incomplete' — a truncated trace must never look like a clean 'ok' to the
Phase 3 distiller. Because the resolution is recomputed each batch rather than
decided once, a batch that arrives out of order and FILLS the hole promotes
the run back to 'ok'/'error'/'cancelled' instead of leaving it permanently
'incomplete'. `sweep_incomplete` catches the other failure mode — no `run_end`
ever arrives at all — by age, via `Repo.find_runs_missing_sentinel` /
`mark_run_incomplete` (contract §11).

CONTRACT_GAP (repo typing, reported per this chunk's return value): contract
§11 types `TraceWriter.__init__`'s `repo` parameter as the concrete `Repo`.
§12 requires this consumer be testable "with fake queue/repo/store" on a
machine with no Postgres. A concrete class typed parameter cannot be
satisfied by a structurally-compatible fake under mypy --strict (Repo is not
a Protocol and FakeRepo cannot subclass it without a live ConnectionPool), so
this module defines `TraceRepoPort`/`_TraceTx` below: the exact subset of
`Repo`'s public surface this writer calls. The real `Repo` satisfies both
Protocols structurally (asserted offline by
`tests/phase0/test_trace_writer.py::test_real_repo_satisfies_trace_repo_port`)
with zero changes to `stores/pg/repo.py`, which this chunk does not own. This
is the same resolution `crypto/shred.py`'s `SubjectKeyStore` and
`domain/config.py`'s `ConfigStorePort` already use for the identical tension
elsewhere in Phase 0.
"""

from __future__ import annotations

import json
import logging
from bisect import bisect_right
from collections.abc import Iterable, Mapping, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Final, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from tracebed.crypto.shred import PlainSection, SubjectKeyManager
from tracebed.domain.clock import Clock
from tracebed.domain.enums import InstrumentationSource, TraceOutcomeStatus
from tracebed.domain.errors import NotFound
from tracebed.domain.events import (
    RUN_END_STATUSES,
    SUBJECT_TAGS_KEY,
    ArtifactRef,
    RunStart,
    StateNote,
    TraceEvent,
)
from tracebed.domain.ids import AgentTypeId, PrincipalId, ProjectId, RunId
from tracebed.domain.signatures import ABSENT_SIGNATURE, input_signature_hash
from tracebed.stores.pg.queue import TOPIC_TRACE_EVENT, compute_backoff
from tracebed.stores.pg.rows import TraceIndexUpsert
from tracebed.stores.tracestore import TraceStorePort

if TYPE_CHECKING:
    from tracebed.adapters.ports import QueueConsumerPort
    from tracebed.domain.config import TracebedSettings
    from tracebed.stores.pg.queue import QueueItem
    from tracebed.stores.pg.rows import TraceIndexRow

__all__ = ["MAX_TRACE_SEQ", "TraceRepoPort", "TraceWriter"]

logger = logging.getLogger(__name__)

# `seq` is client-chosen and it sizes work on this side of the queue: the completeness
# check has to reason about "every seq below the sentinel". An unbounded
# sentinel seq therefore turns one 200-byte request into an arbitrarily large
# computation in the ingest worker. The count-based check below is O(recorded
# ranges) and never materialises the range, but the bound stays as the second
# line: it also caps `path` bookkeeping and keeps `first_seq` inside the trace
# store's fixed-width key format. The SDK assigns per-run seqs from 0 (C-23);
# a run with more than a million events is a loop, not a run. `api.models.MAX_SEQ` mirrors this
# value so the refusal happens at the wire as a 422 rather than here as a dead letter (C-33);
# the bound stays enforced here too, because a queue row can also arrive from a replay tool.
MAX_TRACE_SEQ: Final = 1_000_000

# Reserved `trace_index.path` keys owned by this module. The repo's upsert
# replaces `path` wholesale (`COALESCE(EXCLUDED.path, trace_index.path)`, it
# does not merge per key), so every batch reads the current value and writes
# the merged one back.
PATH_SEQ_RANGES: Final = "seq_ranges"
PATH_PAYLOAD_REFS: Final = "payload_refs"
PATH_END_SEQ: Final = "end_seq"
PATH_END_STATUS: Final = "end_status"


class _TraceQueueEnvelope(BaseModel):
    """One `TOPIC_TRACE_EVENT` row's payload (contract §9.5). `extra="forbid"`:
    a malformed producer (or a row from some other future topic sharing the
    table) fails validation loudly rather than being partially read."""

    model_config = ConfigDict(extra="forbid")

    project_id: UUID
    principal_id: UUID
    agent_type_id: UUID
    run_id: UUID
    seq: int = Field(ge=0, le=MAX_TRACE_SEQ)
    event: TraceEvent


class _TraceTx(Protocol):
    """The `ScopedRepo` methods this writer calls inside `Repo.tx()` (contract
    §5.0). `ScopedRepo` satisfies this structurally without any changes to
    `stores/pg/repo.py` -- see the module docstring's contract_gap note."""

    def get_trace_index(self, run_id: RunId, *, for_update: bool = False) -> TraceIndexRow:
        """Raises `NotFound` when the run has no row yet.

        This writer ALWAYS passes `for_update=True` (C-32): everything it does to
        `trace_index.path` is a read-modify-write, and `upsert_trace_index` replaces `path`
        wholesale, so without the lock two workers holding different batches of one run
        silently discard each other's `seq_ranges` and `payload_refs`."""
        ...

    def upsert_trace_index(self, row: TraceIndexUpsert) -> None: ...

    def append_trace_subject(self, run_id: RunId, subject_tags: Sequence[str]) -> None: ...


class TraceRepoPort(Protocol):
    """The `Repo` surface `TraceWriter` needs (contract §5.1 method names;
    see the module docstring's contract_gap note on why this is a Protocol
    rather than the concrete `Repo` type contract §11 names)."""

    def tx(self, project_id: ProjectId) -> AbstractContextManager[_TraceTx]: ...

    def list_project_ids(self) -> list[ProjectId]: ...

    def find_runs_missing_sentinel(
        self, project_id: ProjectId, older_than: datetime
    ) -> list[RunId]: ...

    def mark_run_incomplete(self, project_id: ProjectId, run_id: RunId) -> None: ...


@dataclass(frozen=True, slots=True)
class _SeqSet:
    """The set of seqs durably recorded for a run, stored run-length encoded.

    Held as sorted, disjoint, non-adjacent `[lo, hi]` closed ranges rather
    than as one entry per seq. The repo cannot merge `path` per key, so this
    value is re-read and re-written on every batch: an entry-per-seq list
    makes a run that streams N single-event batches cost O(N^2) bytes of jsonb
    rewrite, driven entirely by how a client chooses to batch. A well-behaved
    run collapses to a single range no matter how many events it has, and the
    adversarial worst case (every other seq) is no worse than the per-seq list
    it replaces.
    """

    ranges: tuple[tuple[int, int], ...] = ()

    @classmethod
    def from_path(cls, raw: object) -> _SeqSet:
        """Parse the stored form defensively: this value round-trips through
        jsonb, and a shape this module cannot read must degrade to "nothing
        recorded yet" (which re-writes events, idempotently) rather than raise
        and dead-letter an otherwise healthy run."""
        if not isinstance(raw, list):
            return cls()
        parsed: list[tuple[int, int]] = []
        for entry in raw:
            if not isinstance(entry, list | tuple) or len(entry) != 2:
                continue
            lo, hi = entry[0], entry[1]
            if isinstance(lo, bool) or isinstance(hi, bool):
                continue
            if not isinstance(lo, int) or not isinstance(hi, int):
                continue
            if lo < 0 or hi < lo or hi > MAX_TRACE_SEQ:
                continue
            parsed.append((lo, hi))
        return cls(_merge_ranges(parsed))

    def contains(self, seq: int) -> bool:
        los = [lo for lo, _hi in self.ranges]
        idx = bisect_right(los, seq) - 1
        if idx < 0:
            return False
        return seq <= self.ranges[idx][1]

    def extend(self, seqs: Iterable[int]) -> _SeqSet:
        return _SeqSet(_merge_ranges([*self.ranges, *((s, s) for s in seqs)]))

    def count_upto(self, end: int) -> int:
        """How many recorded seqs are <= `end`. Never materialises `end`
        elements: the sentinel's seq is client-chosen (see `MAX_TRACE_SEQ`)."""
        return sum(min(hi, end) - lo + 1 for lo, hi in self.ranges if lo <= end)

    def to_path(self) -> list[list[int]]:
        return [[lo, hi] for lo, hi in self.ranges]


def _merge_ranges(ranges: Sequence[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    merged: list[tuple[int, int]] = []
    for lo, hi in sorted(ranges):
        if merged and lo <= merged[-1][1] + 1:
            prev_lo, prev_hi = merged[-1]
            merged[-1] = (prev_lo, max(prev_hi, hi))
        else:
            merged.append((lo, hi))
    return tuple(merged)


@dataclass(frozen=True, slots=True)
class _RunOwner:
    """Who a run belongs to. Established once and never re-derived from a
    later batch -- see the module docstring (invariant 7 / D-020)."""

    principal_id: PrincipalId
    agent_type_id: AgentTypeId


@dataclass(frozen=True, slots=True)
class _RunStartFeatures:
    """The C-05 `run_start` payload keys that feed `input_signature_hash`,
    after type validation. `payload` is `dict[str, Any]` on the wire, so the
    static `str`/`Sequence[str]` annotations of `input_signature_hash` are a
    promise the wire cannot keep -- this is where it is made true."""

    query_text: str
    workflow_template: str | None
    tool_manifest: list[str] | None
    started_at: datetime
    # NO `arm`. The `run_start` payload still CARRIES one (the SDK stamps it from the last
    # retrieve() result, C-05) and this writer deliberately does not read it: a caller-relayed
    # arm is a caller-asserted arm, and PLAN.md §10 forbids accepting one. The value the
    # experiment is stratified on is `retrieval_event.arm`, which the server wrote itself.


def _run_start_features(env: _TraceQueueEnvelope) -> _RunStartFeatures:
    """Raises ValueError on a `run_start` this writer refuses to signature.

    Rejecting the single event (nack -> retry -> dead_letter) is deliberate:
    coercing a wrong-typed `query_text`/`workflow_template` with `str()` would
    mint a real-looking `input_signature_hash` out of type-confused input, and
    that hash is half of the shadow-confirmation independence test (§3.8).
    """
    event = env.event
    if not isinstance(event, RunStart):  # pragma: no cover - callers pre-filter
        raise ValueError("not a run_start event")
    payload = event.payload

    query_raw = payload.get("query_text", "")
    if not isinstance(query_raw, str):
        raise ValueError("run_start payload['query_text'] must be a string")

    template_raw = payload.get("workflow_template")
    if template_raw is not None and not isinstance(template_raw, str):
        raise ValueError("run_start payload['workflow_template'] must be a string or null")

    manifest_raw = payload.get("tool_manifest")
    manifest: list[str] | None
    if manifest_raw is None:
        manifest = None
    elif isinstance(manifest_raw, list) and all(isinstance(t, str) for t in manifest_raw):
        manifest = [str(t) for t in manifest_raw]
    else:
        raise ValueError("run_start payload['tool_manifest'] must be a list of strings")

    # `input_signature_hash` has its own bounds (MAX_TOOL_MANIFEST_ENTRIES,
    # per-entry length) and raises ValueError past them; calling it here means
    # a manifest it refuses is rejected as one bad event rather than surfacing
    # mid-write and nacking the whole run's batch.
    input_signature_hash(
        agent_type_id=AgentTypeId(env.agent_type_id),
        query_text=query_raw,
        workflow_template=template_raw,
        tool_manifest=manifest,
    )
    return _RunStartFeatures(
        query_text=query_raw,
        workflow_template=template_raw,
        tool_manifest=manifest,
        started_at=event.ts,
    )


def _subject_tags_for(event: TraceEvent) -> tuple[str, ...]:
    """C-05: only `state_note`/`artifact_ref` payloads carry `subject_tags`,
    and only those two event models validate the key's shape at parse time
    (`domain.events._validated_subject_tags`) -- by the time an event reaches
    here it is already a list of short, non-empty strings, or the key is
    absent. Deduplicated and sorted so two events naming the same tags in a
    different order land in the same C-24 section rather than starting a new
    one over ordering alone."""
    if not isinstance(event, StateNote | ArtifactRef):
        return ()
    raw = event.payload.get(SUBJECT_TAGS_KEY)
    if not isinstance(raw, list):
        return ()
    return tuple(sorted({str(tag) for tag in raw}))


def _build_sections(
    envelopes: Sequence[_TraceQueueEnvelope],
) -> list[PlainSection]:
    """C-24: consecutive events (in seq order) sharing an identical
    `subject_tags` set form one section. `envelopes` must already be sorted
    by `seq` and contain no duplicate seqs -- both are guaranteed by
    `TraceWriter._write_batch` before this is called."""
    sections: list[PlainSection] = []
    current_tags: tuple[str, ...] | None = None
    current_lines: list[bytes] = []
    current_seq_from = 0
    current_seq_to = 0

    for env in envelopes:
        tags = _subject_tags_for(env.event)
        line = _wire_line(env.seq, env.event)
        if current_tags is None:
            current_tags, current_seq_from, current_seq_to, current_lines = (
                tags,
                env.seq,
                env.seq,
                [line],
            )
        elif tags == current_tags:
            current_seq_to = env.seq
            current_lines.append(line)
        else:
            sections.append(
                PlainSection(
                    seq_from=current_seq_from,
                    seq_to=current_seq_to,
                    subject_tags=current_tags,
                    lines=tuple(current_lines),
                )
            )
            current_tags, current_seq_from, current_seq_to, current_lines = (
                tags,
                env.seq,
                env.seq,
                [line],
            )

    if current_tags is not None:
        sections.append(
            PlainSection(
                seq_from=current_seq_from,
                seq_to=current_seq_to,
                subject_tags=current_tags,
                lines=tuple(current_lines),
            )
        )
    return sections


def _wire_line(seq: int, event: TraceEvent) -> bytes:
    """The §6.1 plaintext unit: one `{"seq": n, "event": {...}}` JSON object
    per line, no trailing newline (`SubjectKeyManager.encrypt` appends the
    newlines when it joins a section's lines). `model_dump(mode="json")`
    turns `ts`/UUID fields into JSON-safe strings first, which is what makes
    plain `json.dumps` -- not `canonical_json` -- the right tool here: this
    is stored plaintext, not a hash input, so byte-for-byte determinism
    across independent implementations is not the property that matters."""
    return json.dumps(
        {"seq": seq, "event": event.model_dump(mode="json")},
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _resolve_owner(
    existing: TraceIndexRow | None, envelopes: Sequence[_TraceQueueEnvelope]
) -> _RunOwner:
    """The run's owning principal/agent type.

    First-writer-wins: once `trace_index` has a row, its `submitter_principal`
    IS the owner and no later batch can change it. For a brand-new run the
    owner comes from the `run_start` envelope when one is present (the event
    that actually opens a run), otherwise from the lowest seq in the batch.
    """
    if existing is not None:
        return _RunOwner(existing.submitter_principal, existing.agent_type_id)
    candidates = [e for e in envelopes if e.event.type == "run_start"] or list(envelopes)
    source = min(candidates, key=lambda e: e.seq)
    return _RunOwner(PrincipalId(source.principal_id), AgentTypeId(source.agent_type_id))


class TraceWriter:
    """Consumes `TOPIC_TRACE_EVENT` (contract §11 / PHASE-0 Task 14)."""

    def __init__(
        self,
        queue: QueueConsumerPort,
        repo: TraceRepoPort,
        store: TraceStorePort,
        keys: SubjectKeyManager,
        clock: Clock,
        settings: TracebedSettings,
    ) -> None:
        self._queue = queue
        self._repo = repo
        self._store = store
        self._keys = keys
        self._clock = clock
        self._settings = settings

    def run_once(self, max_batch: int | None = None) -> int:
        """Claim, group, dedup, encrypt, store, upsert. Returns the count of
        genuinely NEW `(run_id, seq)` events durably recorded this call --
        an item whose seq was already reflected in `trace_index` (redelivery
        after a crash between the DB write and `ack`) is still acked, just
        not counted twice.

        Items in a group are `ack`'d on success and `nack`'d (with
        `compute_backoff(item.attempts)`) on any exception processing that
        run -- one run's failure must not block another run's items sitting
        in the same claimed batch. Individually refused items (malformed
        envelope, a `run_start` whose signature inputs are not the type they
        claim, an envelope whose principal is not the run's owner) are nacked
        on their own and travel to `dead_letter` after `queue.max_attempts`,
        which is the audit trail for a refused write.
        """
        n = max_batch if max_batch is not None else self._settings.queue.batch_size
        items = self._queue.claim(TOPIC_TRACE_EVENT, n)
        if not items:
            return 0

        groups: dict[tuple[ProjectId, RunId], list[tuple[_TraceQueueEnvelope, QueueItem]]] = {}
        for item in items:
            env = self._parse_item(item)
            if env is None:
                continue
            # The queue row's own `project_id` column is authoritative: it is
            # what the producer scoped the enqueue with and what a consumer's
            # re-scoping is expected to trust (§5.3). The envelope repeats it,
            # and the two disagreeing means the payload no longer describes
            # the row it rode in on -- refuse rather than pick one, or a
            # payload-derived project_id would decide which tenant's partition
            # this batch lands in (invariant 4).
            if ProjectId(env.project_id) != item.project_id:
                logger.warning(
                    "trace_writer: item %s envelope project_id disagrees with the queue row", item.id
                )
                self._queue.nack(item.id, compute_backoff(item.attempts))
                continue
            key = (item.project_id, RunId(env.run_id))
            groups.setdefault(key, []).append((env, item))

        processed = 0
        for (project_id, run_id), pairs in groups.items():
            try:
                processed += self._process_group(project_id, run_id, pairs)
            except Exception:
                logger.exception("trace_writer: failed processing run %s", run_id)
                for _env, item in pairs:
                    self._queue.nack(item.id, compute_backoff(item.attempts))
        return processed

    def _parse_item(self, item: QueueItem) -> _TraceQueueEnvelope | None:
        """Envelope + per-event validation. `None` means the item was refused
        and already nacked."""
        try:
            env = _TraceQueueEnvelope.model_validate(dict(item.payload))
        except ValidationError:
            logger.warning("trace_writer: refusing malformed trace_event item %s", item.id)
            self._queue.nack(item.id, compute_backoff(item.attempts))
            return None
        if env.event.type == "run_start":
            try:
                _run_start_features(env)
            except ValueError as exc:
                logger.warning("trace_writer: refusing run_start item %s: %s", item.id, exc)
                self._queue.nack(item.id, compute_backoff(item.attempts))
                return None
        return env

    def _process_group(
        self,
        project_id: ProjectId,
        run_id: RunId,
        pairs: Sequence[tuple[_TraceQueueEnvelope, QueueItem]],
    ) -> int:
        """One run's slice of one claimed batch. Returns the number of new
        (non-duplicate) events written."""
        accepted: list[tuple[_TraceQueueEnvelope, QueueItem]] = []
        refused: list[tuple[_TraceQueueEnvelope, QueueItem]] = []
        new_count = 0

        with self._repo.tx(project_id) as tx:
            try:
                existing: TraceIndexRow | None = tx.get_trace_index(run_id, for_update=True)
            except NotFound:
                existing = None

            owner = _resolve_owner(existing, [env for env, _item in pairs])
            for env, item in pairs:
                if (
                    PrincipalId(env.principal_id) == owner.principal_id
                    and AgentTypeId(env.agent_type_id) == owner.agent_type_id
                ):
                    accepted.append((env, item))
                else:
                    refused.append((env, item))

            if accepted:
                new_count = self._write_batch(
                    project_id=project_id,
                    run_id=run_id,
                    owner=owner,
                    existing=existing,
                    envs=[env for env, _item in accepted],
                    tx=tx,
                )

        for _env, item in accepted:
            self._queue.ack(item.id)
        for env, item in refused:
            # Not "an event arrived late": another principal (or another agent
            # type under the same principal) tried to write into this run.
            # trace_index.submitter_principal is the identity shadow
            # confirmation counts over -- refuse loudly, dead-letter, keep the
            # run's owner as recorded.
            logger.warning(
                "trace_writer: refusing event for run %s from non-owning principal %s",
                run_id,
                env.principal_id,
            )
            self._queue.nack(item.id, compute_backoff(item.attempts))
        return new_count

    def _write_batch(
        self,
        *,
        project_id: ProjectId,
        run_id: RunId,
        owner: _RunOwner,
        existing: TraceIndexRow | None,
        envs: Sequence[_TraceQueueEnvelope],
        tx: _TraceTx,
    ) -> int:
        # Drop exact (run_id, seq) duplicates delivered twice inside this one
        # claimed batch (e.g. a client retry that re-posted the same batch);
        # first occurrence wins, and every accepted item -- kept or dropped --
        # is still acked by the caller.
        by_seq: dict[int, _TraceQueueEnvelope] = {}
        for env in envs:
            by_seq.setdefault(env.seq, env)

        existing_path: Mapping[str, object] = (
            dict(existing.path) if existing is not None and existing.path else {}
        )
        seen = _SeqSet.from_path(existing_path.get(PATH_SEQ_RANGES))
        new_envs = [env for _seq, env in sorted(by_seq.items()) if not seen.contains(env.seq)]
        if not new_envs:
            return 0

        all_tags: set[str] = set()
        for env in new_envs:
            all_tags.update(_subject_tags_for(env.event))

        # §14 do-not: encryption happens BEFORE the store sees anything.
        sections = _build_sections(new_envs)
        encrypted = self._keys.encrypt(project_id, run_id, sections)
        ref = self._store.put(project_id, run_id, new_envs[0].seq, encrypted.to_bytes())

        merged = seen.extend(env.seq for env in new_envs)
        prior_refs_raw = existing_path.get(PATH_PAYLOAD_REFS)
        prior_refs = (
            [str(r) for r in prior_refs_raw] if isinstance(prior_refs_raw, list) else []
        )
        merged_path: dict[str, object] = dict(existing_path)
        merged_path[PATH_SEQ_RANGES] = merged.to_path()
        # C-25: `payload_ref` (below) keeps only the FIRST put's ref (via the
        # repo's COALESCE); every put's ref -- first included -- accumulates
        # here so a multi-batch run's full object list stays reconstructible.
        merged_path[PATH_PAYLOAD_REFS] = [*prior_refs, str(ref)]

        sig, started_at = self._identity_columns(
            owner=owner, existing=existing, new_envs=new_envs
        )
        outcome_status, ended_at = self._resolve_completeness(
            existing_path=existing_path, merged_path=merged_path, merged=merged, new_envs=new_envs
        )

        row = TraceIndexUpsert(
            run_id=run_id,
            agent_type_id=owner.agent_type_id,
            # No repo method resolves a `workflow_template` NAME (C-05's
            # payload key, a str) to the `workflow_template_id: UUID | None`
            # this row wants (contract §5.2) -- reported as a contract_gap;
            # left unpopulated rather than fabricated.
            workflow_template_id=None,
            submitter_principal=owner.principal_id,
            input_signature_hash=sig,
            instrumentation_source=InstrumentationSource.SDK,
            # NO `arm`: `TraceIndexUpsert` no longer carries one. See that dataclass and
            # `Repo`'s upsert -- the arm is derived server-side from `retrieval_event.arm`
            # rather than relayed from the caller's `run_start` payload (PLAN.md §10).
            path=merged_path,
            started_at=started_at,
            ended_at=ended_at,
            payload_ref=str(ref),
            outcome_status=outcome_status,
        )
        tx.upsert_trace_index(row)
        if all_tags:
            tx.append_trace_subject(run_id, sorted(all_tags))
        return len(new_envs)

    def _identity_columns(
        self,
        *,
        owner: _RunOwner,
        existing: TraceIndexRow | None,
        new_envs: Sequence[_TraceQueueEnvelope],
    ) -> tuple[bytes, datetime | None]:
        """`input_signature_hash` and `started_at` for this upsert.

        Resupplying `existing.input_signature_hash` when this batch carries no `run_start` is
        still required, but no longer for the reason it originally was. The repo's upsert now
        has a merge rule for that column -- a ONE-WAY sentinel upgrade (D-135): the stored value
        wins unless it is `ABSENT_SIGNATURE`, in which case EXCLUDED replaces it once. That rule
        alone already prevents the regression this resupply used to be the only guard against.
        What the resupply still buys is that the CLAIMED value and the KEPT value agree, which
        is what keeps `Repo.upsert_trace_index`'s identity-conflict warning quiet on the
        ordinary at-least-once path: sending the sentinel against a row that already holds a
        real signature is harmless to the stored data but would otherwise be indistinguishable,
        at the warning, from a genuine second claim.

        `arm` used to be computed here too, out of the caller-supplied `run_start` payload.
        It is not any more, and it is not this writer's to compute: PLAN.md §10 forbids
        accepting an arm assignment from a caller, and `Repo`'s upsert derives it from
        `retrieval_event.arm` instead.
        """
        run_start_env = next((e for e in new_envs if e.event.type == "run_start"), None)
        if run_start_env is None:
            sig = existing.input_signature_hash if existing is not None else ABSENT_SIGNATURE
            return sig, None

        # Validated at claim time (`_parse_item`); re-derived here rather than
        # threaded through so there is exactly one parser for these keys.
        features = _run_start_features(run_start_env)
        sig = input_signature_hash(
            agent_type_id=owner.agent_type_id,
            query_text=features.query_text,
            workflow_template=features.workflow_template,
            tool_manifest=features.tool_manifest,
        )
        return sig, features.started_at

    def _resolve_completeness(
        self,
        *,
        existing_path: Mapping[str, object],
        merged_path: dict[str, object],
        merged: _SeqSet,
        new_envs: Sequence[_TraceQueueEnvelope],
    ) -> tuple[TraceOutcomeStatus, datetime | None]:
        """Task 14's completeness guarantee, recomputed from cumulative state.

        The sentinel's `(seq, status)` is recorded in `path` the first time a
        `run_end` is seen and is never overwritten by a second one -- the run
        ends once. Every later batch re-runs the gap test against the run's
        cumulative seq set, so filling a hole promotes the run out of
        'incomplete', and a hole that is still open keeps it there.
        """
        end_seq = _int_or_none(existing_path.get(PATH_END_SEQ))
        end_status = _end_status_or_none(existing_path.get(PATH_END_STATUS))
        ended_at: datetime | None = None

        if end_seq is None:
            run_end_env = next((e for e in new_envs if e.event.type == "run_end"), None)
            if run_end_env is not None:
                end_seq = run_end_env.seq
                end_status = _end_status_or_none(run_end_env.event.payload.get("status"))
                ended_at = run_end_env.event.ts
                merged_path[PATH_END_SEQ] = end_seq
                if end_status is not None:
                    merged_path[PATH_END_STATUS] = end_status

        if end_seq is None:
            return TraceOutcomeStatus.PENDING, None
        if end_status is None:
            # A sentinel with no usable status is exactly as unreliable as a
            # truncated trace: the distiller must not read it as a clean run.
            return TraceOutcomeStatus.INCOMPLETE, ended_at
        if merged.count_upto(end_seq) != end_seq + 1:
            return TraceOutcomeStatus.INCOMPLETE, ended_at
        return TraceOutcomeStatus(end_status), ended_at

    def sweep_incomplete(self) -> int:
        """Marks runs with no `run_end` sentinel after `2 * session.idle_ttl_min`
        as `incomplete` (contract §11). Gap-at-sentinel detection (the other
        half of Task 14's completeness guarantee) is recomputed on every batch
        in `_resolve_completeness`, so a run that reaches this sweep has never
        had a sentinel at all and there is no seq set to inspect for holes
        here."""
        idle_ttl_min = self._settings.session.idle_ttl_min
        cutoff = self._clock.now() - 2 * timedelta(minutes=idle_ttl_min)
        total = 0
        for project_id in self._repo.list_project_ids():
            for run_id in self._repo.find_runs_missing_sentinel(project_id, older_than=cutoff):
                self._repo.mark_run_incomplete(project_id, run_id)
                total += 1
        return total


def _int_or_none(raw: object) -> int | None:
    if isinstance(raw, bool) or not isinstance(raw, int):
        return None
    if not 0 <= raw <= MAX_TRACE_SEQ:
        return None
    return raw


def _end_status_or_none(raw: object) -> str | None:
    if isinstance(raw, str) and raw in RUN_END_STATUSES:
        return raw
    return None
