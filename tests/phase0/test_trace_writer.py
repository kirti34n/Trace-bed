"""TraceWriter proving tests (PHASE0-CONTRACT.md §13.2, PHASE-0 Task 14).

Offline throughout: fakes stand in for `QueueConsumerPort`, `TraceRepoPort`,
`TraceStorePort`, and `SubjectKeyStore` (the last via a real `SubjectKeyManager`
wired to an in-memory store + a deterministic master key, matching
`test_crypto_shred.py`'s pattern — §12 requires nothing here touch Postgres).
`test_real_repo_satisfies_the_ports_trace_writer_declares` is what keeps that
from being a test against a fiction: it asserts, without a database, that the
real `Repo`/`ScopedRepo` still expose the call shapes the fakes imitate.

Proves: a fake-runtime run (`run_start` -> 3 tool/state events -> `run_end`)
produces a complete, queryable trace (`trace_index` row + decryptable payload
+ `trace_subject` rows); replaying the exact same events a second time causes
no duplication (no new store object, no changed state, every replayed item
still acked); dropping the sentinel and advancing `FakeClock` past
`2 * session.idle_ttl_min` makes the sweeper mark the run `incomplete`;
`input_signature_hash` is computed identically regardless of the order events
are delivered to `run_once`; and — the security half — that a second principal
cannot take over `trace_index.submitter_principal` (the identity shadow
confirmation counts over, PLAN.md invariant 7), that a payload-chosen
`project_id` cannot redirect a write, that plaintext never reaches the trace
store, and that a client-chosen `seq` cannot size the writer's work.
"""

from __future__ import annotations

import inspect
import json
import os
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Any
from uuid import UUID, uuid4

import pytest

from tracebed.crypto.shred import EncryptedPayload, PlainSection, SubjectKeyManager
from tracebed.domain.clock import Clock, FakeClock
from tracebed.domain.config import TracebedSettings
from tracebed.domain.enums import Arm, InstrumentationSource, TraceOutcomeStatus
from tracebed.domain.errors import NotFound
from tracebed.domain.ids import AgentTypeId, PrincipalId, ProjectId, RunId, uuid7
from tracebed.domain.signatures import ABSENT_SIGNATURE, input_signature_hash
from tracebed.ingest.trace_writer import (
    MAX_TRACE_SEQ,
    PATH_PAYLOAD_REFS,
    PATH_SEQ_RANGES,
    TraceWriter,
)
from tracebed.stores.pg.queue import TOPIC_TRACE_EVENT, QueueItem
from tracebed.stores.pg.rows import SubjectKeyRow, TraceIndexRow, TraceIndexUpsert
from tracebed.stores.tracestore import PayloadRef

pytestmark = pytest.mark.phase0

# --------------------------------------------------------------------------- #
# Fakes — duplication across chunks' test modules is accepted by contract
# §13.1 ("a shared fakes module would be a merge collision").
# --------------------------------------------------------------------------- #


@dataclass
class _QueueRow:
    id: int
    topic: str
    project_id: ProjectId
    payload: dict[str, object]
    attempts: int = 0


class FakeQueue:
    """Minimal `QueueConsumerPort` + a test-only `enqueue` helper.

    `claim()` returns rows in insertion order (a plain dict preserves it) —
    deliberately NOT sorted by any event field, so a test can enqueue events
    out of seq order and prove `TraceWriter` sorts internally rather than
    relying on delivery order. `enqueue` takes the row's `project_id`
    separately from the payload so a test can construct the one shape the
    real producer never emits: a queue row whose column and whose envelope
    disagree.
    """

    def __init__(self) -> None:
        self._rows: dict[int, _QueueRow] = {}
        self._next_id = 1
        self.acked: list[int] = []
        self.nacked: list[tuple[int, timedelta]] = []

    def enqueue(
        self, topic: str, payload: Mapping[str, object], *, project_id: ProjectId | None = None
    ) -> int:
        row_id = self._next_id
        self._next_id += 1
        scoped = (
            project_id
            if project_id is not None
            else ProjectId(UUID(str(payload["project_id"])))
        )
        self._rows[row_id] = _QueueRow(
            id=row_id, topic=topic, project_id=scoped, payload=dict(payload)
        )
        return row_id

    def claim(self, topic: str, n: int) -> list[QueueItem]:
        claimed: list[QueueItem] = []
        for row in list(self._rows.values()):
            if row.topic != topic:
                continue
            if len(claimed) >= n:
                break
            row.attempts += 1
            claimed.append(
                QueueItem(
                    id=row.id,
                    topic=row.topic,
                    project_id=row.project_id,
                    payload=MappingProxyType(dict(row.payload)),
                    priority=100,
                    attempts=row.attempts,
                )
            )
        return claimed

    def ack(self, item_id: int) -> None:
        self._rows.pop(item_id, None)
        self.acked.append(item_id)

    def nack(self, item_id: int, backoff: timedelta) -> None:
        self.nacked.append((item_id, backoff))


class FakeTraceStore:
    """`TraceStorePort` — an in-memory object dict keyed by `PayloadRef.key`."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.put_calls: list[PayloadRef] = []

    def put(
        self, project_id: ProjectId, run_id: RunId, first_seq: int, payload: bytes
    ) -> PayloadRef:
        ref = PayloadRef(driver="fs", key=f"{project_id}/{run_id}/{first_seq:08d}.tbz")
        self.objects[ref.key] = payload
        self.put_calls.append(ref)
        return ref

    def get(self, project_id: ProjectId, ref: PayloadRef) -> bytes:
        if not ref.key.startswith(f"{project_id}/"):
            raise NotFound("trace payload not found")
        try:
            return self.objects[ref.key]
        except KeyError:
            raise NotFound("trace payload not found") from None

    def exists(self, project_id: ProjectId, ref: PayloadRef) -> bool:
        return ref.key in self.objects

    def delete_project(self, project_id: ProjectId) -> int:
        keys = [k for k in self.objects if k.startswith(f"{project_id}/")]
        for k in keys:
            del self.objects[k]
        return len(keys)


class FakeSubjectKeyStore:
    """`SubjectKeyStore` — in-memory stand-in for `Repo`'s subject-key table.

    Stores the REAL `SubjectKeyRow` (contract §5.2), not a look-alike: a fake
    that returns its own row type would keep passing if the shape the crypto
    layer reads ever changed.
    """

    def __init__(self, clock: Clock) -> None:
        self._clock = clock
        self._rows: dict[tuple[ProjectId, str], SubjectKeyRow] = {}

    def get_subject_key(self, project_id: ProjectId, subject_tag: str) -> SubjectKeyRow | None:
        return self._rows.get((project_id, subject_tag))

    def insert_subject_key(
        self, project_id: ProjectId, subject_tag: str, key_id: UUID, wrapped_kek: bytes
    ) -> None:
        self._rows[(project_id, subject_tag)] = SubjectKeyRow(
            subject_tag=subject_tag,
            key_id=key_id,
            wrapped_kek=wrapped_kek,
            created_at=self._clock.now(),
            destroyed_at=None,
        )

    def destroy_subject_key(self, project_id: ProjectId, subject_tag: str) -> bool:
        row = self._rows.get((project_id, subject_tag))
        if row is None:
            return False
        self._rows[(project_id, subject_tag)] = replace(
            row, wrapped_kek=b"", destroyed_at=self._clock.now()
        )
        return True


class FakeMasterKeyProvider:
    """Deterministic in-memory master key — no env var, no I/O."""

    def __init__(self, key: bytes | None = None) -> None:
        self._key = key if key is not None else os.urandom(32)

    def master_key(self) -> bytes:
        return self._key


class FakeTraceRepo:
    """`TraceRepoPort` — mirrors `Repo`'s `trace_index` upsert semantics
    (COALESCE / sticky-holdout / sticky-non-pending, `_TRACE_INDEX_UPSERT_SQL`)
    in plain Python so this fake is a faithful stand-in, not just a permissive
    one. In particular `submitter_principal` is written unconditionally from
    the incoming row, exactly as the real SQL does — which is why the writer,
    not the repo, has to be the thing that keeps a run's owner stable."""

    def __init__(self) -> None:
        self.trace_index: dict[tuple[ProjectId, RunId], TraceIndexRow] = {}
        self.trace_subjects: dict[tuple[ProjectId, RunId], set[str]] = {}
        self.projects: list[ProjectId] = []
        self.get_trace_index_for_update_flags: list[bool] = []
        """Every `for_update` value `_FakeScopedTraceRepo.get_trace_index` was called with —
        C-32's lock is invisible from the resulting rows, so the only way to assert the writer
        takes it is to observe the call."""

    def list_project_ids(self) -> list[ProjectId]:
        return list(self.projects)

    def find_runs_missing_sentinel(
        self, project_id: ProjectId, older_than: datetime
    ) -> list[RunId]:
        out: list[RunId] = []
        for (pid, rid), row in self.trace_index.items():
            if pid != project_id or row.outcome_status != TraceOutcomeStatus.PENDING:
                continue
            started = row.started_at or datetime(1970, 1, 1, tzinfo=UTC)
            if started < older_than:
                out.append(rid)
        return out

    def mark_run_incomplete(self, project_id: ProjectId, run_id: RunId) -> None:
        key = (project_id, run_id)
        row = self.trace_index.get(key)
        if row is not None and row.outcome_status == TraceOutcomeStatus.PENDING:
            self.trace_index[key] = replace(row, outcome_status=TraceOutcomeStatus.INCOMPLETE)

    @contextmanager
    def tx(self, project_id: ProjectId) -> Iterator[_FakeScopedTraceRepo]:
        yield _FakeScopedTraceRepo(self, project_id)


class _FakeScopedTraceRepo:
    def __init__(self, repo: FakeTraceRepo, project_id: ProjectId) -> None:
        self._repo = repo
        self._project_id = project_id

    def get_trace_index(self, run_id: RunId, *, for_update: bool = False) -> TraceIndexRow:
        # Mirrors `ScopedRepo.get_trace_index`'s real signature including C-32's
        # keyword-only `for_update`; `test_the_writer_takes_the_run_lock` asserts the
        # writer passes True, so this fake must be able to observe it.
        self._repo.get_trace_index_for_update_flags.append(for_update)
        row = self._repo.trace_index.get((self._project_id, run_id))
        if row is None:
            raise NotFound("not found")
        return row

    def upsert_trace_index(self, row: TraceIndexUpsert) -> None:
        key = (self._project_id, row.run_id)
        existing = self._repo.trace_index.get(key)
        merged = TraceIndexRow(
            project_id=self._project_id,
            run_id=row.run_id,
            agent_type_id=row.agent_type_id,
            workflow_template_id=row.workflow_template_id
            if row.workflow_template_id is not None
            else (existing.workflow_template_id if existing else None),
            submitter_principal=row.submitter_principal,
            input_signature_hash=row.input_signature_hash,
            instrumentation_source=row.instrumentation_source,
            # `TraceIndexUpsert` no longer carries an arm: the real upsert derives
            # `trace_index.arm` from `retrieval_event.arm` server-side (PLAN.md §10). This
            # fake has no retrieval_event table, so it preserves whatever it already had and
            # otherwise reports the same non-holdout default the real COALESCE falls back to.
            arm=existing.arm if existing else Arm.MEMORY_ON,
            path=row.path if row.path is not None else (existing.path if existing else None),
            started_at=(existing.started_at if existing and existing.started_at else row.started_at),
            ended_at=row.ended_at
            if row.ended_at is not None
            else (existing.ended_at if existing else None),
            payload_ref=(existing.payload_ref if existing and existing.payload_ref else row.payload_ref),
            outcome_status=(
                existing.outcome_status
                if row.outcome_status == TraceOutcomeStatus.PENDING and existing is not None
                else row.outcome_status
            ),
        )
        self._repo.trace_index[key] = merged

    def append_trace_subject(self, run_id: RunId, subject_tags: Sequence[str]) -> None:
        self._repo.trace_subjects.setdefault((self._project_id, run_id), set()).update(subject_tags)


# --------------------------------------------------------------------------- #
# Test scaffolding
# --------------------------------------------------------------------------- #


def _event(type_: str, ts: datetime, payload: dict[str, Any] | None = None) -> dict[str, object]:
    return {"type": type_, "ts": ts.isoformat(), "payload": payload or {}}


def _trace_payload(
    *,
    project_id: ProjectId,
    principal_id: PrincipalId,
    agent_type_id: AgentTypeId,
    run_id: RunId,
    seq: int,
    event: dict[str, object],
) -> dict[str, object]:
    return {
        "project_id": str(project_id.value),
        "principal_id": str(principal_id.value),
        "agent_type_id": str(agent_type_id.value),
        "run_id": str(run_id.value),
        "seq": seq,
        "event": event,
    }


@dataclass
class _Harness:
    queue: FakeQueue
    repo: FakeTraceRepo
    store: FakeTraceStore
    keys: SubjectKeyManager
    key_store: FakeSubjectKeyStore
    clock: FakeClock
    settings: TracebedSettings
    writer: TraceWriter


def _harness(settings: TracebedSettings) -> _Harness:
    clock = FakeClock()
    queue = FakeQueue()
    repo = FakeTraceRepo()
    store = FakeTraceStore()
    key_store = FakeSubjectKeyStore(clock)
    keys = SubjectKeyManager(key_store, FakeMasterKeyProvider(), clock)
    writer = TraceWriter(queue, repo, store, keys, clock, settings)
    return _Harness(queue, repo, store, keys, key_store, clock, settings, writer)


def _enqueue_run(
    h: _Harness,
    *,
    project_id: ProjectId,
    principal_id: PrincipalId,
    agent_type_id: AgentTypeId,
    run_id: RunId,
    events: list[tuple[int, dict[str, object]]],
    row_project_id: ProjectId | None = None,
) -> list[int]:
    """Enqueues `(seq, event)` pairs in the given list order (NOT necessarily
    seq order — callers use this to test reordering-stability)."""
    ids = []
    for seq, event in events:
        payload = _trace_payload(
            project_id=project_id,
            principal_id=principal_id,
            agent_type_id=agent_type_id,
            run_id=run_id,
            seq=seq,
            event=event,
        )
        ids.append(h.queue.enqueue(TOPIC_TRACE_EVENT, payload, project_id=row_project_id))
    return ids


def _full_run_events(ts0: datetime, *, status: str = "ok") -> list[tuple[int, dict[str, object]]]:
    return [
        (
            0,
            _event(
                "run_start",
                ts0,
                {"query_text": "how do I reset the pipeline?", "workflow_template": "reset_flow"},
            ),
        ),
        (1, _event("tool_call", ts0 + timedelta(seconds=1), {"tool": "reset"})),
        (
            2,
            _event(
                "state_note",
                ts0 + timedelta(seconds=2),
                {"note": "touched customer record", "subject_tags": ["user:alice"]},
            ),
        ),
        (3, _event("tool_result", ts0 + timedelta(seconds=3), {"ok": True})),
        (4, _event("run_end", ts0 + timedelta(seconds=4), {"status": status})),
    ]


def _stored_seqs(h: _Harness, project_id: ProjectId, ref: PayloadRef) -> set[int]:
    """Decrypt one stored object back to the seqs it carries."""
    payload = EncryptedPayload.from_bytes(h.store.get(project_id, ref))
    seqs: set[int] = set()
    for section in h.keys.decrypt(project_id, payload):
        assert isinstance(section, PlainSection), "a freshly written section must be readable"
        for line in section.lines:
            seqs.add(int(json.loads(line)["seq"]))
    return seqs


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #


def test_full_run_produces_complete_queryable_trace(settings: TracebedSettings) -> None:
    h = _harness(settings)
    project_id = ProjectId(uuid7())
    principal_id = PrincipalId(uuid7())
    agent_type_id = AgentTypeId(uuid7())
    run_id = RunId(uuid7())
    ts0 = h.clock.now()

    item_ids = _enqueue_run(
        h,
        project_id=project_id,
        principal_id=principal_id,
        agent_type_id=agent_type_id,
        run_id=run_id,
        events=_full_run_events(ts0),
    )

    processed = h.writer.run_once()

    assert processed == 5
    assert sorted(h.queue.acked) == sorted(item_ids)
    assert h.queue.nacked == []

    row = h.repo.trace_index[(project_id, run_id)]
    assert row.outcome_status == TraceOutcomeStatus.OK
    assert row.submitter_principal == principal_id
    assert row.agent_type_id == agent_type_id
    assert row.instrumentation_source == InstrumentationSource.SDK
    assert row.arm == Arm.MEMORY_ON
    assert row.started_at == ts0
    assert row.ended_at == ts0 + timedelta(seconds=4)
    assert row.input_signature_hash != ABSENT_SIGNATURE
    assert len(row.input_signature_hash) == 40
    assert row.payload_ref is not None

    # trace_subject: the one state_note's tag landed, and only that one.
    assert h.repo.trace_subjects[(project_id, run_id)] == {"user:alice"}

    # The payload is actually stored and decrypts back to the 5 events.
    assert len(h.store.put_calls) == 1
    assert _stored_seqs(h, project_id, PayloadRef.parse(row.payload_ref)) == {0, 1, 2, 3, 4}


def test_plaintext_never_reaches_the_trace_store(settings: TracebedSettings) -> None:
    """§14 ingest do-not: "encrypt BEFORE put — a plaintext payload never
    reaches TraceStorePort". Asserted on the bytes the store actually
    received, not on the call order."""
    h = _harness(settings)
    project_id = ProjectId(uuid7())
    run_id = RunId(uuid7())
    ts0 = h.clock.now()
    secret = "customer 4f2a said the invoice was wrong"

    _enqueue_run(
        h,
        project_id=project_id,
        principal_id=PrincipalId(uuid7()),
        agent_type_id=AgentTypeId(uuid7()),
        run_id=run_id,
        events=[
            (0, _event("run_start", ts0, {"query_text": secret})),
            (
                1,
                _event(
                    "state_note",
                    ts0 + timedelta(seconds=1),
                    {"note": secret, "subject_tags": ["user:alice"]},
                ),
            ),
        ],
    )
    h.writer.run_once()

    assert h.store.objects, "the batch must have been stored"
    for raw in h.store.objects.values():
        assert secret.encode() not in raw
        assert b"state_note" not in raw
        # It is a well-formed envelope, not just an opaque blob that happens
        # to miss the needle.
        EncryptedPayload.from_bytes(raw)


def test_duplicate_seq_replay_causes_no_duplication(settings: TracebedSettings) -> None:
    h = _harness(settings)
    project_id = ProjectId(uuid7())
    principal_id = PrincipalId(uuid7())
    agent_type_id = AgentTypeId(uuid7())
    run_id = RunId(uuid7())
    ts0 = h.clock.now()
    events = _full_run_events(ts0)

    _enqueue_run(
        h,
        project_id=project_id,
        principal_id=principal_id,
        agent_type_id=agent_type_id,
        run_id=run_id,
        events=events,
    )
    first = h.writer.run_once()
    assert first == 5
    row_after_first = h.repo.trace_index[(project_id, run_id)]
    assert len(h.store.put_calls) == 1

    # Simulate at-least-once redelivery: the exact same (run_id, seq) events
    # land again (a crash-before-ack, or an SDK retry re-posting the batch).
    replay_ids = _enqueue_run(
        h,
        project_id=project_id,
        principal_id=principal_id,
        agent_type_id=agent_type_id,
        run_id=run_id,
        events=events,
    )
    second = h.writer.run_once()

    assert second == 0  # no NEW events
    assert sorted(replay_ids) == sorted(h.queue.acked[-len(replay_ids) :])
    assert h.queue.nacked == []
    # No second object written, no state mutated by the replay.
    assert len(h.store.put_calls) == 1
    assert h.repo.trace_index[(project_id, run_id)] == row_after_first
    assert h.repo.trace_subjects[(project_id, run_id)] == {"user:alice"}


def test_missing_sentinel_swept_to_incomplete_after_2x_idle_ttl(
    settings: TracebedSettings,
) -> None:
    h = _harness(settings)
    project_id = ProjectId(uuid7())
    principal_id = PrincipalId(uuid7())
    agent_type_id = AgentTypeId(uuid7())
    run_id = RunId(uuid7())
    ts0 = h.clock.now()

    # run_start + one tool event, no run_end.
    _enqueue_run(
        h,
        project_id=project_id,
        principal_id=principal_id,
        agent_type_id=agent_type_id,
        run_id=run_id,
        events=[
            (0, _event("run_start", ts0, {"query_text": "q"})),
            (1, _event("tool_call", ts0 + timedelta(seconds=1), {})),
        ],
    )
    h.writer.run_once()
    assert h.repo.trace_index[(project_id, run_id)].outcome_status == TraceOutcomeStatus.PENDING

    h.repo.projects.append(project_id)  # sweeper iterates repo.list_project_ids()

    # Not yet past the threshold: still pending.
    h.clock.advance(minutes=h.settings.session.idle_ttl_min)  # 1x — not enough
    swept = h.writer.sweep_incomplete()
    assert swept == 0
    assert h.repo.trace_index[(project_id, run_id)].outcome_status == TraceOutcomeStatus.PENDING

    # Past 2x idle_ttl_min from the run's started_at: now incomplete.
    h.clock.advance(minutes=h.settings.session.idle_ttl_min + 1)
    swept = h.writer.sweep_incomplete()
    assert swept == 1
    assert h.repo.trace_index[(project_id, run_id)].outcome_status == TraceOutcomeStatus.INCOMPLETE


def test_run_end_with_seq_gap_marks_incomplete_not_ok(settings: TracebedSettings) -> None:
    """The other half of Task 14's completeness guarantee: a sentinel whose
    seq range has a hole must never resolve to 'ok', even though the
    `run_end` payload itself claims status='ok'."""
    h = _harness(settings)
    project_id = ProjectId(uuid7())
    principal_id = PrincipalId(uuid7())
    agent_type_id = AgentTypeId(uuid7())
    run_id = RunId(uuid7())
    ts0 = h.clock.now()

    # seq 2 is missing: 0, 1, then straight to run_end at seq 3.
    _enqueue_run(
        h,
        project_id=project_id,
        principal_id=principal_id,
        agent_type_id=agent_type_id,
        run_id=run_id,
        events=[
            (0, _event("run_start", ts0, {"query_text": "q"})),
            (1, _event("tool_call", ts0 + timedelta(seconds=1), {})),
            (3, _event("run_end", ts0 + timedelta(seconds=3), {"status": "ok"})),
        ],
    )
    h.writer.run_once()

    row = h.repo.trace_index[(project_id, run_id)]
    assert row.outcome_status == TraceOutcomeStatus.INCOMPLETE


def test_late_batch_filling_the_gap_promotes_run_out_of_incomplete(
    settings: TracebedSettings,
) -> None:
    """Batches can arrive out of order (at-least-once, N consumers). A run
    whose sentinel landed before its middle events must NOT stay
    'incomplete' forever once the hole is filled — that permanently hides a
    complete trace from the distiller."""
    h = _harness(settings)
    project_id = ProjectId(uuid7())
    principal_id = PrincipalId(uuid7())
    agent_type_id = AgentTypeId(uuid7())
    run_id = RunId(uuid7())
    ts0 = h.clock.now()

    _enqueue_run(
        h,
        project_id=project_id,
        principal_id=principal_id,
        agent_type_id=agent_type_id,
        run_id=run_id,
        events=[
            (0, _event("run_start", ts0, {"query_text": "q"})),
            (3, _event("run_end", ts0 + timedelta(seconds=3), {"status": "ok"})),
        ],
    )
    h.writer.run_once()
    assert h.repo.trace_index[(project_id, run_id)].outcome_status == TraceOutcomeStatus.INCOMPLETE

    _enqueue_run(
        h,
        project_id=project_id,
        principal_id=principal_id,
        agent_type_id=agent_type_id,
        run_id=run_id,
        events=[
            (1, _event("tool_call", ts0 + timedelta(seconds=1), {})),
            (2, _event("tool_result", ts0 + timedelta(seconds=2), {})),
        ],
    )
    assert h.writer.run_once() == 2

    row = h.repo.trace_index[(project_id, run_id)]
    assert row.outcome_status == TraceOutcomeStatus.OK
    # ended_at was recorded when the sentinel landed and survived the later batch.
    assert row.ended_at == ts0 + timedelta(seconds=3)


def test_input_signature_hash_stable_across_event_reordering(
    settings: TracebedSettings,
) -> None:
    """Two runs enqueue the same logical event set, one in natural seq order
    and one scrambled (delivery order != seq order within the claimed
    batch). Both must compute the identical `input_signature_hash`, and both
    must match calling `domain.signatures.input_signature_hash` directly on
    the same features — proving the writer's own grouping/sorting, not just
    the pure hash function, is order-independent."""
    h = _harness(settings)
    project_id = ProjectId(uuid7())
    principal_id = PrincipalId(uuid7())
    agent_type_id = AgentTypeId(uuid7())
    ts0 = h.clock.now()

    run_start_payload = {
        "query_text": "why did the deploy fail?",
        "workflow_template": "deploy_flow",
        "tool_manifest": ["kubectl", "helm"],
    }
    events = [
        (0, _event("run_start", ts0, dict(run_start_payload))),
        (1, _event("tool_call", ts0 + timedelta(seconds=1), {})),
        (2, _event("tool_result", ts0 + timedelta(seconds=2), {})),
        (3, _event("run_end", ts0 + timedelta(seconds=3), {"status": "ok"})),
    ]

    run_id_natural = RunId(uuid7())
    _enqueue_run(
        h,
        project_id=project_id,
        principal_id=principal_id,
        agent_type_id=agent_type_id,
        run_id=run_id_natural,
        events=events,
    )

    run_id_scrambled = RunId(uuid7())
    scrambled = [events[2], events[0], events[3], events[1]]  # NOT seq order
    _enqueue_run(
        h,
        project_id=project_id,
        principal_id=principal_id,
        agent_type_id=agent_type_id,
        run_id=run_id_scrambled,
        events=scrambled,
    )

    h.writer.run_once()

    sig_natural = h.repo.trace_index[(project_id, run_id_natural)].input_signature_hash
    sig_scrambled = h.repo.trace_index[(project_id, run_id_scrambled)].input_signature_hash

    expected = input_signature_hash(
        agent_type_id=agent_type_id,
        query_text="why did the deploy fail?",
        workflow_template="deploy_flow",
        tool_manifest=["kubectl", "helm"],
    )
    assert sig_natural == expected
    assert sig_scrambled == expected


def test_run_start_seen_in_later_batch_does_not_erase_earlier_signature(
    settings: TracebedSettings,
) -> None:
    """A batch that does NOT contain this run's run_start must resupply the
    already-known `input_signature_hash`/`arm` rather than letting them
    regress to ABSENT_SIGNATURE/default — the upsert's non-COALESCEd
    columns (contract §5.1) make this the writer's responsibility, not the
    repo's."""
    h = _harness(settings)
    project_id = ProjectId(uuid7())
    principal_id = PrincipalId(uuid7())
    agent_type_id = AgentTypeId(uuid7())
    run_id = RunId(uuid7())
    ts0 = h.clock.now()

    _enqueue_run(
        h,
        project_id=project_id,
        principal_id=principal_id,
        agent_type_id=agent_type_id,
        run_id=run_id,
        events=[(0, _event("run_start", ts0, {"query_text": "q1"}))],
    )
    h.writer.run_once()
    sig_after_start = h.repo.trace_index[(project_id, run_id)].input_signature_hash
    assert sig_after_start != ABSENT_SIGNATURE

    _enqueue_run(
        h,
        project_id=project_id,
        principal_id=principal_id,
        agent_type_id=agent_type_id,
        run_id=run_id,
        events=[(1, _event("tool_call", ts0 + timedelta(seconds=1), {}))],
    )
    h.writer.run_once()

    assert h.repo.trace_index[(project_id, run_id)].input_signature_hash == sig_after_start


def test_malformed_item_is_nacked_not_processed(settings: TracebedSettings) -> None:
    h = _harness(settings)
    bad_id = h.queue.enqueue(
        TOPIC_TRACE_EVENT,
        {"project_id": str(uuid4()), "not_a_real_shape": True},
    )
    processed = h.writer.run_once()
    assert processed == 0
    assert h.queue.nacked and h.queue.nacked[0][0] == bad_id
    assert h.queue.acked == []


# --------------------------------------------------------------------------- #
# Adversarial: run ownership, tenancy, and client-chosen numbers
# --------------------------------------------------------------------------- #


def test_second_principal_cannot_take_over_an_existing_run(
    settings: TracebedSettings,
) -> None:
    """`trace_index.submitter_principal` is the identity
    `state_machine.independent_confirmations` counts distinct values of
    (PLAN.md invariant 7 / D-020). `run_id` is client-chosen
    (`api.models.TraceIn.run_id`), so a second principal in the same project
    can address another principal's run. It must not be able to claim it —
    nor to append events to its evidence trail."""
    h = _harness(settings)
    project_id = ProjectId(uuid7())
    owner = PrincipalId(uuid7())
    attacker = PrincipalId(uuid7())
    agent_type_id = AgentTypeId(uuid7())
    attacker_agent_type = AgentTypeId(uuid7())
    run_id = RunId(uuid7())
    ts0 = h.clock.now()

    _enqueue_run(
        h,
        project_id=project_id,
        principal_id=owner,
        agent_type_id=agent_type_id,
        run_id=run_id,
        events=[(0, _event("run_start", ts0, {"query_text": "legitimate run"}))],
    )
    h.writer.run_once()
    row_before = h.repo.trace_index[(project_id, run_id)]
    assert row_before.submitter_principal == owner
    puts_before = len(h.store.put_calls)
    acked_before = list(h.queue.acked)

    forged_ids = _enqueue_run(
        h,
        project_id=project_id,
        principal_id=attacker,
        agent_type_id=attacker_agent_type,
        run_id=run_id,
        events=[
            (1, _event("state_note", ts0 + timedelta(seconds=1), {"note": "planted"})),
            (2, _event("run_end", ts0 + timedelta(seconds=2), {"status": "ok"})),
        ],
    )
    processed = h.writer.run_once()

    assert processed == 0
    row_after = h.repo.trace_index[(project_id, run_id)]
    assert row_after == row_before  # nothing about the run changed
    assert row_after.submitter_principal == owner
    assert row_after.outcome_status == TraceOutcomeStatus.PENDING  # forged sentinel ignored
    assert len(h.store.put_calls) == puts_before  # no forged bytes stored
    assert sorted(i for i, _b in h.queue.nacked) == sorted(forged_ids)
    assert h.queue.acked == acked_before  # the forged items were never acked


def test_lower_seq_from_another_principal_does_not_select_the_owner(
    settings: TracebedSettings,
) -> None:
    """`seq` is client-chosen too. Picking the run's owner off "whichever
    envelope has the lowest seq in this batch" would let an attacker win the
    race by sending seq=0. The `run_start` event decides."""
    h = _harness(settings)
    project_id = ProjectId(uuid7())
    owner = PrincipalId(uuid7())
    attacker = PrincipalId(uuid7())
    agent_type_id = AgentTypeId(uuid7())
    run_id = RunId(uuid7())
    ts0 = h.clock.now()

    forged = _enqueue_run(
        h,
        project_id=project_id,
        principal_id=attacker,
        agent_type_id=AgentTypeId(uuid7()),
        run_id=run_id,
        events=[(0, _event("state_note", ts0, {"note": "i was here first"}))],
    )
    _enqueue_run(
        h,
        project_id=project_id,
        principal_id=owner,
        agent_type_id=agent_type_id,
        run_id=run_id,
        events=[(1, _event("run_start", ts0 + timedelta(seconds=1), {"query_text": "real"}))],
    )

    processed = h.writer.run_once()

    assert processed == 1
    row = h.repo.trace_index[(project_id, run_id)]
    assert row.submitter_principal == owner
    assert row.agent_type_id == agent_type_id
    assert sorted(i for i, _b in h.queue.nacked) == sorted(forged)


def test_same_run_id_in_two_projects_stays_separated(settings: TracebedSettings) -> None:
    """Two tenants using the same `run_id` (it is client-chosen) must produce
    two independent rows — the group key is (project_id, run_id), and the
    store key embeds project_id (invariant 4)."""
    h = _harness(settings)
    project_a = ProjectId(uuid7())
    project_b = ProjectId(uuid7())
    run_id = RunId(uuid7())
    principal_a = PrincipalId(uuid7())
    principal_b = PrincipalId(uuid7())
    ts0 = h.clock.now()

    for project_id, principal_id, text in (
        (project_a, principal_a, "tenant a query"),
        (project_b, principal_b, "tenant b query"),
    ):
        _enqueue_run(
            h,
            project_id=project_id,
            principal_id=principal_id,
            agent_type_id=AgentTypeId(uuid7()),
            run_id=run_id,
            events=[(0, _event("run_start", ts0, {"query_text": text}))],
        )

    assert h.writer.run_once() == 2
    assert h.queue.nacked == []

    row_a = h.repo.trace_index[(project_a, run_id)]
    row_b = h.repo.trace_index[(project_b, run_id)]
    assert row_a.submitter_principal == principal_a
    assert row_b.submitter_principal == principal_b
    assert row_a.input_signature_hash != row_b.input_signature_hash
    # Neither tenant's object is readable under the other's scope.
    ref_a = PayloadRef.parse(str(row_a.payload_ref))
    assert _stored_seqs(h, project_a, ref_a) == {0}
    with pytest.raises(NotFound):
        h.store.get(project_b, ref_a)


def test_envelope_project_id_disagreeing_with_the_queue_row_is_refused(
    settings: TracebedSettings,
) -> None:
    """The queue row's `project_id` column is the scoping authority (§5.3).
    If a payload-carried `project_id` could override it, a single forged
    envelope would choose which tenant's partition the write lands in."""
    h = _harness(settings)
    victim = ProjectId(uuid7())
    attacker_row_project = ProjectId(uuid7())
    run_id = RunId(uuid7())
    ts0 = h.clock.now()

    bad_ids = _enqueue_run(
        h,
        project_id=victim,  # what the envelope claims
        principal_id=PrincipalId(uuid7()),
        agent_type_id=AgentTypeId(uuid7()),
        run_id=run_id,
        events=[(0, _event("run_start", ts0, {"query_text": "q"}))],
        row_project_id=attacker_row_project,  # what the row actually is
    )

    assert h.writer.run_once() == 0
    assert h.repo.trace_index == {}
    assert h.store.objects == {}
    assert sorted(i for i, _b in h.queue.nacked) == sorted(bad_ids)


def test_seq_above_the_cap_is_refused_before_any_work(settings: TracebedSettings) -> None:
    """`seq` is client-chosen and unbounded on the wire. A sentinel seq is
    what the completeness check reasons about, so an unbounded one turns a
    200-byte request into unbounded work in the ingest worker."""
    h = _harness(settings)
    project_id = ProjectId(uuid7())
    ts0 = h.clock.now()

    bad_ids = _enqueue_run(
        h,
        project_id=project_id,
        principal_id=PrincipalId(uuid7()),
        agent_type_id=AgentTypeId(uuid7()),
        run_id=RunId(uuid7()),
        events=[(MAX_TRACE_SEQ + 1, _event("run_end", ts0, {"status": "ok"}))],
    )

    assert h.writer.run_once() == 0
    assert h.store.objects == {}
    assert h.repo.trace_index == {}
    assert sorted(i for i, _b in h.queue.nacked) == sorted(bad_ids)


def test_sentinel_at_the_cap_resolves_without_materialising_the_range(
    settings: TracebedSettings,
) -> None:
    """A legal-but-huge sentinel seq must still be answered from the recorded
    ranges (O(ranges)), never by enumerating every seq below it."""
    h = _harness(settings)
    project_id = ProjectId(uuid7())
    run_id = RunId(uuid7())
    ts0 = h.clock.now()

    _enqueue_run(
        h,
        project_id=project_id,
        principal_id=PrincipalId(uuid7()),
        agent_type_id=AgentTypeId(uuid7()),
        run_id=run_id,
        events=[
            (0, _event("run_start", ts0, {"query_text": "q"})),
            (MAX_TRACE_SEQ, _event("run_end", ts0 + timedelta(seconds=1), {"status": "ok"})),
        ],
    )
    assert h.writer.run_once() == 2

    row = h.repo.trace_index[(project_id, run_id)]
    assert row.outcome_status == TraceOutcomeStatus.INCOMPLETE
    path = row.path or {}
    assert path[PATH_SEQ_RANGES] == [[0, 0], [MAX_TRACE_SEQ, MAX_TRACE_SEQ]]


def test_streaming_batches_keep_the_seq_bookkeeping_compact(
    settings: TracebedSettings,
) -> None:
    """`trace_index.path` is re-read and re-written on every batch, so a
    per-seq list makes a run that streams N single-event batches cost O(N^2)
    jsonb rewrite — driven purely by how a client chooses to batch. A
    contiguous run collapses to one range regardless of N."""
    h = _harness(settings)
    project_id = ProjectId(uuid7())
    principal_id = PrincipalId(uuid7())
    agent_type_id = AgentTypeId(uuid7())
    run_id = RunId(uuid7())
    ts0 = h.clock.now()
    batches = 25

    for seq in range(batches):
        _enqueue_run(
            h,
            project_id=project_id,
            principal_id=principal_id,
            agent_type_id=agent_type_id,
            run_id=run_id,
            events=[
                (
                    seq,
                    _event("run_start", ts0, {"query_text": "q"})
                    if seq == 0
                    else _event("tool_call", ts0 + timedelta(seconds=seq), {}),
                )
            ],
        )
        assert h.writer.run_once() == 1

    path = h.repo.trace_index[(project_id, run_id)].path or {}
    assert path[PATH_SEQ_RANGES] == [[0, batches - 1]]
    # C-25: every put's ref is still reconstructible, and payload_ref keeps the first.
    assert len(path[PATH_PAYLOAD_REFS]) == batches  # type: ignore[arg-type]
    assert str(h.repo.trace_index[(project_id, run_id)].payload_ref) == str(h.store.put_calls[0])


@pytest.mark.parametrize(
    "payload",
    [
        {"query_text": {"nested": "object"}},
        {"query_text": "q", "workflow_template": 17},
        {"query_text": "q", "tool_manifest": "kubectl"},
        {"query_text": "q", "tool_manifest": [1, 2, 3]},
    ],
)
def test_run_start_with_type_confused_signature_inputs_is_refused(
    settings: TracebedSettings, payload: dict[str, Any]
) -> None:
    """`payload` is `dict[str, Any]` on the wire, so `input_signature_hash`'s
    `str`/`Sequence[str]` annotations are a promise the wire cannot keep.
    Coercing (`str(...)`) would mint a real-looking signature out of
    type-confused input — and that hash is half of D-020's independence
    test. Refuse the event instead."""
    h = _harness(settings)
    project_id = ProjectId(uuid7())
    ts0 = h.clock.now()

    bad_ids = _enqueue_run(
        h,
        project_id=project_id,
        principal_id=PrincipalId(uuid7()),
        agent_type_id=AgentTypeId(uuid7()),
        run_id=RunId(uuid7()),
        events=[(0, _event("run_start", ts0, payload))],
    )

    assert h.writer.run_once() == 0
    assert h.repo.trace_index == {}
    assert sorted(i for i, _b in h.queue.nacked) == sorted(bad_ids)


def test_one_bad_run_does_not_block_another_runs_events(settings: TracebedSettings) -> None:
    """Groups are isolated: a run whose write raises must not take the rest of
    the claimed batch down with it."""
    h = _harness(settings)
    project_id = ProjectId(uuid7())
    principal_id = PrincipalId(uuid7())
    agent_type_id = AgentTypeId(uuid7())
    good_run = RunId(uuid7())
    bad_run = RunId(uuid7())
    ts0 = h.clock.now()

    bad_ids = _enqueue_run(
        h,
        project_id=project_id,
        principal_id=principal_id,
        agent_type_id=agent_type_id,
        run_id=bad_run,
        events=[(0, _event("run_start", ts0, {"query_text": "boom"}))],
    )
    good_ids = _enqueue_run(
        h,
        project_id=project_id,
        principal_id=principal_id,
        agent_type_id=agent_type_id,
        run_id=good_run,
        events=[(0, _event("run_start", ts0, {"query_text": "fine"}))],
    )

    real_put = h.store.put

    def exploding_put(
        project: ProjectId, run: RunId, first_seq: int, payload: bytes
    ) -> PayloadRef:
        if run == bad_run:
            raise OSError("trace store unavailable")
        return real_put(project, run, first_seq, payload)

    h.store.put = exploding_put  # type: ignore[method-assign]

    processed = h.writer.run_once()

    assert processed == 1
    assert (project_id, good_run) in h.repo.trace_index
    assert (project_id, bad_run) not in h.repo.trace_index
    assert sorted(h.queue.acked) == sorted(good_ids)
    assert sorted(i for i, _b in h.queue.nacked) == sorted(bad_ids)


def test_real_repo_satisfies_the_ports_trace_writer_declares() -> None:
    """Every other test in this module runs against fakes. This one keeps
    those fakes honest without a database: if `Repo`/`ScopedRepo` ever rename
    a method or a parameter `TraceRepoPort`/`_TraceTx` names, the fakes would
    keep passing and production would break at the first real batch."""
    from tracebed.stores.pg.repo import Repo, ScopedRepo

    self_ = object()
    project_id = ProjectId(uuid7())
    run_id = RunId(uuid7())
    row = TraceIndexUpsert(
        run_id=run_id,
        agent_type_id=AgentTypeId(uuid7()),
        workflow_template_id=None,
        submitter_principal=PrincipalId(uuid7()),
        input_signature_hash=ABSENT_SIGNATURE,
        instrumentation_source=InstrumentationSource.SDK,
        path=None,
        started_at=None,
        ended_at=None,
        payload_ref=None,
        outcome_status=TraceOutcomeStatus.PENDING,
    )

    inspect.signature(Repo.tx).bind(self_, project_id)
    inspect.signature(Repo.list_project_ids).bind(self_)
    inspect.signature(Repo.find_runs_missing_sentinel).bind(
        self_, project_id, older_than=datetime(2026, 1, 1, tzinfo=UTC)
    )
    inspect.signature(Repo.mark_run_incomplete).bind(self_, project_id, run_id)
    # C-32: `for_update` must be keyword-only and must exist on the real method — the writer
    # passes it on every batch, so a `ScopedRepo` that dropped it would `TypeError` on the
    # first real trace while every fake-backed test above stayed green.
    inspect.signature(ScopedRepo.get_trace_index).bind(self_, run_id, for_update=True)
    inspect.signature(ScopedRepo.upsert_trace_index).bind(self_, row)
    inspect.signature(ScopedRepo.append_trace_subject).bind(self_, run_id, ["user:alice"])


def test_the_writer_takes_the_run_lock_before_reading_trace_index(
    settings: TracebedSettings,
) -> None:
    """C-32. `upsert_trace_index` replaces `path` wholesale (a jsonb column cannot be per-key
    merged by ON CONFLICT), so the writer's read-modify-write of `seq_ranges`/`payload_refs`
    is only safe under a lock held for the rest of the transaction. Two workers holding
    different batches of one run would otherwise each read the pre-batch `path` and the last
    commit would win -- dropping the loser's `payload_refs` entry, which is the ONLY pointer
    to that batch's stored ciphertext.

    The lock leaves no trace in the resulting rows, so nothing about the final state can
    prove it was taken; the call itself is the only observable. Asserting `all(...)` rather
    than "at least one" is deliberate -- an unlocked read anywhere in this path reopens the
    race for the batch that took it.
    """
    h = _harness(settings)
    project_id = ProjectId(uuid7())
    run_id = RunId(uuid7())
    principal_id = PrincipalId(uuid7())
    agent_type_id = AgentTypeId(uuid7())
    ts0 = h.clock.now()

    # One event per batch: the streaming shape where the race actually bites.
    for seq, event in _full_run_events(ts0):
        _enqueue_run(
            h,
            project_id=project_id,
            principal_id=principal_id,
            agent_type_id=agent_type_id,
            run_id=run_id,
            events=[(seq, event)],
        )
        h.writer.run_once()

    assert h.repo.get_trace_index_for_update_flags, "the writer never read trace_index at all"
    assert all(h.repo.get_trace_index_for_update_flags)
