"""PHASE-0 Task 3: domain newtypes (`tracebed.domain.ids`, frozen).

`ids.py` is a frozen file this chunk does not own or modify, but Task 3's own
test bullet ("UUIDv7 ids are time-ordered... ProjectId != RunId with the same
UUID... TypedId is immutable") is otherwise unproved anywhere, so these are
read-only proofs against the already-shipped implementation.

NOTE for the merge step: PHASE0-CONTRACT.md §13.2 lists no test file for
`domain/ids.py` at all — this file is additive rather than contract-named. It
collides with no other chunk's assignment; every other test file in this chunk
now carries its §13.2 name (`test_enums_events.py`, `test_canonical.py`,
`test_signatures.py`, `test_scan_verdict_type.py`).
"""

from __future__ import annotations

import itertools
import re
from uuid import UUID

import pytest

from tracebed.domain.ids import (
    AgentTypeId,
    MemoryId,
    PrincipalId,
    ProjectId,
    RunId,
    mint_memory_id,
    mint_run_id,
    uuid7,
    uuid7_timestamp_ms,
)

pytestmark = pytest.mark.phase0

# `uuid7`'s monotonic counter is a single process-global (`_last_ms`/`_counter`
# in ids.py) that never moves backwards — by design, so ids stay time-ordered
# even across a clock step. That means tests sharing this process must hand
# it a strictly-increasing stream of `now_ms` values, or an "earlier" value
# silently gets clamped forward onto the last one used. This counter starts
# far beyond any real wall-clock `time.time_ns()` value for the rest of this
# century, so it never collides with `test_uuid7_is_version_7`'s real-clock mint.
_NEXT_MS = itertools.count(4_000_000_000_000, 1_000_000)


def test_uuid7_is_version_7() -> None:
    value = uuid7()
    assert value.version == 7


def test_uuid7_time_ordered_across_mints_in_same_millisecond() -> None:
    # Force every mint onto the same millisecond so ordering can only come
    # from the rand_a monotonic counter (RFC 9562 §5.7 method 2), not wall time.
    now_ms = next(_NEXT_MS)
    ids = [uuid7(now_ms=now_ms) for _ in range(50)]
    assert ids == sorted(ids), "UUIDv7s minted in one millisecond must sort in mint order"
    assert len(set(ids)) == len(ids), "no duplicate ids within the same millisecond"


def test_uuid7_time_ordered_across_millisecond_boundaries() -> None:
    earlier_ms = next(_NEXT_MS)
    later_ms = earlier_ms + 1
    earlier = uuid7(now_ms=earlier_ms)
    later = uuid7(now_ms=later_ms)
    assert earlier < later


def test_uuid7_timestamp_round_trips() -> None:
    now_ms = next(_NEXT_MS)
    value = uuid7(now_ms=now_ms)
    assert uuid7_timestamp_ms(value) == now_ms


def test_uuid7_timestamp_rejects_non_v7() -> None:
    # A v4 UUID has no embedded millisecond timestamp to extract.
    v4 = UUID("12345678-1234-4234-8234-123456789012")
    with pytest.raises(ValueError, match="not a UUIDv7"):
        uuid7_timestamp_ms(v4)


def test_mint_run_id_and_mint_memory_id_are_uuid7() -> None:
    run_id = mint_run_id()
    memory_id = mint_memory_id()
    assert run_id.value.version == 7
    assert memory_id.value.version == 7


def test_cross_type_equality_is_false_even_for_same_uuid() -> None:
    same = UUID("11111111-1111-1111-1111-111111111111")
    project_id = ProjectId(same)
    run_id = RunId(same)
    assert project_id != run_id
    assert not (project_id == run_id)  # noqa: SIM201 - exercising __eq__ explicitly, not `!=`


def test_cross_type_ids_hash_differently() -> None:
    same = UUID("22222222-2222-2222-2222-222222222222")
    project_id = ProjectId(same)
    run_id = RunId(same)
    principal_id = PrincipalId(same)
    memory_id = MemoryId(same)
    agent_type_id = AgentTypeId(same)
    hashes = {
        hash(project_id),
        hash(run_id),
        hash(principal_id),
        hash(memory_id),
        hash(agent_type_id),
    }
    assert len(hashes) == 5, "same underlying UUID must hash differently per typed-id class"


def test_same_type_same_value_is_equal_and_same_hash() -> None:
    same = UUID("33333333-3333-3333-3333-333333333333")
    a = ProjectId(same)
    b = ProjectId(same)
    assert a == b
    assert hash(a) == hash(b)


def test_typed_id_is_immutable() -> None:
    project_id = ProjectId(uuid7())
    with pytest.raises(AttributeError):
        project_id.value = uuid7()  # type: ignore[misc]
    with pytest.raises(AttributeError):
        del project_id.value  # type: ignore[attr-defined]


def test_typed_id_rejects_wrapping_another_typed_id() -> None:
    project_id = ProjectId(uuid7())
    with pytest.raises(TypeError):
        RunId(project_id)  # type: ignore[arg-type]


def test_typed_id_parses_string_form() -> None:
    raw = "44444444-4444-4444-4444-444444444444"
    project_id = ProjectId.parse(raw)
    assert str(project_id) == raw
    assert re.match(r"^ProjectId\(", repr(project_id))


def test_typed_id_rejects_non_uuid_string() -> None:
    with pytest.raises(ValueError, match="not a UUID"):
        ProjectId("not-a-uuid")
