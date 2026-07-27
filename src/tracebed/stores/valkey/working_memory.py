"""Per-run scratch state (PLAN.md §5 key spec, §6 `session.*`).

SYNCHRONOUS BY DESIGN — the named exception to invariant 5 (PLAN.md §2:
"Named synchronous exceptions: working-memory reads/writes and blackboard
commits (they are run-state, not learning writes)."). Trace, outcome, and
derived-memory writes are LEARNING writes and must go through the async
work queue so a slow store never blocks an agent's run; working memory is
run STATE — an agent reading back a scratch note it wrote a moment earlier
in the same run cannot wait on a queue round-trip, and there is no
background worker that will ever reconcile a working-memory row the way the
distiller reconciles a trace. Do not "fix" this into `WorkQueue` — that
would reintroduce, for a code path invariant 5 explicitly carves out, the
exact latency invariant 2's degradation ladder exists to budget against.

`session.offload_threshold_tokens` (default 20,000): scratch state at or
under this size is written straight to Valkey; above it, growing Valkey
unboundedly is the wrong trade, so the value spills to `TraceStorePort` and
Valkey holds only a small pointer envelope. Token counting is deliberately
the CALLER's job — this module has no tokenizer, and estimating one here
would make the offload decision depend on a heuristic this module invented
rather than on the caller's own accounting. `set()` therefore takes an
explicit `token_count`, which is also what makes the threshold boundary
exactly reproducible in a test: no tokenizer's particular output to match,
just an integer compared against a config field.

That choice has a consequence worth stating plainly rather than leaving
implied: `offload_threshold_tokens` is a CAPACITY POLICY, not a memory-safety
guard. The comparison is against a number the caller supplies, not against
`len(value)`, so it bounds Valkey's growth exactly as far as callers are
honest about their own accounting; a caller that reports `token_count=0` for
a megabyte of bytes writes a megabyte inline. Closing that would need a
byte-denominated ceiling, and `domain/config.py`'s `session.*` section has
only `idle_ttl_min` and `offload_threshold_tokens` — no such field exists,
and inventing a literal bytes-per-token factor here is precisely the magic
number hard rule 4 forbids. Reported as a contract gap; not papered over
with a number this module made up.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Final

from tracebed.domain.config import SessionConfig
from tracebed.domain.ids import ProjectId, RunId
from tracebed.stores.tracestore import PayloadRef, TraceStorePort
from tracebed.stores.valkey.client import ValkeyClient
from tracebed.stores.valkey.keys import working_memory_key

__all__ = ["WorkingMemory", "WorkingMemoryEntry"]

# Envelope discriminator: every value this module ever writes to Valkey is
# prefixed with exactly one of these two bytes, so `get()` can tell "this IS
# the value" from "this is a pointer to the value" without a second Valkey
# round-trip or a schema negotiation. Neither byte is a valid start of the
# other envelope kind by construction (there are only two).
_INLINE: Final[bytes] = b"\x00"
_SPILLED: Final[bytes] = b"\x01"

# `ingest.trace_writer.MAX_TRACE_SEQ` / `api.models.MAX_SEQ` (C-33): the
# highest `first_seq` a REAL trace-event object for a run will ever be
# stored under. Mirrored, not imported — `stores.valkey` must not depend on
# `ingest` (a store must not depend on an ingest consumer), and C-33 already
# established the "mirror the ceiling, don't import it" pattern for exactly
# this pair of numbers. A working-memory spill's `first_seq` is placed
# strictly above this ceiling (see `_spill_first_seq`) so it can never
# collide with the run's own trace payload objects in the same
# `TraceStorePort` namespace.
_TRACE_SEQ_CEILING: Final[int] = 1_000_000


def _spill_first_seq(key: str) -> int:
    """The `first_seq` a working-memory spill for `key` is stored under.

    Two properties this must have, neither of which a shared counter could
    give this module (it has no counter that stays consistent across
    processes or restarts, and inventing a Valkey-backed one would be key
    construction this module doesn't own):

    1. The SAME `key` always resolves to the SAME `first_seq`, so a later
       `set()` overwrite of one working-memory key overwrites its own prior
       spill object rather than leaking an orphaned blob under a fresh path
       every time.
    2. Two DIFFERENT keys in the same run resolve to different `first_seq`
       values with overwhelming probability, and to values that can never
       collide with a real trace-event object for that run (see
       `_TRACE_SEQ_CEILING`) — a working-memory spill must never silently
       overwrite live trace-event ciphertext in the same object namespace.

    `sha256(key)` gives both: deterministic per key, and a birthday bound
    (~1 in 2**32) that any realistic number of scratch keys held by one run
    — a handful, not billions — comfortably clears.
    """
    digest = hashlib.sha256(key.encode("utf-8")).digest()
    offset = int.from_bytes(digest[:4], "big")
    return _TRACE_SEQ_CEILING + 1 + offset


def _idle_ttl_seconds(cfg: SessionConfig) -> int:
    return cfg.idle_ttl_min * 60


@dataclass(frozen=True, slots=True)
class WorkingMemoryEntry:
    """What `WorkingMemory.get` returns: the bytes `set()` was given, plus
    whether they were reassembled from a trace-store spill — a caller doing
    its own capacity accounting may care which path a read took even though
    the content is identical either way."""

    value: bytes
    spilled: bool


class WorkingMemory:
    """Per-run scratch state over Valkey, offloading to `TraceStorePort`
    above `session.offload_threshold_tokens`.

    Every method here is a direct, synchronous store round-trip — see the
    module docstring for why that is the correct, invariant-5-exempt shape
    for this class and no other.

    Known limitation, not fixed here: `TraceStorePort` has no per-object
    delete, so `delete()` below removes the Valkey pointer but a spilled
    blob it pointed at is only reclaimed when the whole project is deleted
    (`TraceStorePort.delete_project`). Bounded (one object per distinct
    working-memory key a run ever spills), not unbounded, but not immediate.
    """

    def __init__(self, client: ValkeyClient, store: TraceStorePort, cfg: SessionConfig) -> None:
        self._client = client
        self._store = store
        self._cfg = cfg

    def set(
        self,
        project_id: ProjectId,
        run_id: RunId,
        key: str,
        value: bytes,
        *,
        token_count: int,
    ) -> None:
        """Writes `value` under `key`, expiring after `session.idle_ttl_min`.

        `token_count` is the caller's own estimate of `value`'s size in
        tokens (module docstring — this class has no tokenizer). At or
        below `session.offload_threshold_tokens`, `value` is written to
        Valkey inline. Strictly above it, `value` is put through
        `TraceStorePort` and only the resulting pointer occupies the Valkey
        key, so one oversized scratch write costs Valkey a few dozen bytes,
        not the payload itself.
        """
        if token_count < 0:
            raise ValueError("token_count must not be negative")
        # Validate `key` BEFORE spending a trace-store write on it. `keys.py`
        # is the only validator of `key` (type, length cap, separator
        # freedom) and it runs inside `working_memory_set` — i.e. AFTER the
        # spill below. A rejected key would therefore leave behind exactly
        # the object this class's docstring admits nothing can reclaim short
        # of deleting the whole project: caller-triggered, unreclaimable
        # growth in the trace store on an input the store layer was always
        # going to refuse. Check first, work second.
        working_memory_key(project_id, run_id, key)
        ttl_seconds = _idle_ttl_seconds(self._cfg)
        if token_count > self._cfg.offload_threshold_tokens:
            ref = self._store.put(project_id, run_id, _spill_first_seq(key), value)
            envelope = _SPILLED + str(ref).encode("utf-8")
        else:
            envelope = _INLINE + value
        self._client.working_memory_set(project_id, run_id, key, envelope, ttl_seconds=ttl_seconds)

    def get(self, project_id: ProjectId, run_id: RunId, key: str) -> WorkingMemoryEntry | None:
        """Reads `key` back, transparently resolving a spilled pointer
        through `TraceStorePort` — a caller never needs to know which path a
        given `set()` took; it gets back exactly the bytes that were given,
        either way."""
        raw = self._client.working_memory_get(project_id, run_id, key)
        if raw is None:
            return None
        return self._decode(project_id, raw)

    def delete(self, project_id: ProjectId, run_id: RunId, key: str) -> None:
        """Removes the Valkey pointer for `key` (see the class docstring's
        note on spilled-blob reclamation)."""
        self._client.working_memory_delete(project_id, run_id, key)

    def _decode(self, project_id: ProjectId, raw: bytes) -> WorkingMemoryEntry:
        marker, body = raw[:1], raw[1:]
        if marker == _INLINE:
            return WorkingMemoryEntry(value=body, spilled=False)
        if marker == _SPILLED:
            ref = PayloadRef.parse(body.decode("utf-8"))
            return WorkingMemoryEntry(value=self._store.get(project_id, ref), spilled=True)
        raise ValueError(f"working memory entry has an unrecognised envelope marker {marker!r}")
