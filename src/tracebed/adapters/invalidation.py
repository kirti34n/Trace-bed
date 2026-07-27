"""Shipped `InvalidationPort` defaults (PLAN.md §3 adapters table; PLAN.md §7 Phase 2).

`adapters.ports.InvalidationPort` is exactly `def poll(self) -> Sequence[Mapping[str,
object]]`. Two host-facing defaults satisfy it structurally here, matching PLAN.md §3's
"HTTP webhook receiver + generic polling skeleton (interval-diff a JSON source)":

  - `WebhookInvalidationSource`: an in-memory receive/drain buffer. A host's HTTP route
    (owned by `api/`, outside this chunk's file list) calls `.receive(event_type, selector)`
    for each webhook delivery it accepts; `workers.invalidator.Invalidator` (or whatever
    drains a live `InvalidationPort`) calls `.poll()` on its own cadence to take everything
    that arrived since the last drain. Thread-safe for the single-process case only — a
    multi-process deployment needs a durable queue in front of this, and `stores/pg/queue.py`
    (D-041) explicitly has no fourth topic for invalidation events; reported as a
    contract_gap rather than invented here, since neither file is in this chunk's list.
  - `PollingInvalidationSource`: a generic "interval-diff a JSON source" skeleton. Each
    `.poll()` call fetches the source's current full item list through a host-supplied
    `JsonSourcePort`, diffs it against the snapshot kept from the previous call by a
    host-supplied stable key, and emits one raw payload per added/changed/removed item.
    Nothing here assumes what the source enumerates (tool definitions, workflow templates,
    environment facts) — the host supplies `item_key` and `build_selector` to say what a
    changed item means in `provenance.tool_refs` / `trace_ids` / `input_sig_hashes` terms.

Raw payload shape emitted by both, and consumed by
`workers.invalidator.parse_invalidation_payload`: `{"event_type": str, "selector":
Mapping[str, object]}` — the same two columns `Repo.insert_invalidation_event` persists
(D-041). Neither class here writes to Postgres; persisting the row is `POST
/v1/invalidation`'s job. These are *sources* a poller reads, not writers of
`invalidation_event`.
"""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable, Mapping, Sequence
from typing import Protocol, runtime_checkable

from tracebed.domain.canonical import canonical_json
from tracebed.stores.valkey.flush import CACHE_FLUSH_EVENT_TYPE

__all__ = [
    "CACHE_FLUSH_EVENT_TYPE",
    "JsonSourcePort",
    "PollingInvalidationSource",
    "WebhookInvalidationSource",
]


class WebhookInvalidationSource:
    """Buffers raw webhook deliveries between HTTP receipt and worker drain.

    `receive()` is what a host's webhook route calls per delivery; `poll()` (the
    `InvalidationPort` method) drains and clears everything buffered since the last call.

    DURABILITY: at-MOST-once, and in-memory. The drain and the clear happen under one lock,
    so no event is handed to two concurrent pollers — but an event is gone from this buffer
    the instant it is returned, so a consumer that crashes between `poll()` and acting on
    the result loses it, as does a process restart with events still buffered. A lost
    invalidation is a memory that stays `validated` after the thing it depends on changed,
    which the R-day revalidation sweep is the only backstop for. A deployment that cannot
    accept that needs a durable queue in front of this, which `stores/pg/queue.py` (D-041)
    deliberately does not provide — reported as a contract_gap, not papered over here.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pending: list[dict[str, object]] = []

    def receive(self, event_type: str, selector: Mapping[str, object]) -> None:
        """Called by a host's webhook handler for each delivered event."""
        if not event_type:
            raise ValueError("event_type must be a non-empty string")
        with self._lock:
            self._pending.append({"event_type": event_type, "selector": dict(selector)})

    def poll(self) -> Sequence[Mapping[str, object]]:
        """`InvalidationPort.poll()`: drains and returns everything received so far."""
        with self._lock:
            drained, self._pending = self._pending, []
        return drained


@runtime_checkable
class JsonSourcePort(Protocol):
    """A host-owned enumerable JSON-shaped source (tool registry, workflow templates, ...).

    `fetch()` must raise on failure rather than return a smaller-than-real list —
    `PollingInvalidationSource.poll()` does not catch it, so a broken source surfaces as a
    broken worker tick, never as a silent "nothing changed" diff against a partial read.
    """

    def fetch(self) -> Sequence[Mapping[str, object]]: ...


class PollingInvalidationSource:
    """Generic interval-diff skeleton: `poll()` is one interval tick.

    Each call fetches the source's current items, computes their identity (`item_key`) and
    content hash (canonical JSON, so key order never causes a false "changed"), and compares
    against the snapshot from the previous call. Every added or changed item produces one
    raw payload via `build_selector`; every item present last time but absent now produces one
    raw payload via `build_removed_selector` if the host supplied one — a diff has only the
    removed item's key, not its old content, so a host that cannot build a meaningful selector
    from a bare key may leave `build_removed_selector` unset and removals are then silently
    not reported (documented, not a bug: there is nothing else this skeleton could invent).

    THE FIRST POLL ESTABLISHES THE BASELINE AND EMITS NOTHING. With no snapshot, every item
    in the source differs from "nothing", so the first tick after every process start
    reported the ENTIRE source as changed — and each of those events stales every validated
    memory that names the item in its provenance. A restart of a poller watching a tool
    registry therefore demoted the project's whole vault out of `RETRIEVABLE_STATUSES`, from
    nothing but an ordinary redeploy. The cost of priming instead is a blind spot for
    changes made while this process was down; a host that cannot accept that persists
    `snapshot()` and hands it back as `initial_snapshot`, which makes the first poll a real
    diff against real prior state rather than against an assumption.
    """

    def __init__(
        self,
        source: JsonSourcePort,
        *,
        item_key: Callable[[Mapping[str, object]], str],
        build_selector: Callable[[Mapping[str, object]], Mapping[str, object]],
        event_type: str,
        build_removed_selector: Callable[[str], Mapping[str, object]] | None = None,
        initial_snapshot: Mapping[str, str] | None = None,
    ) -> None:
        if not event_type:
            raise ValueError("event_type must be a non-empty string")
        self._source = source
        self._item_key = item_key
        self._build_selector = build_selector
        self._event_type = event_type
        self._build_removed_selector = build_removed_selector
        self._lock = threading.Lock()
        self._last: dict[str, str] = dict(initial_snapshot or {})
        self._primed = initial_snapshot is not None

    def snapshot(self) -> Mapping[str, str]:
        """The `item_key -> content hash` state as of the last `poll()`.

        Persist it and pass it back as `initial_snapshot` after a restart so the first poll
        of the new process diffs against what the old one last saw.
        """
        with self._lock:
            return dict(self._last)

    def poll(self) -> Sequence[Mapping[str, object]]:
        items = self._source.fetch()
        current: dict[str, tuple[str, Mapping[str, object]]] = {}
        for item in items:
            key = self._item_key(item)
            if key in current:
                # Two items with one identity: the later would silently overwrite the
                # earlier in the snapshot, so a change to whichever lost the race would
                # never be reported again. A host's `item_key` returning duplicates is a
                # wiring defect, and a diff engine cannot diff what it cannot tell apart.
                raise ValueError(f"item_key produced a duplicate key {key!r} within one fetch")
            current[key] = (_hash_item(item), item)

        events: list[dict[str, object]] = []
        with self._lock:
            primed, previous = self._primed, self._last
            self._last = {key: content_hash for key, (content_hash, _item) in current.items()}
            self._primed = True
            if not primed:
                return ()
            for key, (content_hash, item) in current.items():
                if previous.get(key) != content_hash:
                    events.append(
                        {
                            "event_type": self._event_type,
                            "selector": dict(self._build_selector(item)),
                        }
                    )
            if self._build_removed_selector is not None:
                for key in previous.keys() - current.keys():
                    events.append(
                        {
                            "event_type": self._event_type,
                            "selector": dict(self._build_removed_selector(key)),
                        }
                    )
        return events


def _hash_item(item: Mapping[str, object]) -> str:
    """Content-identity for one source item — canonical JSON so key order never matters."""
    return hashlib.sha256(canonical_json(dict(item))).hexdigest()
