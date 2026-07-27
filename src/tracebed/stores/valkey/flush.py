"""Valkey-side cache invalidation: the `cache_flush` event and project deletion.

PLAN.md §5: "Per-project key sets are tracked for O(1) flush; a `cache_flush`
invalidation event type exists from Phase 1." This module names the one
thing neither `keys.py` nor `client.py` commits to on its own: which
`invalidation_event.event_type` string means "wipe this project's entire
cache namespace" (`CACHE_FLUSH_EVENT_TYPE`), and the single entry point both
a live `cache_flush` delivery and full project deletion route through — so
"erase everything this project put in the cache" has exactly one
implementation, not two call sites that can silently drift apart.

It does not re-implement the sweep: `ValkeyClient.delete_project` already
walks every key under a project's namespace — tool cache, working memory,
static prefix alike — through the one key-pattern every builder in
`keys.py` writes under, and that (see its own docstring) is what "flush" and
"delete" both need. This module only names the two call sites that must
reach it and the wire spelling a future `invalidation_event` consumer
recognises.
"""

from __future__ import annotations

from typing import Final

from tracebed.domain.ids import ProjectId
from tracebed.stores.valkey.client import ValkeyClient

__all__ = ["CACHE_FLUSH_EVENT_TYPE", "delete_project", "flush_project_cache", "is_cache_flush"]

CACHE_FLUSH_EVENT_TYPE: Final[str] = "cache_flush"
"""The `invalidation_event.event_type` spelling (PLAN.md §5) that means
"flush this project's cache namespace". `POST /v1/invalidation` persists an
arbitrary caller-chosen `kind` string (`Repo.insert_invalidation_event`); a
future consumer of `invalidation_event` rows recognises this exact spelling
and calls `flush_project_cache` below. One named constant is what keeps the
webhook-writer side and the consumer side from drifting into two different
strings for what must be the same event."""


def is_cache_flush(event_type: str) -> bool:
    """Whether an `invalidation_event.event_type` value names this event."""
    return event_type == CACHE_FLUSH_EVENT_TYPE


def flush_project_cache(client: ValkeyClient, project_id: ProjectId) -> int:
    """Handles a `cache_flush` invalidation event: removes every key under
    `project_id`'s namespace. Returns the count removed — leak-suite probe 6
    and this call share the exact same sweep (`ValkeyClient.delete_project`),
    so "flushed" and "auditable as gone" are the same claim.
    """
    return client.delete_project(project_id)


def delete_project(client: ValkeyClient, project_id: ProjectId) -> int:
    """The Valkey-side half of full project deletion.

    The sibling call `stores.pg.partitions.drop_project` and
    `TraceStorePort.delete_project` each make in their own store, so a
    project delete leaves nothing of this project behind in the cache layer
    either. Mechanically identical to `flush_project_cache` — named
    separately because the two are reached from different events (a live,
    reversible-in-effect webhook vs. an irreversible admin action), and a
    reader following a project-deletion call chain should find a
    same-named sibling here rather than a cache_flush-specific name applied
    outside the scope it names.
    """
    return client.delete_project(project_id)
