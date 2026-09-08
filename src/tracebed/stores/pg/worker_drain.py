"""Narrow physical worker-identity queue-drain read for Compose lifecycle control.

This is deliberately not a ``WorkerQueue`` operation: the controller invokes it
only after the owner has closed the singleton admission fence, through the
actual worker login, to prove that no v1 rows (leased rows included) remain
before a lifecycle mutation.  It has no mutation surface.
"""

from __future__ import annotations

from typing import Final

import psycopg

__all__ = ["pending_v1_work_count"]

_V1_TOPICS: Final = ("trace_event", "outcome_event", "memory_proposal")
_WORKER_DRAIN_SQL: Final = """
SELECT depth
  FROM public.tracebed_worker_queue_metrics(%s::text)
"""


def pending_v1_work_count(dsn: str) -> int:
    """Return all v1 queue rows, including leased claim generations."""

    try:
        with psycopg.connect(dsn, autocommit=True) as connection:
            total = 0
            for topic in _V1_TOPICS:
                row = connection.execute(_WORKER_DRAIN_SQL, (topic,)).fetchone()
                if row is None or len(row) != 1 or not isinstance(row[0], int) or row[0] < 0:
                    raise RuntimeError("worker drain probe failed")
                total += row[0]
    except psycopg.Error:
        raise RuntimeError("worker drain probe failed") from None
    return total
