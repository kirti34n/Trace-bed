"""Closed worker-identity queue drain probe used by the Compose controller."""

from __future__ import annotations

import os
import sys

from tracebed.stores.pg.authority_dsn import runtime_dsn_from_environment
from tracebed.stores.pg.worker_drain import pending_v1_work_count as _pending_v1_work_count


def pending_v1_work_count() -> int:
    """Return all v1 work, including currently leased generations.

    This connects as the actual worker process identity.  It deliberately does
    not dequeue, change leases, or set a project context: the owner controller
    needs a physical capability-bound count before it stops the worker.
    """

    dsn = runtime_dsn_from_environment("tracebed_worker", os.environ).value
    return _pending_v1_work_count(dsn)


def main() -> int:
    """Print only the bounded count for the closed lifecycle controller."""

    try:
        print(pending_v1_work_count())
    except Exception:
        print("tracebed-worker-drain failed", file=sys.stderr)
        return 1
    return 0
