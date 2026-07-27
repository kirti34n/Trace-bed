"""Trace and outcome ingestion (PHASE0-CONTRACT.md §11, PHASE-0 Tasks 14/15).

Consumers of `TOPIC_TRACE_EVENT`/`TOPIC_OUTCOME_EVENT`
(`tracebed.stores.pg.queue`). Nothing here executes SQL directly
(`scripts/raw_sql_lint.py` enforces this) -- every write goes through
`Repo`/`ScopedRepo`.
"""

from __future__ import annotations
