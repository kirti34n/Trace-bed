"""The Postgres store: typed repository, migrations, partitions, queue.

This is the one package `scripts/raw_sql_lint.py` permits to execute SQL
(PLAN.md §5 invariant 4 — "raw SQL outside the repository fails a static
check"). Empty on purpose; submodules are imported directly
(`tracebed.stores.pg.ddl`, `tracebed.stores.pg.partitions`,
`tracebed.stores.pg.migrate`, ...).
"""

from __future__ import annotations
