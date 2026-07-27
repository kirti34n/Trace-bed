"""Storage drivers: Postgres, Valkey, and the trace object store.

Empty on purpose (contract §1) — each backend lives in its own subpackage
(`stores.pg`, `stores.valkey`, `stores.tracestore`) so that
scripts/raw_sql_lint.py's containment rule ("SQL execution only under
stores/pg/") has a stable package boundary to check against.
"""

from __future__ import annotations
