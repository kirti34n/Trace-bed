"""Phase 4 workflow-memory package: run blackboard, routing records, orchestrator prefetch.

Not part of `hotpath/` (no purity restriction applies here — `scripts/purity_check.py`
only walks the graph rooted at `tracebed.hotpath`) and not part of `workers/` (nothing
here is a background batch job). This package is read/write surface an external
orchestrator (or an in-run agent, for `blackboard.py`) calls directly, same shape as
`sdk/`.

`blackboard.py` is the domain-level (pure, no I/O) half of the run blackboard — shared,
transactional run-state between agents inside one workflow run (PLAN.md §7). Its
persistence half lives in `stores.pg.blackboard`, kept out of this package because SQL
is confined to `stores/pg/` (`scripts/raw_sql_lint.py` enforces this for the whole
`src/` tree). `routing.py` (routing records) and `prefetch.py` (orchestrator prefetch)
are a separate Phase 4 chunk's modules, with no import relationship to `blackboard.py`
in either direction.
"""

from __future__ import annotations
