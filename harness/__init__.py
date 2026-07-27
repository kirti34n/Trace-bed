"""Phase 0 harness package (PHASE-0 Tasks 17-18; PHASE0-CONTRACT.md §1, owner: harness).

Everything under `harness/` is gate tooling, not shipped product code: the
cross-project leak suite (`leak_suite/`), the fake agent runtime used to
measure SDK overhead (`fake_runtime.py`), and the gate runner that ties every
Phase 0 proving step together into one report (`phase0_gate.py`). Nothing in
`src/tracebed` imports this package.
"""

from __future__ import annotations
