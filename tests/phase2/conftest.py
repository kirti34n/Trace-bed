"""Phase 2 integration fixtures registered for every Phase 2 test module.

Pytest 9 rejects ``pytest_plugins`` in a non-root conftest because plugin
registration is global.  Re-export the one local fixture instead, retaining
the Phase-2-only fixture scope without changing collection for other phases.
"""

from tests.phase2.trace_e2e_support import scratch_dsn as scratch_dsn
