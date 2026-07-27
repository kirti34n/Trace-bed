"""The cross-project leak suite (PHASE-0 Task 17; PHASE0-CONTRACT.md §1/§13.2, owner: harness).

`fixtures.py` builds two fully-provisioned projects (registered principals,
memories, traces, cache entries) the same way a real deployment would —
through the admin routes and the typed repository, never by hand-crafting
rows — and `test_leaks.py` runs the seven probe classes PHASE-0.md Task 17
requires against them.
"""

from __future__ import annotations
