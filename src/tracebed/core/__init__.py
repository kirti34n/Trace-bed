"""`tracebed.core` — pure, I/O-free governance logic shared across write paths.

Home to `core/scans`, the shared gate suite every write path must present a
`ScanVerdict` to (PHASE-0 Task 9, PHASE0-CONTRACT.md §4). Nothing under
`core/` touches a database, a queue, or the network.
"""

from __future__ import annotations
