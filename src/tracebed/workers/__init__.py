"""Background workers: extractors, distiller, scorer, shadow_validator, consolidator,
invalidator, prefix_builder, killswitch, gc (PLAN.md §4).

Phase 0 ships exactly one member of this package: `spend.py`'s `SpendMeter`, a
records-only ledger meter (`spend_ledger`). Every other worker in PLAN.md §3's
module table lands in Phase 2/3; this package stays otherwise empty until then.
"""

from __future__ import annotations
