"""The Phase 3 red team (PLAN.md section 7 Phase 3 gate). See `probes.py`'s
module docstring for the four probes, the Sybil test, and the retirement
K-1 probe -- every one driven end to end through the real governance
machinery (`domain.state_machine.apply`, `workers.shadow_validator
.ShadowValidator`, `workers.sweeps.quarantine_ttl_sweep`,
`workers.promotion.PromotionWorker`), never a re-implementation of a
predicate those modules already own.
"""

from __future__ import annotations

from harness.redteam.probes import (
    ProbeResult,
    RedTeamReport,
    RetirementProbeReport,
    SybilProbeReport,
    render_text,
    run_redteam,
    run_retirement_k_minus_one_probe,
    run_sybil_probe,
)

__all__ = [
    "ProbeResult",
    "RedTeamReport",
    "RetirementProbeReport",
    "SybilProbeReport",
    "render_text",
    "run_redteam",
    "run_retirement_k_minus_one_probe",
    "run_sybil_probe",
]
