"""Negative probes (PLAN.md §7 Phase 1 gate — the headline assertion).

A negative probe is a query for which the CORRECT hot-path behaviour is to
inject NOTHING dynamic. See `probes.py`'s module docstring for the four
probe classes, the harness assembly that exercises real production code
(never a stub), and the positive control that proves the harness can still
detect an injection when one is warranted.
"""

from __future__ import annotations

from harness.negative_probes.probes import (
    TARGET_ABSTENTION_PCT,
    NegativeProbeReport,
    Probe,
    ProbeClass,
    ProbeResult,
    build_probes,
    positive_control_probe,
    render_text,
    run_negative_probes,
    run_probe,
    run_probe_through_pipeline,
)

__all__ = [
    "TARGET_ABSTENTION_PCT",
    "NegativeProbeReport",
    "Probe",
    "ProbeClass",
    "ProbeResult",
    "build_probes",
    "positive_control_probe",
    "render_text",
    "run_negative_probes",
    "run_probe",
    "run_probe_through_pipeline",
]
