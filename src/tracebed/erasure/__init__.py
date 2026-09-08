"""Private, deployment-only erasure execution surface.

E2 intentionally exposes only request/fence publication.  Nothing in this
package is imported by the API or ordinary worker runtime; it is wired only by
the separately credentialed E3 command entry points.
"""

from tracebed.erasure.domain import (
    ErasureLease,
    ErasureSettings,
    ExternalWork,
    StepOutcome,
    StoreResult,
)

__all__ = [
    "ErasureLease",
    "ErasureSettings",
    "ExternalWork",
    "StepOutcome",
    "StoreResult",
]
