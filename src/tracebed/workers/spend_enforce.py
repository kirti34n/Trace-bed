"""Spend enforcement (PLAN.md section 7 Phase 3: "spend enforcement"; section 6
`spend.daily_llm_cap_usd`).

`workers.spend.SpendMeter` (Phase 0) already records ledger entries and reports `CapStatus`,
but its own module docstring is explicit that Phase 0 "does not refuse anything" and that
"Phase 3 is what pauses workers on `CapStatus.exceeded`". This module is that Phase 3: the one
place `domain.errors.CapExceeded` (declared in Phase 0 "for Phase 3's proposal / spend cap
enforcement", raised nowhere until now) actually gets raised.

THE HARD BOUNDARY (PLAN.md section 6: "on cap: workers pause + alert; hot path unaffected"):
retrieval must keep serving when the learning budget is exhausted, because a spend cap that
takes down retrieval turns a billing event into an outage. This is enforced structurally, not
by convention, and the structure is worth stating precisely because "nothing imports it" is a
property that decays:

  * `scripts/purity_check.py` (CI-blocking, invariant 1) proves no `workers` module -- this one
    included -- is reachable from `hotpath/`'s import graph.
  * `hotpath.pipeline.Pipeline.__init__` takes `clock`, `config`, `telemetry`, `retriever`,
    `assembly`, `static_prefix`, `injections`, `holdout_salt`. None of them is a spend meter,
    and none of them is a type this module can reach: the only shared dependency between the
    hot path and the spend cap is `stores.pg.repo.Repo` itself, which `SpendMeter` reads
    `spend_ledger` through and which `Pipeline` never touches (it goes through the narrow
    `TelemetryRecorderPort` / `CandidateAssemblyPort` seams). A pooled-connection outage can
    degrade both, but that is invariant 2's fail-open ladder, not this cap: there is no value
    of `spent_today_usd` that changes what `Pipeline.retrieve()` returns.
  * `EffectiveConfig.killswitch_overlay` is the one channel by which a background decision DOES
    reach retrieval. Nothing in this module writes it -- only `workers.killswitch` does, and
    only from lift evidence. A spend cap deliberately has no such channel.

`tests/phase3/test_spend_enforce.py::TestHotPathUnaffected` exercises the second bullet against
a real `Pipeline`, over cap, rather than asserting it in prose.

`SpendCapCheckPort` is declared locally (structural typing, `typing.Protocol`) rather than
depending on the concrete `workers.spend.SpendMeter` class directly, so this module's own tests
stay fully offline: `SpendMeter.__init__` takes a concrete `stores.pg.repo.Repo` (outside this
chunk's file list, and a real Postgres connection pool besides), and a `Protocol` lets a plain
in-memory fake satisfy `SpendEnforcer`'s dependency exactly the way `workers.invalidator`'s
`MemoryLifecycleRepoPort` lets that module's tests avoid a database. `SpendMeter` itself
satisfies `SpendCapCheckPort` structurally without modification -- production code passes a
real `SpendMeter`, tests pass a fake with the same one method.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, TypeVar, runtime_checkable

from tracebed.domain.errors import CapExceeded
from tracebed.domain.ids import ProjectId
from tracebed.workers.spend import CapStatus

__all__ = [
    "SpendCapCheckPort",
    "SpendEnforcementResult",
    "SpendEnforcer",
]

logger = logging.getLogger(__name__)

_T = TypeVar("_T")


@runtime_checkable
class SpendCapCheckPort(Protocol):
    """What `SpendEnforcer` needs from a spend meter -- see the module docstring for why this
    is a Protocol rather than a direct `workers.spend.SpendMeter` dependency. `SpendMeter`
    satisfies this structurally; nothing needs to inherit from it.
    """

    def check_cap(self, project_id: ProjectId) -> CapStatus: ...


@dataclass(frozen=True, slots=True)
class SpendEnforcementResult:
    """What one `SpendEnforcer.run_guarded` call decided. `paused` is `True` exactly when the
    guarded callable was skipped -- not "the cap was over" (an operator could be checking
    `status` on its own, with nothing to pause), but "a worker's unit of work did not run
    because of this cap"."""

    project_id: ProjectId
    status: CapStatus | None
    """`None` only when the meter itself could not answer (see `run_guarded`): the cap state is
    genuinely unknown, and reporting a fabricated `CapStatus` would put an invented number in
    front of whoever reads the pause."""
    paused: bool


class SpendEnforcer:
    """Pauses WORKERS on a per-project daily spend cap. See the module docstring for why this
    can never reach retrieval: nothing in `hotpath/` imports this class or is imported by it.
    """

    def __init__(self, meter: SpendCapCheckPort) -> None:
        self._meter = meter

    def status(self, project_id: ProjectId) -> CapStatus:
        """A pure read, for a dashboard or a caller that wants to report the cap state without
        guarding anything."""
        return self._meter.check_cap(project_id)

    def guard(self, project_id: ProjectId) -> CapStatus:
        """Raises `CapExceeded` if today's (UTC) spend is over `spend.daily_llm_cap_usd`;
        returns the passing `CapStatus` otherwise.

        This is the one-line check a worker's batch loop makes before it spends another dollar
        of LLM budget. `SpendMeter.check_cap` already fails closed on the numbers it sums over
        (its own module docstring covers NaN/negative deltas), so there is nothing else for
        this method to interpret -- it either raises, or it does not.

        A failure of the meter itself (a store error) propagates: `guard` reports the cap, it
        does not decide policy about an unknown cap. `run_guarded` is where that decision is
        made, and it is made explicitly.
        """
        return self._refuse_if_over(self._meter.check_cap(project_id), project_id)

    @staticmethod
    def _refuse_if_over(current: CapStatus, project_id: ProjectId) -> CapStatus:
        if current.exceeded:
            logger.warning(
                "spend_enforce: project %s over its daily LLM cap ($%.2f spent / $%.2f cap); "
                "pausing quality-lane workers for the rest of the UTC day",
                project_id,
                current.spent_today_usd,
                current.cap_usd,
            )
            raise CapExceeded(
                f"project {project_id} spent ${current.spent_today_usd:.2f} against a "
                f"${current.cap_usd:.2f} daily cap"
            )
        return current

    def run_guarded(
        self, project_id: ProjectId, fn: Callable[[], _T]
    ) -> tuple[_T | None, SpendEnforcementResult]:
        """Runs `fn()` unless `project_id` is over its daily cap, in which case `fn` is never
        called at all -- a skip, not a retry-later -- and the result reports `paused=True`.

        This is the worker-side integration point (module docstring): a distiller, judge, or
        shadow-validator batch loop wraps its per-project unit of LLM-costing work in this call
        instead of calling `guard` and catching `CapExceeded` itself, so "pause on cap" is one
        line at every call site rather than a try/except duplicated at each of them.

        THE CAP IS READ EXACTLY ONCE per call. An earlier version read it a second time to fill
        in the result after `guard` raised, which meant the reported `status` could disagree
        with the one the decision was made on, and -- worse -- a store error on that second read
        replaced `CapExceeded` with an unrelated exception escaping into the worker loop.

        AN UNREADABLE METER PAUSES. If `check_cap` raises, this call reports `paused=True` with
        `status=None` and does not run `fn`. The alternative (spend on, cap unknown) fails open
        on the one control that bounds real money, and a ledger outage is exactly when spend is
        least observable. Nothing about this reaches retrieval, which is what makes pausing the
        safe default here and would make it the wrong default on the hot path.
        """
        try:
            current = self._meter.check_cap(project_id)
        except Exception:
            logger.warning(
                "spend_enforce: cap state unreadable for project %s; pausing this unit of work "
                "rather than spending against an unknown budget",
                project_id,
                exc_info=True,
            )
            return None, SpendEnforcementResult(project_id=project_id, status=None, paused=True)

        try:
            status = self._refuse_if_over(current, project_id)
        except CapExceeded:
            return None, SpendEnforcementResult(
                project_id=project_id, status=current, paused=True
            )
        return fn(), SpendEnforcementResult(project_id=project_id, status=status, paused=False)
