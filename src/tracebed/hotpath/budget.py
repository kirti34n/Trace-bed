"""The retrieval deadline (PLAN.md §2 invariant 2, §6 `retrieval.total_budget_ms` /
`retrieval.embed_timeout_ms`).

Built from `clock.monotonic_ms()` only — never wall-clock time (hard rule 3: no
`datetime.now()` outside `SystemClock`, and monotonic time is what a latency budget
must be measured against, since a wall-clock step must never manufacture or erase
retrieval budget).

The load-bearing rule the docstring on `Deadline` restates at each call site: every
hot-path stage checks remaining time BEFORE it starts doing work, not after. A stage
that begins with 5ms left and takes 80ms has already blown the budget the instant it
started — there is no way to notice that after the fact except by measuring elapsed
time nobody had. `Deadline` therefore only ever answers "how much time is left right
now"; it has no method that reports how long a finished stage took, because that
question is exactly the wrong one for a fail-open budget to be answering.
"""

from __future__ import annotations

from tracebed.domain.clock import Clock

__all__ = ["Deadline"]


class Deadline:
    """One retrieval call's budget, anchored to a single `clock.monotonic_ms()` reading.

    `total_budget_ms` and `embed_timeout_ms` are read from `EffectiveConfig.retrieval`
    by the caller (`pipeline.py`) and passed in here — never a literal (hard rule 4),
    so per-project / per-agent-type tuning (PLAN.md §6) reaches every budget check
    without a code change. A plain class, not a frozen dataclass: the one thing this
    object does is measure elapsed time against a reading it took at construction, and
    that reading is deliberately its only mutable-in-spirit state (never reassigned
    after `__init__`, just read repeatedly against a moving clock).

    `started_at_ms` exists because the budget PLAN.md §2 invariant 2 names is the
    *call's* budget, not the ladder's: the config resolution and holdout assignment
    that precede the first search happen inside the same 300ms the caller is waiting
    on, and `ConfigResolver.effective()` reads `project_config` / `agent_type_config`
    — a store round trip that can stall. Anchoring here (at `Deadline` construction)
    instead of at the entry to `retrieve()` would silently exclude that stall from the
    budget, so a 2s config stall would still be followed by a full retrieval attempt
    and recorded as a healthy `injected` row. Callers that already read the clock at
    call entry pass that reading in; the default keeps the object usable standalone.
    """

    __slots__ = ("_clock", "_started_at_ms", "embed_timeout_ms", "total_budget_ms")

    def __init__(
        self,
        *,
        clock: Clock,
        total_budget_ms: int,
        embed_timeout_ms: int,
        started_at_ms: float | None = None,
    ) -> None:
        if total_budget_ms <= 0:
            raise ValueError(f"total_budget_ms must be positive, got {total_budget_ms!r}")
        if embed_timeout_ms <= 0:
            raise ValueError(f"embed_timeout_ms must be positive, got {embed_timeout_ms!r}")
        self._clock = clock
        self.total_budget_ms = total_budget_ms
        self.embed_timeout_ms = embed_timeout_ms
        self._started_at_ms = clock.monotonic_ms() if started_at_ms is None else started_at_ms

    def elapsed_ms(self) -> float:
        """Monotonic milliseconds since this `Deadline` was constructed."""
        return self._clock.monotonic_ms() - self._started_at_ms

    def remaining_ms(self) -> float:
        """`total_budget_ms` minus elapsed time. May be negative once exceeded —
        callers compare against 0 via `total_exceeded()` rather than re-deriving it."""
        return self.total_budget_ms - self.elapsed_ms()

    def total_exceeded(self) -> bool:
        """True once the total retrieval budget (PLAN.md §2 invariant 2's second
        ladder rung) has been reached or passed. Checked BEFORE every stage that
        would otherwise start work with no time left to finish it."""
        return self.remaining_ms() <= 0

    def embed_sub_budget_ms(self) -> float:
        """How much time a stage may spend on query embedding starting right now.

        Never more than `embed_timeout_ms`, and never more than what remains of the
        total budget — the sub-budget the embed stage is handed is the tighter of
        the two, checked before the embed call starts rather than derived from how
        long it happened to take. A value `<= 0` means there is no time left to
        even attempt an embed call; the caller must skip it entirely.
        """
        return max(0.0, min(float(self.embed_timeout_ms), self.remaining_ms()))
