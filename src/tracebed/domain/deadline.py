"""Neutral structural request-budget contract for synchronous adapters."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

__all__ = ["RemainingBudget"]


@runtime_checkable
class RemainingBudget(Protocol):
    """The remaining cooperative request time in milliseconds."""

    def remaining_ms(self) -> float: ...
