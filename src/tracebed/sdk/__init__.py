"""Tracebed SDK — the fire-and-forget client (PHASE0-CONTRACT.md §10).

Public surface: `TracebedClient` (client.py) plus the buffering primitives it
is built on (`RingBuffer`, `FlushReport` — buffer.py), re-exported here so a
host application imports `tracebed.sdk` and nothing deeper.
"""

from __future__ import annotations

from tracebed.sdk.buffer import BufferedItem, FlushReport, RingBuffer
from tracebed.sdk.client import TracebedClient

__all__ = ["BufferedItem", "FlushReport", "RingBuffer", "TracebedClient"]
