"""Same-origin browser edge; it owns opaque sessions, never application scope."""

from tracebed.edge.config import EdgeSettings
from tracebed.edge.main import create_app, run

__all__ = ["EdgeSettings", "create_app", "run"]
