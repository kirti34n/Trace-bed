"""Process-local HMAC signing key for `ScanVerdict` (PHASE0-CONTRACT.md §3.7/C-06).

The key lives in its own module-private file because that is what the binding
contract's module map (§1) and `domain/scan.py`'s own docstring both name as
its home. Keeping it out of `core/scans/__init__.py` also keeps it out of the
namespace every consumer of the scan suite imports: `from tracebed.core import
scans` gives a caller `scan`, `verify_verdict`, and nothing that lets them mint
a signature themselves.

Generated once at import and never persisted, so a verdict is valid only inside
the process that minted it. That is acceptable for Phase 0 because scanning and
inserting always happen in the same process (§3.7 point 3); a later phase that
separates them must raise a contract_gap rather than reach for a shared secret.
"""

from __future__ import annotations

import secrets
from typing import Final

__all__ = ["SIGNING_KEY"]

#: 32 random bytes, HMAC-SHA256 key. Module-private by convention (this module
#: is `_authority`); nothing outside `tracebed.core.scans` may import it.
SIGNING_KEY: Final[bytes] = secrets.token_bytes(32)
