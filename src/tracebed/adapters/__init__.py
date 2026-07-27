"""Ports and shipped defaults.

PLAN.md §3: the core must run, fully featured, against zero host. Every
host-specific concern is a port in `ports.py` with a working default
implementation in this package. A host platform (Atom, or anything else)
integrates by implementing a port — never by patching the core.

`adapters/atom/` holds documented interface stubs only. No integration code
lives here; the human writes that against the port definitions.
"""
