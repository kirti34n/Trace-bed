"""The FastAPI process (PHASE0-CONTRACT.md §9, owner: api-auth).

Deliberately empty beyond the docstring: `api/main.py` builds the app,
`api/deps.py` carries `AppDeps` and the auth/scope dependency chain,
`api/models.py` carries the wire models, `api/routes_v1.py` and `api/admin.py`
carry the routers. Nothing here re-exports the submodules — importers name
the submodule they want, so a stray `from tracebed.api import *` cannot
accidentally pull the real (network-touching) `create_app` into an offline
unit test that only meant to import a Pydantic model.
"""

from __future__ import annotations
