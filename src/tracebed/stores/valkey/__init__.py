"""The Valkey store: working memory, tool cache, static-prefix cache.

Key construction lives exclusively in `stores.valkey.keys` — the one module
`scripts/raw_sql_lint.py` permits to contain a `tb` key-prefix literal (PLAN.md §5,
PHASE0-CONTRACT.md §7). `stores.valkey.client.ValkeyClient` is the thin
scoped wrapper over valkey-py that builds every key through it; nothing else
under `stores.valkey` constructs a key inline.
"""

from __future__ import annotations
