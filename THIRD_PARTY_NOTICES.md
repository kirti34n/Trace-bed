# Third-party notices

Tracebed does not vendor third-party source code in this snapshot. Runtime and
development dependencies are installed separately from locked Python and npm
dependency graphs.

For a candidate release, the release-evidence workflow materializes every
available `LICENSE*`, `COPYING*`, and `NOTICE*` file from the installed locked
Python and npm runtime graphs, including the conditional psycopg LGPL metadata.
Missing notice material fails the candidate rather than producing a placeholder.
It pairs this inventory with per-graph SPDX/CycloneDX SBOMs. Those generated files are hash-bound release evidence.
They do not claim a published release or substitute for review of the generated
notice and SBOM material.

The source-level dependency licence gate and its policy live in
[`scripts/license_check.py`](scripts/license_check.py) and
[`scripts/license_policy.toml`](scripts/license_policy.toml).
