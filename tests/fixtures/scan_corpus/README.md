# scan_corpus

Fixtures for `tests/phase0/test_scans.py` and
`tests/phase0/test_tier_a_zero_passthrough.py` (PHASE-0 Task 9,
PHASE0-CONTRACT.md §4). Not a formality — this corpus is the deliverable
that proves the shared scan gate suite actually catches the vectors
PHASE-0 and Phase 2 gate on (D-019, D-024).

## Format

Every file is JSON Lines (one JSON object per line, UTF-8, no trailing
comma). Every line has at minimum:

```json
{"id": "<stable-slug>", "text": "<the candidate content string>"}
```

`injection_strong.jsonl`, `injection_weak.jsonl` and `secrets.jsonl`
additionally carry `"expected_rule"` — the `patterns.py`/`secrets.py` rule id
the payload is written to trigger. **It is asserted, not decorative.** Every
fixture must be caught by its own declared rule, and every declared rule must
have at least one fixture (`test_every_declared_rule_id_has_at_least_one_fixture`).

Grading only on pass/fail was tried and was wrong: the fixtures overlap enough
that a broken rule stays hidden behind an unrelated one. `sec-015` shipped with
a GCP key one character short of the `gcp-api-key` rule's length and the suite
stayed green for it, because the catch-all `high-entropy-token` heuristic fired
instead. Rule-level attribution is what makes each regex individually
load-bearing under mutation.

## Files

- **`injection_strong.jsonl`** — >=30 distinct, real-shaped prompt-injection
  payloads (imperative override phrasing, ChatML/XML control markers,
  tool-invocation syntax, jailbreak markers, exfiltration/decode-and-execute
  instructions, persona overrides). **100% must be rejected** by `scan()`.
- **`injection_weak.jsonl`** — lower-confidence imperative-shaped phrasing
  that is plausible in ordinary operational prose. Informational: used to
  sanity-check the WEAK rule tier fires at all, not gated at 100%.
- **`secrets.jsonl`** — real-shaped credential/token/key material (AWS, GCP,
  PEM private key blocks, JWTs, bearer tokens, Slack/GitHub tokens, DB
  connection strings with embedded passwords, and unlabelled high-entropy
  tokens for the entropy heuristic). **100% must be rejected** by `scan()`,
  same as `injection_strong.jsonl` (PHASE0-CONTRACT.md §4).
- **`benign.jsonl`** — ordinary operational text a legitimate memory item
  might contain: lessons, semantic facts, preferences, tool-usage notes.
  Deliberately includes near-miss phrasing (the words "token"/"system"/
  "instructions" used in a non-injection sense, ordinary sha256 provenance
  hashes, UUIDs) so the false-positive rate measured against it is
  meaningful, not trivially zero. Asserted at **zero** false positives, not
  under a percentage ceiling: `scan()` rejects on any reason at all, so a
  false positive here is a legitimate memory refused at insert. A ceiling
  would silently absorb regressions (PHASE0-CONTRACT.md §4: "benign/ must
  pass"). If a fixture ever genuinely needs to be accepted, move the fixture
  — do not raise a ceiling.
- **`tool_error_bodies.jsonl`** — realistic tool/validator error bodies,
  the exact shape Tier A notes must never leak a substring of (D-019).
  Required contents per PHASE-0 Task 9:
  - the **Pydantic `input_value=` echo fixture**: a validation error whose
    message embeds the offending (attacker-shaped) input verbatim — the
    precise vector D-019 found ("structured" errors still quote payloads).
  - a tool error body with an **embedded injection payload** (a downstream
    service echoing attacker-controlled text back in an error/traceback).
  - assorted ordinary operational error bodies (timeout, rate-limit, auth,
    network, upstream 5xx) spanning `ErrorClassEnum`, so the zero-passthrough
    substring check has realistic non-adversarial bodies to check against
    too, not only the two adversarial ones.

## Why some fixtures contain `{{FILL:...}}` placeholders

For AWS access-key ids, GCP API keys and GitHub tokens, **our detector regex and the
provider's published format are the same pattern**. `AKIA[0-9A-Z]{16}` is byte-identical
in `src/tracebed/core/scans/secrets.py` and in GitHub push protection, gitleaks and
trufflehog. A fixture that exercises our rule therefore trips every one of those for
anyone who clones this repository — and the usual escape hatch ("allow this secret")
permanently allowlists a string that was never a secret.

So those fixtures store a placeholder, and `tests/phase0/test_scans.py::_expand_fills`
substitutes deterministic filler at collection time:

| Placeholder | Alphabet | Used by |
|---|---|---|
| `{{FILL:U:n}}` | `[0-9A-Z]` | AWS access-key id |
| `{{FILL:A:n}}` | `[A-Za-z0-9]` | GitHub PAT |
| `{{FILL:G:n}}` | `[0-9A-Za-z\-_]` | GCP API key |
| `{{FILL:B:n}}` | `[A-Za-z0-9/+]` | AWS secret access key |

**The file on disk contains no token-shaped substring; the string handed to the scanner
does.** Expansion is deterministic rather than random, so a parametrised test id is stable
and a failure reproduces exactly.

Fixtures whose rule is *not* a provider format (Slack, bearer, connection strings, generic
credential assignment, high-entropy) are written literally with an `EXAMPLE_NOT_A_REAL_`
marker instead — no placeholder is needed because no third-party scanner keys on them.

The two JWT fixtures are literal: their base64 payloads decode to the English text
`EXAMPLE-NOT-A-REAL`, a JWT with a fake signature authenticates nothing, and no scanner
treats one as a revocable provider credential.
