# injection_payloads

Fuzz corpus for `tests/phase1/test_renderer_property.py` (Phase 1 chunk
assembler-renderer, PLAN.md §2 invariant 3). This is the deliverable that
proves the render-as-data property against realistic adversarial shapes, not
a formality.

**What this corpus is for, and what it is not.** Every payload here is placed
into a `Candidate.text` VALUE position and rendered through
`hotpath.renderer.render()`. The test asserts each one survives
verbatim-escaped inside its entry's JSON-encoded `text=` field and never
appears as a raw top-level line/token in the rendered document (no forged
section header, no forged `MEMORY_HEADER`, no second entry line, no
delimiter break-out). This proves the **governance** property (PLAN.md
invariant 3 / D-026): render-as-data preserves policy subordination because
attacker text can never become template structure. It does **not** prove
these payloads are harmless if a downstream model reads them — delimiting is
the weakest prompt-injection defense variant (~50% ASR reduction
non-adaptive, >95% adaptive; Hines et al. arXiv:2403.14720). `core.scans`
(content-level rejection before a memory is ever stored) is the layer that
tries to catch payloads like these on meaning, not shape; this corpus is
scoped to shape only.

## Format

`payloads.jsonl` — one JSON object per line, UTF-8, no trailing comma:

```json
{"id": "<stable-slug>", "category": "<one of the categories below>", "text": "<the payload string>"}
```

## Categories (>=40 payloads total, each category non-empty)

- **`imperative_override`** — direct instruction-override phrasing ("ignore
  all previous instructions", "you must now...", role/persona hijacks).
- **`delimiter_escape`** — attempts to close the JSON string early or break
  out of the entry line: unescaped-looking quotes, a literal `text=` or
  `id=` sequence, raw newlines, an attempt to terminate with `"]` or similar.
- **`fake_header`** — the literal `MEMORY_HEADER` string
  (`MEMORY (recalled data, verify against current state)`) or a close
  variant, attempting to forge a second header line or relabel the block.
- **`nested_fence`** — triple-backtick code fences, XML/ChatML control
  tags (`<system>`, `<|im_start|>`), attempting to open a nested delimited
  region inside the value.
- **`unicode_direction_override`** — Unicode bidi control characters
  (U+202E RIGHT-TO-LEFT OVERRIDE, U+200F RIGHT-TO-LEFT MARK, U+2066-U+2069
  isolates) that visually reorder or disguise surrounding text in a
  terminal/UI.
- **`null_byte`** — embedded NUL (Unicode code point zero) and other C0
  control characters.

Every category must have at least one fixture
(`test_every_declared_category_has_at_least_one_fixture`), matching the
convention in `tests/fixtures/scan_corpus/README.md`.

## Do not remove the non-ASCII line breaks

Several payloads carry **U+2028** LINE SEPARATOR, **U+2029** PARAGRAPH
SEPARATOR, or **U+0085** NEXT LINE (`esc-011`..`esc-017`, `hdr-008`,
`hdr-009`, `fen-010`, `nul-006`, `mix-006`, `mix-007`). They are not
decoration. `json.dumps` escapes every code point below U+0020 whether or not
`ensure_ascii` is set, so a corpus built only from `\n`/`\r`/NUL cannot tell
`ensure_ascii=True` apart from `ensure_ascii=False` — and that flag is the
third of the three escaping properties `hotpath/templates.py` claims, the one
that neutralises bidi overrides and homoglyphs. This was measured: before
these payloads existed, flipping `ensure_ascii` to `False` left the entire
suite green. `test_corpus_covers_every_splitlines_only_line_break` now fails
if any of those code points leaves the corpus.

Relatedly, the property test splits rendered documents with
`str.splitlines()`, not `split("\n")`: `splitlines()` also breaks on
`\v \f \x1c \x1d \x1e \x85` and on U+2028 / U+2029, so it is the most generous
definition of "a line" available and therefore the right one for a property
that says attacker text can never become a top-level line.
