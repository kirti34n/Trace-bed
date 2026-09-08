# Diagram assets

These PNG diagrams were generated with built-in image generation on 8 September 2026 against code
baseline `80445118c8fa05b106e3451f60545f205ba4ad17`. They are publication aids, not executable
architecture. [ARCHITECTURE.md](../../ARCHITECTURE.md) supplies the accessible text equivalents and
code source map.

No SVG or Mermaid source is maintained for these diagrams. Regenerate a PNG when the architecture
changes, review legibility and every arrow against code, then update this provenance record and the
accessible description together.

## Generation prompts

<details>
<summary>Shared visual style</summary>

```text
Use case: infographic-diagram. Create a polished publication-quality technical diagram as a PNG raster, landscape 1536x1024 or higher. Opaque warm-white background, deep navy sans-serif typography, teal for request path, muted violet for background work, amber for optional services. Generous whitespace, crisp large text, consistent rounded cards, restrained thin borders, small geometric icons only if useful. No decorative art, no 3D, no watermark, no SVG or Mermaid output. Exact labels only; prioritize correct arrows and legible type.
```
</details>

<details>
<summary><code>architecture.png</code></summary>

```text
Title "Trace-bed architecture"; subtitle "Self-hosted service · standalone pre-alpha". Three horizontal bands. Top band "Clients": two cards "Host application + SDK" and "Browser dashboard". Middle service band: beneath host "API" with subtitle "Authority · retrieval · intake"; beneath browser "Same-origin edge / BFF". Arrow host→API, browser→edge, edge→API. A separate middle-row card "Background worker" subtitle "Ingest · extraction · maintenance"; another card "Erasure executor" subtitle "Separate credentials". Bottom storage band: wide "PostgreSQL" subtitle "Authority · memory · audit · durable queues"; "S3-compatible storage" subtitle "Encrypted trace archives"; "Valkey" subtitle "Cache / runtime data". Connections: API↔PostgreSQL only; worker↔PostgreSQL, worker↔S3, worker↔Valkey. Erasure executor points to a bracket encompassing storage band labeled "Scoped deletion". At right outside service boundary one amber card "Optional embedding provider", dashed connections from API and worker to it, label "Configured external egress". A concise footer: "Logical component view, not network topology" and "No generative LLM on the retrieval hot path". Make routing clear without crossings, ample space. Do not connect API to S3 or Valkey, do not call Valkey a queue. All services except clients and optional provider enclosed in a very subtle box labeled "Self-hosted boundary".
```

Targeted revision:

```text
Preserve all existing text, cards, style and connections except the erasure scoped deletion bracket. The bracket currently spans only Valkey, which is incorrect. Remove that bracket and its downward arrow. Instead put a clearly labeled violet dashed arrow from Erasure executor to the OUTER storage layer enclosure right edge, label 'Scoped deletion'. Its endpoint must touch the overall Storage layer border, not one individual storage card. This denotes all three stores. Do not change anything else.
```
</details>

<details>
<summary><code>retrieval-flow.png</code></summary>

```text
Title "Retrieval: query to audited context"; subtitle "Synchronous request path". Six numbered large cards arranged in a clearly connected snake, top row left→right 1,2,3, bottom row right→left 4,5,6. 1 "Receive query" subtitle "Host application / SDK"; 2 "Authorize + open run" subtitle "Server-derived scope and access"; 3 "Retrieve candidates" subtitle "Lexical + vector search"; 4 "Apply policy + assemble" subtitle "Visibility · budget · holdout"; 5 "Commit final-result audit" subtitle "Required before context response"; 6 "Return context or abstain" subtitle "Host decides whether to use it". Explicit arrows 1→2→3→4→5→6, numbered badges. A small amber card next to 3 "Optional query embedding" with dashed link to 3 and small text "Embedding unavailable: lexical fallback". A red-outlined branch from 5 downward labeled "Audit failure" to a card "Unavailable response". Bottom strip "One cooperative request deadline" and note "Holdout shadow selection is not delivered context". Do not show generation or autonomous prompt execution. Avoid any arrow from 4 straight to 6. Keep title and labels large and readable.
```
</details>

<details>
<summary><code>evidence-flow.png</code></summary>

```text
Title "From traces to candidate memory"; subtitle "Background processing, separate from retrieval". Six numbered large cards in clear snake with top row left→right 1,2,3 and bottom row right→left 4,5,6. 1 "Host sends trace" subtitle "SDK uses a bounded buffer"; 2 "Authorize + enqueue" subtitle "202 = intake accepted"; 3 "Process + archive trace" subtitle "Worker · encrypted S3 archive"; 4 "Claim trace-learning job" subtitle "PostgreSQL · lease-fenced work"; 5 "Extract structural candidates" subtitle "Tier-A / v1 · no generative LLM"; 6 "Finalize candidate + provenance" subtitle "Later retrieval is policy-dependent". Explicit arrows 1→2→3→4→5→6. Label the arrow 2→3 "PostgreSQL durable queue", arrow3→4 "Completed trace", arrow5→6 "Fenced finalization". Small separate callout beneath 1 "SDK retries are best-effort". Bottom amber strip "Accepted ≠ processed ≠ approved ≠ improved". Do not depict automatic approval, model training, or proven agent improvement. No feedback loop arrow back to the host. Typography must be accurate and readable.
```

Targeted revision:

```text
Preserve the six numbered cards, exact card headers/subtitles, main six-step arrows and labels, title/footer/palette. Remove ALL contents beneath header/subtitle within each of the six cards, including every internal icon, bullet list, extra label and internal arrow. They were unrequested and can imply incorrect technical facts. Replace each card's now-empty lower area with just ONE small simple navy geometric icon (laptop, server, archive, database, gear, document respectively); NO extra text, NO internal arrows. Keep 'SDK retries are best-effort' callout. This must be a clean uncluttered six-step diagram with only the original header/subtitle text and connecting-arrow labels. No invented bullet lists or HTTPS labels.
```
</details>
