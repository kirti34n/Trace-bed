-- depends: 0004_lifecycle

-- 0005_bm25.sql — Stage 2: real vchord_bm25 lexical ranking (supersedes the phantom
-- pg_textsearch surface D-050 inferred; see DECISIONS D-140). Extensions
-- (vchord_bm25 + pg_tokenizer) already exist from 0001. This migration adds the two things
-- the ranking arm needs on top of a fresh install:
--   1. a pg_tokenizer tokenizer 'tracebed_lexical' (unicode segmentation + lowercase +
--      english Porter2 stemming, ids via the preloaded bert_base_uncased vocab). Stemming is
--      deliberately the same shape as the 'english' config the `lexemes` tsvector uses, so the
--      ranking arm and the rarity-gate DF source tokenize consistently.
--   2. memory_item.content_bm25 bm25vector — the ranked column the per-partition `bm25`
--      access-method index (stores.pg.ddl) is built on.
-- The per-partition bm25 INDEX is NOT created here: like the HNSW index it is a per-project
-- object built by stores.pg.partitions.create_project_partitions from stores.pg.ddl. A
-- migration only ever creates the empty partitioned parent + this column.
-- No SET search_path needed here: create_text_analyzer/create_tokenizer and the fully
-- qualified tokenize()::bm25_catalog.bm25vector resolve under the default path (verified);
-- only to_bm25query() (read path, stores.pg.search) needs bm25_catalog on the path.

SELECT tokenizer_catalog.create_text_analyzer('tracebed_lexical_analyzer', $$
pre_tokenizer = "unicode_segmentation"
[[character_filters]]
to_lowercase = {}
[[token_filters]]
skip_non_alphanumeric = {}
[[token_filters]]
stemmer = "english_porter2"
$$);

SELECT tokenizer_catalog.create_tokenizer('tracebed_lexical', $$
model = "bert_base_uncased"
text_analyzer = "tracebed_lexical_analyzer"
$$);

ALTER TABLE memory_item ADD COLUMN content_bm25 bm25_catalog.bm25vector;

-- Backfill pre-existing rows (no-op on a fresh install: parent is empty, no partitions). Both
-- columns: the write path populated NEITHER before Stage 2, so historical rows have NULL
-- lexemes and the rarity gate would read df=0 for every term until this runs.
UPDATE memory_item
   SET content_bm25 = tokenizer_catalog.tokenize(content, 'tracebed_lexical')::bm25_catalog.bm25vector,
       lexemes      = to_tsvector('english', content)
 WHERE content_bm25 IS NULL OR lexemes IS NULL;

-- The application connects as tracebed_app (NOBYPASSRLS; migrations/0003_rls.sql) -- the ONLY role
-- for which invariant-4 RLS is actually enforced (the owner bypasses it). Both the write path
-- (stores.pg.repo.insert_memory_item) and the lexical read path (stores.pg.search.lexical_arm /
-- document_frequency) call tokenizer_catalog.tokenize()::bm25_catalog.bm25vector and
-- bm25_catalog.to_bm25query(). Function EXECUTE is already PUBLIC, but that is not enough:
--   * both extension schemas need USAGE (name resolution for the types/functions); and
--   * tokenize() runs SECURITY INVOKER and reads its configuration from tokenizer_catalog's
--     tokenizer/text_analyzer/model tables, so the app needs SELECT on them -- with USAGE only it
--     raises "permission denied for table tokenizer". These are GLOBAL tokenizer config (not
--     project data, not RLS-scoped), so a plain SELECT grant is safe. bm25_catalog has no tables
--     (to_bm25query reads the per-partition bm25 index the app already owns), so USAGE suffices.
-- Without these, EVERY memory INSERT and EVERY lexical search raises InsufficientPrivilege under
-- the role production runs as -- invisible to the owner-DSN test suite, which bypasses ACLs and RLS.
GRANT USAGE ON SCHEMA bm25_catalog TO tracebed_app;
GRANT USAGE ON SCHEMA tokenizer_catalog TO tracebed_app;
GRANT SELECT ON ALL TABLES IN SCHEMA tokenizer_catalog TO tracebed_app;
