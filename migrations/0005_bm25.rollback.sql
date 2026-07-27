-- Drop the column FIRST (this also drops every per-partition bm25 index built on it), then the
-- tokenizer (depends on the analyzer), then the analyzer. The schemas themselves belong to the
-- 0001 extensions and are not dropped here; undo only the USAGE grants this migration added.
REVOKE SELECT ON ALL TABLES IN SCHEMA tokenizer_catalog FROM tracebed_app;
REVOKE USAGE ON SCHEMA bm25_catalog FROM tracebed_app;
REVOKE USAGE ON SCHEMA tokenizer_catalog FROM tracebed_app;
ALTER TABLE memory_item DROP COLUMN IF EXISTS content_bm25;
SELECT tokenizer_catalog.drop_tokenizer('tracebed_lexical');
SELECT tokenizer_catalog.drop_text_analyzer('tracebed_lexical_analyzer');
