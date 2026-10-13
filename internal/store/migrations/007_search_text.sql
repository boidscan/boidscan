-- Filled by the application (SearchText); serve backfills older rows in the background.
ALTER TABLE observations ADD COLUMN search_text text;

CREATE INDEX observations_search_text ON observations USING gin (search_text gin_trgm_ops);
CREATE INDEX observations_search_text_pending ON observations (id) WHERE search_text IS NULL;

DROP INDEX observations_raw_trgm;
