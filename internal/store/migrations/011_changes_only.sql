-- A row now stands for one version of a service as one boid saw it: from
-- first_seen_at to seen_at, holding the newest signed result of that version.
-- seq orders rows for replication and moves forward when a row is seen again.
-- Existing rows keep NULL in all three, so the table is not rewritten: reads
-- fall back to seen_at and id, and seq starts above every existing id.
ALTER TABLE observations ADD COLUMN first_seen_at timestamptz, ADD COLUMN change_key text, ADD COLUMN seq bigint;
CREATE SEQUENCE observations_seq OWNED BY observations.seq;
SELECT setval('observations_seq', (SELECT coalesce(max(id), 0) + 1 FROM observations), false);
CREATE INDEX observations_by_seq ON observations (seq) WHERE seq IS NOT NULL;
