-- A row now stands for one version of a service as one boid saw it: from
-- first_seen_at to seen_at, holding the newest signed result of that version.
-- seq orders rows for replication and moves forward when a row is seen again.
ALTER TABLE observations ADD COLUMN first_seen_at timestamptz, ADD COLUMN change_key text, ADD COLUMN seq bigint;
UPDATE observations SET first_seen_at = seen_at, seq = id;
ALTER TABLE observations ALTER COLUMN first_seen_at SET NOT NULL, ALTER COLUMN seq SET NOT NULL;
CREATE SEQUENCE observations_seq OWNED BY observations.seq;
SELECT setval('observations_seq', (SELECT coalesce(max(id), 0) + 1 FROM observations), false);
ALTER TABLE observations ALTER COLUMN seq SET DEFAULT nextval('observations_seq');
CREATE INDEX observations_by_seq ON observations (seq);
CREATE INDEX observations_series ON observations (ip, port, name, node_id, seen_at DESC);
