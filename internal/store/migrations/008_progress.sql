-- The latest signed progress count of each boid, this one included.
CREATE TABLE peer_progress (
    node_id    text PRIMARY KEY,
    counted_at timestamptz NOT NULL,
    progress   bytea NOT NULL,
    signature  bytea NOT NULL
);
