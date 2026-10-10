CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE scan_runs (
    id          bigserial PRIMARY KEY,
    node_id     text NOT NULL,
    started_at  timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    targets     text[] NOT NULL,
    ports       integer[] NOT NULL,
    error       text
);

CREATE TABLE observations (
    id          bigserial PRIMARY KEY,
    run_id      bigint NOT NULL REFERENCES scan_runs (id),
    node_id     text NOT NULL,
    ip          inet NOT NULL,
    port        integer NOT NULL,
    name        text NOT NULL,
    protocol    text NOT NULL,
    status      text NOT NULL,
    seen_at     timestamptz NOT NULL DEFAULT now(),
    cert_sha256 text,
    cert_names  text[],
    -- json, not jsonb: banners contain \u0000, which jsonb rejects.
    raw         json NOT NULL,
    -- Ed25519 signature by node_id, filled once federation lands.
    signature   bytea
);

CREATE INDEX observations_ip ON observations USING gist (ip inet_ops);
CREATE INDEX observations_port ON observations (port);
CREATE INDEX observations_host_latest ON observations (ip, port, name, seen_at DESC);
CREATE INDEX observations_cert_sha256 ON observations (cert_sha256);
CREATE INDEX observations_cert_names ON observations USING gin (cert_names);
CREATE INDEX observations_raw_trgm ON observations USING gin ((raw::text) gin_trgm_ops);

CREATE TABLE optouts (
    cidr     cidr PRIMARY KEY,
    contact  text NOT NULL DEFAULT '',
    added_at timestamptz NOT NULL DEFAULT now()
);
