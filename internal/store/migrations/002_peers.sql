CREATE TABLE peers (
    id          text PRIMARY KEY,
    name        text NOT NULL,
    endpoint    text NOT NULL,
    contact     text NOT NULL,
    project_url text NOT NULL,
    version     text NOT NULL,
    record_time timestamptz NOT NULL,
    signature   bytea NOT NULL,
    first_seen  timestamptz NOT NULL DEFAULT now(),
    verified_at timestamptz,
    state       text NOT NULL DEFAULT 'new'
);
