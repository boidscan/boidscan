ALTER TABLE peers ADD COLUMN catalog text NOT NULL DEFAULT '';

-- Rows pushed by other boids have no local run.
ALTER TABLE observations ALTER COLUMN run_id DROP NOT NULL;
CREATE UNIQUE INDEX observations_signature ON observations (signature);

ALTER TABLE scan_runs ADD COLUMN block cidr, ADD COLUMN port_group integer;
CREATE INDEX scan_runs_unit ON scan_runs (block, port_group, started_at DESC) WHERE block IS NOT NULL;

CREATE TABLE coverage (
    id         bigserial PRIMARY KEY,
    block      cidr NOT NULL,
    port_group integer NOT NULL,
    catalog    text NOT NULL,
    node_id    text NOT NULL,
    scanned_at timestamptz NOT NULL,
    signature  bytea NOT NULL UNIQUE
);
CREATE INDEX coverage_unit ON coverage (block, port_group, scanned_at DESC);

CREATE TABLE leases (
    block      cidr NOT NULL,
    port_group integer NOT NULL,
    holder     text NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (block, port_group)
);

CREATE TABLE replicas (
    home_id    text PRIMARY KEY,
    view       text[] NOT NULL,
    obs_id     bigint NOT NULL,
    cov_id     bigint NOT NULL,
    catch_up   boolean NOT NULL,
    old_view   text[] NOT NULL,
    old_obs_id bigint NOT NULL,
    old_cov_id bigint NOT NULL
);
