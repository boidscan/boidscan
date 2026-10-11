-- Node records are signed in the v2 format now; v1 peers are found again through gossip.
DELETE FROM peers;
ALTER TABLE peers
    ADD COLUMN root text NOT NULL DEFAULT '',
    ADD COLUMN policy_serial bigint NOT NULL DEFAULT 0,
    ADD COLUMN emergency_pause boolean NOT NULL DEFAULT false;

CREATE TABLE policies (
    serial      bigint PRIMARY KEY,
    document    bytea NOT NULL,
    expires_at  timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE policy_pauses (
    serial      bigint PRIMARY KEY,
    document    bytea NOT NULL,
    expires_at  timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now()
);
