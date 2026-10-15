-- Hosts that asked, from their own address, not to be scanned. Each row is
-- signed by the boid that took the request and replicated to every boid.
CREATE TABLE optouts (
    id         bigserial PRIMARY KEY,
    ip         inet NOT NULL,
    action     text NOT NULL,
    expires_at timestamptz NOT NULL,
    signer     text NOT NULL,
    signed_at  timestamptz NOT NULL,
    signature  bytea NOT NULL UNIQUE
);
CREATE INDEX optouts_ip ON optouts (ip, signed_at DESC);
CREATE INDEX optouts_signer ON optouts (signer, signed_at);
CREATE INDEX optouts_signed_at ON optouts (signed_at);

-- How far this boid has read each peer's opt-out log.
CREATE TABLE optout_cursors (
    peer_id text PRIMARY KEY,
    after   bigint NOT NULL
);
