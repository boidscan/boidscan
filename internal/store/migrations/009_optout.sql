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
CREATE INDEX optouts_ip ON optouts (ip, signed_at DESC, signature DESC);
CREATE INDEX optouts_signer ON optouts (signer, signed_at);
CREATE INDEX optouts_signed_at ON optouts (signed_at);

-- The newest attestation of each signer this boid has read from peers.
CREATE TABLE optout_cursors (
    signer text PRIMARY KEY,
    after  timestamptz NOT NULL
);
