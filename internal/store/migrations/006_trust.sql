ALTER TABLE peers
    ADD COLUMN trust text NOT NULL DEFAULT 'probation',
    ADD COLUMN low_reach boolean NOT NULL DEFAULT false;

-- Results of other boids that this boid has checked again.
CREATE TABLE samples (
    id            bigserial PRIMARY KEY,
    key           text NOT NULL UNIQUE,
    subject       bytea NOT NULL UNIQUE,
    kind          text NOT NULL,
    scanner       text NOT NULL,
    ip            inet NOT NULL,
    port          integer NOT NULL,
    name          text NOT NULL,
    reported_open boolean NOT NULL,
    reported_fp   text NOT NULL,
    scanned_at    timestamptz NOT NULL,
    evidence      bytea NOT NULL,
    checkers      text[],
    created_at    timestamptz NOT NULL DEFAULT now(),
    decided_at    timestamptz,
    verdict       text
);
CREATE INDEX samples_open ON samples (id) WHERE decided_at IS NULL;
CREATE INDEX samples_scanner ON samples (scanner, decided_at DESC) WHERE decided_at IS NOT NULL;

CREATE TABLE sample_votes (
    sample_id   bigint NOT NULL REFERENCES samples ON DELETE CASCADE,
    checker     text NOT NULL,
    open        boolean NOT NULL,
    fingerprint text NOT NULL,
    unavailable boolean NOT NULL,
    PRIMARY KEY (sample_id, checker)
);

-- Grabs this boid runs for its own samples and for other boids' samples.
CREATE TABLE checks (
    id          bigserial PRIMARY KEY,
    requester   text NOT NULL,
    key         text NOT NULL,
    kind        text NOT NULL,
    scanner     text NOT NULL,
    ip          inet NOT NULL,
    port        integer NOT NULL,
    name        text NOT NULL,
    evidence    bytea NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    done_at     timestamptz,
    open        boolean,
    fingerprint text,
    unavailable boolean,
    UNIQUE (requester, key)
);
CREATE INDEX checks_pending ON checks (id) WHERE done_at IS NULL;
CREATE INDEX checks_target ON checks (ip, port, name, done_at DESC) WHERE done_at IS NOT NULL;
