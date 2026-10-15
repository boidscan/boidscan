-- The newest coverage of each unit, so status reads do not walk the coverage history.
CREATE TABLE unit_latest (
    block      cidr NOT NULL,
    port_group integer NOT NULL,
    scanned_at timestamptz NOT NULL,
    node_id    text NOT NULL,
    PRIMARY KEY (block, port_group)
);

INSERT INTO unit_latest
SELECT DISTINCT ON (block, port_group) block, port_group, scanned_at, node_id
FROM coverage ORDER BY block, port_group, scanned_at DESC;
