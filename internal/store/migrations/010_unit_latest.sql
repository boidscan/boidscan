-- Only the newest coverage of each unit by each boid is read; older rows only grow the table.
DELETE FROM coverage c WHERE EXISTS (SELECT 1 FROM coverage n WHERE n.block = c.block AND n.port_group = c.port_group
    AND n.node_id = c.node_id AND n.scanned_at > c.scanned_at);

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
