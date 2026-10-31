-- Phase 3: services published through the gateway.
-- Names are global (they become <name>.<gateway domain>). Like routes,
-- approval survives a node briefly withdrawing an exposure.
CREATE TABLE exposures (
    node_id    INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    name       TEXT NOT NULL UNIQUE,
    port       INTEGER NOT NULL,
    advertised INTEGER NOT NULL DEFAULT 1,
    approved   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (node_id, name)
);
