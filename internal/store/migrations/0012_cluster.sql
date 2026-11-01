-- Phase 4: several servers sharing one database. Each running server
-- heartbeats a row; presence says which nodes hold a map stream on which
-- server; leases elect one server for periodic jobs; change_seq lets
-- servers tell each other that something changed.
CREATE TABLE servers (
    id         TEXT PRIMARY KEY,
    public_url TEXT NOT NULL,
    relay_url  TEXT NOT NULL,
    quic_addr  TEXT NOT NULL DEFAULT '',
    started_at INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL
);
CREATE TABLE presence (
    node_id   INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    server_id TEXT NOT NULL,
    PRIMARY KEY (node_id, server_id)
);
CREATE TABLE leases (
    name       TEXT PRIMARY KEY,
    holder     TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE change_seq (
    id  INTEGER PRIMARY KEY,
    seq INTEGER NOT NULL
);
INSERT INTO change_seq(id, seq) VALUES (1, 0);
