-- Phase 2: admin API keys, web console sessions, OIDC users, subnet routes.

ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN oidc_subject TEXT;
CREATE UNIQUE INDEX users_oidc_subject ON users(oidc_subject) WHERE oidc_subject IS NOT NULL;

CREATE TABLE api_keys (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    prefix     TEXT NOT NULL UNIQUE,
    hash       BLOB NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    last_used  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE sessions (
    hash       BLOB PRIMARY KEY,
    identity   TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

-- One row per (node, prefix) ever advertised. Approval survives a node
-- briefly withdrawing a route, so re-advertising needs no new approval.
CREATE TABLE routes (
    node_id    INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    prefix     TEXT NOT NULL,
    advertised INTEGER NOT NULL DEFAULT 1,
    approved   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (node_id, prefix)
);
