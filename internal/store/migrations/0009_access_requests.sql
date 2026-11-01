-- Phase 4: time-limited access. A request for one node, approved (or not)
-- by an admin; an approved request is a grant until expires_at.
CREATE TABLE access_requests (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id      INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    dst          TEXT NOT NULL,
    duration     INTEGER NOT NULL,
    reason       TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL,
    requested_at INTEGER NOT NULL,
    decided_by   TEXT NOT NULL DEFAULT '',
    decided_at   INTEGER NOT NULL DEFAULT 0,
    expires_at   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX access_requests_status ON access_requests(status, expires_at);
