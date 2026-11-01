-- Phase 4: audit log. Append-only; each row's hash covers the previous
-- row's hash, so editing or deleting a row breaks the chain.
CREATE TABLE audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    at        INTEGER NOT NULL,
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    detail    TEXT NOT NULL DEFAULT '',
    prev_hash BLOB NOT NULL,
    hash      BLOB NOT NULL
);
CREATE INDEX audit_log_at ON audit_log(at);
