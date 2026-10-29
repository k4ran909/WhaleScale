CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
);

CREATE TABLE preauth_keys (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    prefix     TEXT NOT NULL,
    hash       BLOB NOT NULL UNIQUE,
    reusable   INTEGER NOT NULL DEFAULT 0,
    ephemeral  INTEGER NOT NULL DEFAULT 0,
    used       INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE nodes (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name           TEXT NOT NULL,
    machine_key    TEXT NOT NULL UNIQUE,
    ipv4           TEXT NOT NULL UNIQUE,
    ipv6           TEXT NOT NULL UNIQUE,
    os             TEXT NOT NULL DEFAULT '',
    token_hash     BLOB NOT NULL UNIQUE,
    ephemeral      INTEGER NOT NULL DEFAULT 0,
    preauth_key_id INTEGER REFERENCES preauth_keys(id) ON DELETE SET NULL,
    created_at     INTEGER NOT NULL,
    last_seen      INTEGER NOT NULL
);

CREATE UNIQUE INDEX nodes_user_name ON nodes(user_id, name);
