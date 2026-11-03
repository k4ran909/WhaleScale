-- Console accounts with a password, for sign-in without OIDC or an API
-- key. The first one is created in the console with a setup code.
CREATE TABLE admins (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    INTEGER NOT NULL
);
