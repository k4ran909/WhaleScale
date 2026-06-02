-- Store a short, non-sensitive prefix of each auth key (e.g. "ws-1a2b3c4d") so
-- the dashboard can list and identify keys without ever revealing the secret.
-- Only the SHA-256 hash is kept for verification; the prefix discloses nothing
-- useful on its own.
ALTER TABLE auth_keys
    ADD COLUMN key_prefix TEXT;
