-- Local credential auth: Argon2 password hash on users.
-- (OIDC/SSO users keep this NULL and authenticate via oidc_sub instead.)
ALTER TABLE users
    ADD COLUMN password_hash TEXT;
