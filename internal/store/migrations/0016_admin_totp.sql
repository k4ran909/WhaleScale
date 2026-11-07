-- Two-factor sign-in for console accounts: a TOTP secret once it's on,
-- the one being set up until its first code checks out, and the last
-- code's time step, so no code works twice.
ALTER TABLE admins ADD COLUMN totp_secret TEXT NOT NULL DEFAULT '';
ALTER TABLE admins ADD COLUMN totp_pending TEXT NOT NULL DEFAULT '';
ALTER TABLE admins ADD COLUMN totp_last INTEGER NOT NULL DEFAULT 0;
