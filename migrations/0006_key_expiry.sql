-- Key rotation & expiry: when a device's WireGuard key expires (NULL = never).
-- Expired devices are quarantined from the mesh until they rotate.
ALTER TABLE devices
    ADD COLUMN key_expires_at TIMESTAMPTZ;
