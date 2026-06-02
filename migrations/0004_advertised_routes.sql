-- Subnet routers / exit nodes: CIDRs a device routes for its peers.
-- `0.0.0.0/0` marks an exit node.
ALTER TABLE devices
    ADD COLUMN advertised_routes TEXT[] NOT NULL DEFAULT '{}';
