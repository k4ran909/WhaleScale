-- Phase 1: WireGuard and path-discovery keys, candidate endpoints.
ALTER TABLE nodes ADD COLUMN node_key  TEXT NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN disco_key TEXT NOT NULL DEFAULT '';
-- JSON array of "ip:port" strings.
ALTER TABLE nodes ADD COLUMN endpoints TEXT NOT NULL DEFAULT '[]';

-- MagicDNS names are <node>.<suffix>, so node names must be unique across
-- all users, not just within one. Rename any clashes left by Phase 0.
UPDATE nodes SET name = name || '-' || id
WHERE id IN (
    SELECT n.id FROM nodes n
    WHERE EXISTS (SELECT 1 FROM nodes o WHERE o.name = n.name AND o.id < n.id)
);
DROP INDEX nodes_user_name;
CREATE UNIQUE INDEX nodes_name ON nodes(name);
