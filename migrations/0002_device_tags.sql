-- Device tags, used by the ACL policy engine for `tag:*` selectors.
ALTER TABLE devices
    ADD COLUMN tags TEXT[] NOT NULL DEFAULT '{}';
