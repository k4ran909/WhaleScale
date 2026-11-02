-- Phase 5: nodes that prove requests with their machine key. Once a node
-- has, its bearer token is refused.
ALTER TABLE nodes ADD COLUMN signed_auth BOOLEAN NOT NULL DEFAULT FALSE;
