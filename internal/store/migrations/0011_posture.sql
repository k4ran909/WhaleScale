-- Phase 4: device posture. What each node last reported about itself.
ALTER TABLE nodes ADD COLUMN os_version TEXT NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN client_version TEXT NOT NULL DEFAULT '';
