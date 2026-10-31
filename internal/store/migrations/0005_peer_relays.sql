-- Phase 3: nodes that relay UDP for peers that can't connect directly.
-- Like routes, approval survives a node briefly withdrawing its offer.
ALTER TABLE nodes ADD COLUMN relay_offered  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE nodes ADD COLUMN relay_approved INTEGER NOT NULL DEFAULT 0;
