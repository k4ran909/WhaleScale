-- Phase 5: API key scopes. "admin" keys can do everything; "read" keys
-- only look (for monitoring and AI agents).
ALTER TABLE api_keys ADD COLUMN scope TEXT NOT NULL DEFAULT 'admin';
