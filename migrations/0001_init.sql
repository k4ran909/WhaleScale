-- WhaleScale initial schema.
-- Multi-tenant: every domain table carries tenant_id and is isolated by it.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Tenants (organizations) ---------------------------------------------------
CREATE TABLE tenants (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL UNIQUE,
    dns_suffix  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Users ---------------------------------------------------------------------
CREATE TABLE users (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email       TEXT NOT NULL,
    -- 'owner' | 'admin' | 'member'
    role        TEXT NOT NULL DEFAULT 'member',
    -- external identity provider subject (OIDC sub); null for local accounts
    oidc_sub    TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, email)
);

-- Pre-auth keys for headless / device enrollment ----------------------------
CREATE TABLE auth_keys (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- store only a hash of the key; the raw key is shown once at creation
    key_hash    TEXT NOT NULL UNIQUE,
    reusable    BOOLEAN NOT NULL DEFAULT false,
    ephemeral   BOOLEAN NOT NULL DEFAULT false,
    used_count  INTEGER NOT NULL DEFAULT 0,
    expires_at  TIMESTAMPTZ,
    revoked     BOOLEAN NOT NULL DEFAULT false,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Devices (nodes) -----------------------------------------------------------
CREATE TABLE devices (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    owner_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    hostname     TEXT NOT NULL,
    os           TEXT NOT NULL,
    public_key   TEXT NOT NULL,
    -- assigned overlay address, host form e.g. 100.64.0.5
    overlay_ip   INET NOT NULL,
    -- last reported endpoints (STUN/local), JSON array of Endpoint
    endpoints    JSONB NOT NULL DEFAULT '[]'::jsonb,
    relay_region TEXT,
    last_seen    TIMESTAMPTZ,
    approved     BOOLEAN NOT NULL DEFAULT true,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, public_key),
    UNIQUE (tenant_id, overlay_ip)
);

CREATE INDEX devices_tenant_idx ON devices (tenant_id);

-- ACL policy (one active document per tenant; Tailscale-style allow rules) ---
CREATE TABLE acl_policies (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- HuJSON/JSON policy document
    document    JSONB NOT NULL DEFAULT '{}'::jsonb,
    version     INTEGER NOT NULL DEFAULT 1,
    active      BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX acl_tenant_active_idx ON acl_policies (tenant_id) WHERE active;

-- MagicDNS records ----------------------------------------------------------
CREATE TABLE dns_records (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    record_type TEXT NOT NULL DEFAULT 'A',
    value       TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name, record_type)
);

-- Audit log -----------------------------------------------------------------
CREATE TABLE audit_log (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    actor_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    action      TEXT NOT NULL,
    target      TEXT,
    metadata    JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX audit_tenant_time_idx ON audit_log (tenant_id, created_at DESC);
