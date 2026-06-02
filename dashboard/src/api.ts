// API client for the WhaleScale coordinator admin endpoints.
//
// Set VITE_DEMO=1 (e.g. `VITE_DEMO=1 pnpm dev`) to render the dashboard with
// sample data when no coordinator/DB is running.

export type Tenant = {
  id: string;
  name: string;
  slug: string;
  device_count: number;
};

export type Device = {
  id: string;
  hostname: string;
  os: string;
  overlay_ip: string;
  online: boolean;
  last_seen: string | null;
  connectivity: "direct" | "relay";
  relay_region: string | null;
  endpoint_count: number;
  approved: boolean;
  key_expires_at: string | null;
};

export type AuditEntry = {
  action: string;
  target: string | null;
  created_at: string;
};

export const DEMO = import.meta.env.VITE_DEMO === "1";

// --- session token --------------------------------------------------------

const TOKEN_KEY = "ws.token";
export const getToken = () => localStorage.getItem(TOKEN_KEY);
export const setToken = (t: string) => localStorage.setItem(TOKEN_KEY, t);
export const clearToken = () => localStorage.removeItem(TOKEN_KEY);

function authHeaders(): Record<string, string> {
  const t = getToken();
  return t ? { authorization: `Bearer ${t}` } : {};
}

export class UnauthorizedError extends Error {}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`/api${path}`, { headers: authHeaders() });
  if (res.status === 401) throw new UnauthorizedError("unauthorized");
  if (!res.ok) throw new Error(`${path}: HTTP ${res.status}`);
  return res.json() as Promise<T>;
}

export type Session = {
  token: string;
  user_id: string;
  tenant_id: string;
  email: string;
  role: "owner" | "admin" | "member";
};

/** Log in; stores the token and returns the session. */
export async function login(email: string, password: string): Promise<Session> {
  const res = await fetch("/api/admin/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  if (res.status === 401) throw new Error("Invalid email or password");
  if (!res.ok) throw new Error(`login: HTTP ${res.status}`);
  const session = (await res.json()) as Session;
  setToken(session.token);
  return session;
}

export async function fetchTenants(): Promise<Tenant[]> {
  if (DEMO) return demoTenants;
  return get<Tenant[]>("/admin/tenants");
}

export async function fetchDevices(tenantId: string): Promise<Device[]> {
  if (DEMO) return demoDevices;
  return get<Device[]>(`/admin/tenants/${tenantId}/devices`);
}

export async function fetchAudit(tenantId: string): Promise<AuditEntry[]> {
  if (DEMO) return demoAudit;
  return get<AuditEntry[]>(`/admin/tenants/${tenantId}/audit`);
}

export type LatencyEntry = {
  device_id: string;
  hostname: string | null;
  last_ms: number | null;
  avg_ms: number | null;
  p95_ms: number | null;
  samples: number[];
  tx_bps: number;
  rx_bps: number;
};

export async function fetchLatency(tenantId: string): Promise<LatencyEntry[]> {
  if (DEMO) return demoLatency;
  return get<LatencyEntry[]>(`/admin/tenants/${tenantId}/latency`);
}

export async function deleteDevice(deviceId: string): Promise<void> {
  if (DEMO) return;
  const res = await fetch(`/api/admin/devices/${deviceId}`, {
    method: "DELETE",
    headers: authHeaders(),
  });
  if (!res.ok) throw new Error(`delete device: HTTP ${res.status}`);
}

export async function approveDevice(deviceId: string): Promise<void> {
  if (DEMO) return;
  const res = await fetch(`/api/admin/devices/${deviceId}/approve`, {
    method: "POST",
    headers: authHeaders(),
  });
  if (!res.ok) throw new Error(`approve device: HTTP ${res.status}`);
}

export async function fetchAcl(tenantId: string): Promise<unknown> {
  if (DEMO) return demoAcl;
  return get<unknown>(`/admin/tenants/${tenantId}/acl`);
}

/** Returns null on success, or the server's validation error message. */
export async function saveAcl(tenantId: string, doc: unknown): Promise<string | null> {
  if (DEMO) return null;
  const res = await fetch(`/api/admin/tenants/${tenantId}/acl`, {
    method: "PUT",
    headers: { "content-type": "application/json", ...authHeaders() },
    body: JSON.stringify(doc),
  });
  if (res.ok) return null;
  const body = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
  return body.error ?? `HTTP ${res.status}`;
}

// --- auth keys ------------------------------------------------------------

export type AuthKey = {
  id: string;
  key_prefix: string | null;
  reusable: boolean;
  ephemeral: boolean;
  require_approval: boolean;
  used_count: number;
  revoked: boolean;
  expires_at: string | null;
  created_at: string;
};

export type CreateAuthKeyReq = {
  reusable: boolean;
  ephemeral: boolean;
  require_approval: boolean;
  expires_in_days: number | null;
};

export type CreatedAuthKey = {
  id: string;
  auth_key: string;
  expires_at: string | null;
};

export async function fetchAuthKeys(tenantId: string): Promise<AuthKey[]> {
  if (DEMO) return demoAuthKeys;
  return get<AuthKey[]>(`/admin/tenants/${tenantId}/authkeys`);
}

export async function createAuthKey(
  tenantId: string,
  req: CreateAuthKeyReq,
): Promise<CreatedAuthKey> {
  if (DEMO) {
    return {
      id: crypto.randomUUID(),
      auth_key: `ws-${crypto.randomUUID().replace(/-/g, "").slice(0, 48)}`,
      expires_at: req.expires_in_days
        ? new Date(Date.now() + req.expires_in_days * 86400_000).toISOString()
        : null,
    };
  }
  const res = await fetch(`/api/admin/tenants/${tenantId}/authkeys`, {
    method: "POST",
    headers: { "content-type": "application/json", ...authHeaders() },
    body: JSON.stringify(req),
  });
  if (!res.ok) throw new Error(`create auth key: HTTP ${res.status}`);
  return res.json() as Promise<CreatedAuthKey>;
}

export async function revokeAuthKey(keyId: string): Promise<void> {
  if (DEMO) return;
  const res = await fetch(`/api/admin/authkeys/${keyId}/revoke`, {
    method: "POST",
    headers: authHeaders(),
  });
  if (!res.ok) throw new Error(`revoke auth key: HTTP ${res.status}`);
}

// --- demo data ------------------------------------------------------------

const demoTenants: Tenant[] = [
  { id: "demo-tenant", name: "Dev Org", slug: "dev", device_count: 4 },
  { id: "acme", name: "Acme Inc", slug: "acme", device_count: 2 },
];

const demoDevices: Device[] = [
  { id: "d1", hostname: "laptop-rohit", os: "windows", overlay_ip: "100.64.0.1", online: true, last_seen: new Date().toISOString(), connectivity: "direct", relay_region: null, endpoint_count: 2, approved: true, key_expires_at: null },
  { id: "d2", hostname: "macbook-air", os: "macos", overlay_ip: "100.64.0.2", online: true, last_seen: new Date().toISOString(), connectivity: "direct", relay_region: null, endpoint_count: 2, approved: true, key_expires_at: null },
  { id: "d3", hostname: "prod-server-1", os: "linux", overlay_ip: "100.64.0.3", online: true, last_seen: new Date().toISOString(), connectivity: "relay", relay_region: "local", endpoint_count: 0, approved: true, key_expires_at: new Date(Date.now() + 5 * 86400_000).toISOString() },
  { id: "d4", hostname: "pixel-phone", os: "android", overlay_ip: "100.64.0.4", online: false, last_seen: new Date(Date.now() - 3600_000).toISOString(), connectivity: "relay", relay_region: "local", endpoint_count: 0, approved: true, key_expires_at: null },
  { id: "d5", hostname: "new-thinkpad", os: "linux", overlay_ip: "100.64.0.5", online: true, last_seen: new Date().toISOString(), connectivity: "direct", relay_region: null, endpoint_count: 1, approved: false, key_expires_at: null },
];

const demoAcl = {
  groups: { "group:eng": ["rohit@thapar.edu", "admin@dev"] },
  acls: [
    { action: "accept", src: ["group:eng"], dst: ["tag:server:22,443"] },
    { action: "accept", src: ["*"], dst: ["*:*"] },
  ],
};

function wobble(base: number, n: number): number[] {
  return Array.from({ length: n }, (_, i) => Math.round(base + 6 * Math.sin(i / 2) + (i % 3)));
}

const demoLatency: LatencyEntry[] = [
  { device_id: "d1", hostname: "laptop-rohit", last_ms: 18, avg_ms: 19.4, p95_ms: 27, samples: wobble(18, 30), tx_bps: 1_240_000, rx_bps: 880_000 },
  { device_id: "d2", hostname: "macbook-air", last_ms: 24, avg_ms: 25.1, p95_ms: 33, samples: wobble(24, 30), tx_bps: 410_000, rx_bps: 2_100_000 },
  { device_id: "d3", hostname: "prod-server-1", last_ms: 41, avg_ms: 44.8, p95_ms: 58, samples: wobble(42, 30), tx_bps: 5_600_000, rx_bps: 3_300_000 },
];

const demoAudit: AuditEntry[] = [
  { action: "device.enroll", target: "d4", created_at: new Date(Date.now() - 3600_000).toISOString() },
  { action: "device.enroll", target: "d3", created_at: new Date(Date.now() - 7200_000).toISOString() },
];

const demoAuthKeys: AuthKey[] = [
  { id: "k1", key_prefix: "ws-1a2b3c4d", reusable: true, ephemeral: false, require_approval: false, used_count: 3, revoked: false, expires_at: null, created_at: new Date(Date.now() - 5 * 86400_000).toISOString() },
  { id: "k2", key_prefix: "ws-9f8e7d6c", reusable: false, ephemeral: true, require_approval: true, used_count: 1, revoked: false, expires_at: new Date(Date.now() + 60 * 86400_000).toISOString(), created_at: new Date(Date.now() - 2 * 86400_000).toISOString() },
  { id: "k3", key_prefix: "ws-deadbeef", reusable: false, ephemeral: false, require_approval: false, used_count: 1, revoked: true, expires_at: null, created_at: new Date(Date.now() - 12 * 86400_000).toISOString() },
];
