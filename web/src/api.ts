// Minimal Connect-RPC (JSON) client for AdminService. Field names follow
// protobuf's JSON mapping: lowerCamelCase, 64-bit ints as strings,
// timestamps as RFC 3339 strings.

export class ApiError extends Error {
  constructor(public code: string, message: string) {
    super(message);
  }
}

async function call<T>(method: string, body: object = {}): Promise<T> {
  const res = await fetch(`/whalescale.v1.AdminService/${method}`, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", "Connect-Protocol-Version": "1" },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : {};
  if (!res.ok) {
    throw new ApiError(data.code ?? String(res.status), data.message ?? res.statusText);
  }
  return data as T;
}

export interface Node {
  id: string;
  name: string;
  user: string;
  addresses?: string[];
  os?: string;
  createdAt?: string;
  lastSeen?: string;
  ephemeral?: boolean;
  nodeKey?: string;
  endpoints?: string[];
  online?: boolean;
  fqdn?: string;
  routes?: string[];
  advertisedRoutes?: string[];
  exitNode?: boolean;
  osVersion?: string;
  clientVersion?: string;
}

export interface User {
  id: string;
  name: string;
  email?: string;
  createdAt?: string;
  nodeCount?: number;
  // From the policy's device_limits; absent means no limit.
  deviceLimit?: number;
}

export interface PreAuthKey {
  id: string;
  prefix: string;
  user: string;
  reusable?: boolean;
  ephemeral?: boolean;
  used?: boolean;
  expiresAt?: string;
  createdAt?: string;
  valid?: boolean;
}

export interface APIKey {
  id: string;
  prefix: string;
  scope?: "admin" | "read";
  createdAt?: string;
  expiresAt?: string;
  lastUsed?: string;
  valid?: boolean;
}

export interface Route {
  nodeId: string;
  nodeName: string;
  prefix: string;
  approved?: boolean;
  exitNode?: boolean;
}

export interface Exposure {
  nodeId: string;
  nodeName: string;
  name: string;
  port: number;
  approved?: boolean;
  url?: string;
  connected?: boolean;
}

export interface PeerRelay {
  nodeId: string;
  nodeName: string;
  approved?: boolean;
  online?: boolean;
}

export interface Recording {
  id: string;
  nodeName: string;
  localUser: string;
  srcNode: string;
  srcUser: string;
  startedAt?: string;
  endedAt?: string;
  size?: string;
}

export interface Flow {
  nodeName: string;
  proto: number;
  client: string;
  clientName?: string;
  server: string;
  serverName?: string;
  port?: number;
  outbound?: boolean;
  denied?: boolean;
  start?: string;
  end?: string;
  bytesSent?: string;
  bytesRecv?: string;
}

export interface AccessRequest {
  id: string;
  nodeName: string;
  user: string;
  dst: string;
  durationSeconds?: string;
  reason?: string;
  status: "pending" | "approved" | "denied" | "revoked" | "expired";
  requestedAt?: string;
  decidedBy?: string;
  decidedAt?: string;
  expiresAt?: string;
}

export interface AuditEvent {
  id: string;
  at?: string;
  actor: string;
  action: string;
  detail?: string;
}

export interface AuditVerification {
  ok?: boolean;
  checked?: number;
  headHash?: string;
  brokenAt?: string;
}

export interface PathReport {
  fromNode: string;
  toNode: string;
  path: "direct" | "peer-relay" | "relay" | "none";
  addr?: string;
  latencyMs?: number;
  updatedAt?: string;
}

export const api = {
  whoAmI: () => call<{ method: string; identity: string; oidcEnabled?: boolean }>("WhoAmI"),
  listNodes: () => call<{ nodes?: Node[] }>("ListNodes").then((r) => r.nodes ?? []),
  deleteNode: (id: string) => call("DeleteNode", { id }),
  listUsers: () => call<{ users?: User[] }>("ListUsers").then((r) => r.users ?? []),
  createUser: (name: string) => call("CreateUser", { name }),
  deleteUser: (name: string) => call("DeleteUser", { name }),
  listPreAuthKeys: () => call<{ keys?: PreAuthKey[] }>("ListPreAuthKeys").then((r) => r.keys ?? []),
  createPreAuthKey: (user: string, reusable: boolean, ephemeral: boolean, expirationSeconds: number) =>
    call<{ key: PreAuthKey; secret: string; joinCode?: string; joinCodeQr?: string }>("CreatePreAuthKey", { user, reusable, ephemeral, expirationSeconds }),
  expirePreAuthKey: (prefix: string) => call("ExpirePreAuthKey", { prefix }),
  listAPIKeys: () => call<{ keys?: APIKey[] }>("ListAPIKeys").then((r) => r.keys ?? []),
  createAPIKey: (expirationSeconds: number, scope: "admin" | "read" = "admin") =>
    call<{ key: APIKey; secret: string }>("CreateAPIKey", { expirationSeconds, scope }),
  expireAPIKey: (prefix: string) => call("ExpireAPIKey", { prefix }),
  getPolicy: () =>
    call<{
      policy: string;
      source: string;
      editable?: boolean;
      syncUrl?: string;
      lastSync?: string;
      revision?: string;
      syncError?: string;
    }>("GetPolicy"),
  checkPolicy: (policy: string) => call<{ errors?: string[]; warnings?: string[] }>("CheckPolicy", { policy }),
  setPolicy: (policy: string) => call<{ warnings?: string[] }>("SetPolicy", { policy }),
  explainAccess: (src: string, dst: string, policy?: string) =>
    call<{ allowed?: boolean; reasons?: string[] }>("ExplainAccess", { src, dst, policy }),
  listRoutes: () => call<{ routes?: Route[] }>("ListRoutes").then((r) => r.routes ?? []),
  setRouteApproved: (nodeId: string, prefix: string, approved: boolean) =>
    call("SetRouteApproved", { nodeId, prefix, approved }),
  topology: () => call<{ paths?: PathReport[] }>("GetTopology").then((r) => r.paths ?? []),
  listPeerRelays: () => call<{ relays?: PeerRelay[] }>("ListPeerRelays").then((r) => r.relays ?? []),
  setPeerRelayApproved: (nodeId: string, approved: boolean) => call("SetPeerRelayApproved", { nodeId, approved }),
  queryFlows: (q: { node?: string; sinceSeconds?: number; deniedOnly?: boolean; limit?: number }) =>
    call<{ flows?: Flow[]; enabled?: boolean }>("QueryFlows", q).then((r) => ({ flows: r.flows ?? [], enabled: !!r.enabled })),
  listAccessRequests: (includeClosed: boolean) =>
    call<{ requests?: AccessRequest[] }>("ListAccessRequests", { includeClosed }).then((r) => r.requests ?? []),
  decideAccess: (id: string, approve: boolean) => call("DecideAccess", { id, approve }),
  revokeAccess: (id: string) => call("RevokeAccess", { id }),
  listAuditEvents: (q: { sinceSeconds?: number; actor?: string; action?: string; limit?: number; verify?: boolean }) =>
    call<{ events?: AuditEvent[]; verification?: AuditVerification }>("ListAuditEvents", q).then((r) => ({
      events: r.events ?? [],
      verification: r.verification,
    })),
  listRecordings: () => call<{ recordings?: Recording[] }>("ListRecordings").then((r) => r.recordings ?? []),
  // data is base64 (protobuf JSON for bytes).
  getRecording: (id: string) => call<{ recording: Recording; data?: string }>("GetRecording", { id }),
  deleteRecording: (id: string) => call("DeleteRecording", { id }),
  listExposures: () =>
    call<{ exposures?: Exposure[]; gatewayDomain?: string }>("ListExposures").then((r) => ({
      exposures: r.exposures ?? [],
      domain: r.gatewayDomain ?? "",
    })),
  setExposureApproved: (nodeId: string, name: string, approved: boolean) =>
    call("SetExposureApproved", { nodeId, name, approved }),
};

// ---------- sign-in (plain HTTP endpoints, not AdminService) ----------

export interface AuthStatus {
  // No admin account yet: the console shows first-run setup.
  setup: boolean;
  oidc: boolean;
  publicUrl: string;
}

export async function authStatus(): Promise<AuthStatus> {
  const res = await fetch("/auth/status", { credentials: "same-origin", cache: "no-store" });
  if (!res.ok) throw new ApiError(String(res.status), "The server is not answering; try again in a moment.");
  return res.json();
}

async function postAuth(path: string, body: object) {
  const res = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = (await res.text()).trim();
    // The password was right, and the account needs its authenticator code.
    if (res.headers.get("X-Whalescale-Two-Factor") === "required") throw new ApiError("two-factor", text);
    throw new ApiError(res.status === 401 ? "unauthenticated" : String(res.status), text || "Request failed");
  }
  return res;
}

export const setupAdmin = (code: string, name: string, password: string) => postAuth("/auth/setup", { code, name, password });
export const loginWithPassword = (name: string, password: string, code = "") =>
  postAuth("/auth/password", { name, password, code });

/** Two-factor sign-in for password accounts ("available" is false for
 * OIDC and API key sessions). */
export async function twoFactorStatus(): Promise<{ available: boolean; enabled: boolean }> {
  const res = await fetch("/auth/2fa", { credentials: "same-origin" });
  if (!res.ok) throw new ApiError(String(res.status), (await res.text()).trim() || "Request failed");
  return res.json();
}
/** Starts setup: a new secret as text, an otpauth:// link and a QR code (SVG). */
export const twoFactorSetup = (password: string) =>
  postAuth("/auth/2fa/setup", { password }).then((r) => r.json() as Promise<{ secret: string; uri: string; qr: string }>);
export const twoFactorEnable = (code: string) => postAuth("/auth/2fa/enable", { code });
export const twoFactorDisable = (password: string, code: string) => postAuth("/auth/2fa/disable", { password, code });
export const loginWithAPIKey = (key: string) => postAuth("/auth/apikey", { key });
export const changePassword = (current: string, next: string) =>
  postAuth("/auth/password/change", { current, new: next });

export async function logout() {
  await fetch("/auth/logout", { method: "POST", credentials: "same-origin" });
}
