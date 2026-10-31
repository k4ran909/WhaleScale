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
}

export interface User {
  id: string;
  name: string;
  email?: string;
  createdAt?: string;
  nodeCount?: number;
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

export interface PathReport {
  fromNode: string;
  toNode: string;
  path: "direct" | "relay" | "none";
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
    call<{ key: PreAuthKey; secret: string }>("CreatePreAuthKey", { user, reusable, ephemeral, expirationSeconds }),
  expirePreAuthKey: (prefix: string) => call("ExpirePreAuthKey", { prefix }),
  listAPIKeys: () => call<{ keys?: APIKey[] }>("ListAPIKeys").then((r) => r.keys ?? []),
  createAPIKey: (expirationSeconds: number) => call<{ key: APIKey; secret: string }>("CreateAPIKey", { expirationSeconds }),
  expireAPIKey: (prefix: string) => call("ExpireAPIKey", { prefix }),
  getPolicy: () => call<{ policy: string; source: string; editable?: boolean }>("GetPolicy"),
  checkPolicy: (policy: string) => call<{ errors?: string[]; warnings?: string[] }>("CheckPolicy", { policy }),
  setPolicy: (policy: string) => call<{ warnings?: string[] }>("SetPolicy", { policy }),
  listRoutes: () => call<{ routes?: Route[] }>("ListRoutes").then((r) => r.routes ?? []),
  setRouteApproved: (nodeId: string, prefix: string, approved: boolean) =>
    call("SetRouteApproved", { nodeId, prefix, approved }),
  topology: () => call<{ paths?: PathReport[] }>("GetTopology").then((r) => r.paths ?? []),
  listExposures: () =>
    call<{ exposures?: Exposure[]; gatewayDomain?: string }>("ListExposures").then((r) => ({
      exposures: r.exposures ?? [],
      domain: r.gatewayDomain ?? "",
    })),
  setExposureApproved: (nodeId: string, name: string, approved: boolean) =>
    call("SetExposureApproved", { nodeId, name, approved }),
};

export async function loginWithAPIKey(key: string) {
  const res = await fetch("/auth/apikey", {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ key }),
  });
  if (!res.ok) throw new ApiError("unauthenticated", (await res.text()).trim() || "Sign-in failed");
}

export async function logout() {
  await fetch("/auth/logout", { method: "POST", credentials: "same-origin" });
}
