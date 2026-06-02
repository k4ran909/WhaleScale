# 🐋 WhaleScale — Full Engineering Plan

> **Reconciled 2026-06-02 to the implemented stack.** This document was originally
> drafted around a Go + Next.js + coturn design. The project was built — by deliberate
> decision at kickoff — in **Rust (axum + boringtun) + React/Vite**, with a **from-scratch
> STUN** codec and a **custom DERP-style relay** (no TURN/coturn). Every technical detail
> below now reflects the actual codebase; the earlier Go/Next.js draft is superseded.
> The authoritative status of each component lives in `README.md`.

## 1. Vision
WhaleScale is a low-latency, decentralized mesh VPN platform similar to Tailscale, built on
WireGuard. It enables secure, peer-to-peer communication between devices across different
networks using NAT traversal (STUN + hole punching) with a relay fallback for strict NATs.

---

## 2. Core Objectives
- Secure communication using WireGuard (end-to-end encrypted, zero-trust data plane)
- Automatic peer discovery via a from-scratch control plane
- NAT traversal: STUN reflexive-endpoint discovery + UDP hole punching
- DERP-style encrypted relay fallback (not TURN) for strict/symmetric NAT
- Centralized control plane (source of truth, never sees plaintext traffic)
- Distributed data plane (direct peer-to-peer WireGuard tunnels)
- Multi-tenant SaaS: isolated orgs, RBAC, ACLs
- Cross-platform client support (Linux, Windows, macOS, iOS, Android)

---

## 3. High-Level Architecture

```
                       ┌──────────────────────────────┐
                       │   Coordinator (Rust / axum)   │   control plane
   enroll / poll       │  - auth: authkeys + JWT, RBAC │
   ┌──────────────────▶│  - tenants, users, devices    │◀─────────────────┐
   │   network map      │  - WG *public* key registry   │   network map    │
   │   (WebSocket)      │  - overlay IP allocation      │   (WebSocket)    │
   │                    │  - ACL policy engine          │                  │
   │                    │  - MagicDNS source data       │                  │
   │                    └───────────────┬──────────────┘                  │
   │                          Postgres  │  Redis (pub/sub, partial)        │
   │                                                                       │
┌──┴───────────┐                                                  ┌────────┴─────┐
│  Node Agent  │   1. STUN  ─────▶  ┌──────────┐                  │  Node Agent  │
│   (Rust)     │   discover public  │  STUN    │                  │   (Rust)     │
│  boringtun   │   endpoint         │  server  │                  │  boringtun   │
│  WireGuard   │◀──────────────────▶└──────────┘ ◀───────────────▶│  WireGuard   │
└──────┬───────┘                                                  └──────┬───────┘
       │            2. direct hole-punched WireGuard tunnel (UDP)        │
       └────────────────────────────────────────────────────────────────┘
                    3. fallback: encrypted relay if direct fails
                       ┌──────────────────────────────────────┐
                       │  DERP-style Relay (Rust WebSocket)    │
                       └──────────────────────────────────────┘
```

### 3.1 Control Plane (`crates/coordinator`)
Handles:
- Authentication: pre-auth keys for headless enrollment + signed **JWT** sessions
- Device registration (stores **public** keys only)
- Overlay IP allocation from `100.64.0.0/10`
- Peer coordination + network-map computation, pushed to agents over WebSocket
- ACL policy engine, RBAC (owner/admin/member), tenant isolation

Tech:
- **Rust + axum** (tokio) HTTP/WebSocket API
- **PostgreSQL** via `sqlx` (async, compile-time-checked queries, `sqlx migrate`)
- **Redis** pub/sub for cross-instance map fanout *(partial — single-instance works today)*

### 3.2 Data Plane
- Direct peer-to-peer **WireGuard** tunnels (UDP), end-to-end encrypted
- **boringtun** userspace WireGuard in the shared agent core (cross-platform, incl. Windows)
- Kernel WireGuard via a `wg-quick` backend on Linux/macOS for performance

### 3.3 NAT Traversal Layer

#### STUN (`crates/stun`, `crates/stun-server`)
- **From-scratch RFC 5389** codec + STUN server (no external STUN dependency)
- Agent discovers its public reflexive `IP:port` and reports it to the coordinator
- Coordinator distributes peer endpoints so agents can **hole-punch** a direct UDP path

> Note: there is **no TURN/coturn** and **no pion/webrtc** in this build. The strict-NAT
> fallback is the custom DERP-style relay below, which is lighter than a TURN deployment.

### 3.4 Relay Server — DERP-style (`crates/relay`)
- Encrypted **WebSocket** packet forwarder, **keyed by WG public key**
- Sees only **ciphertext** (zero-trust); forwards frames between registered peers
- **Authenticates** clients with a coordinator-signed JWT (`RELAY_JWT_SECRET`)
- Acts as the fallback path when direct hole punching fails (symmetric/CGNAT)
- *Remaining:* latency-based region selection + automatic direct→relay failover at runtime

### 3.5 Client Agent (`crates/agent-core`, `agent-cli`, `agent-ffi`)
Responsibilities:
- Generate WG keypair, enroll, fetch + apply the network map on a loop
- Run STUN discovery, report endpoints + measured RTT
- Configure WireGuard (render `wg-quick` / `wg syncconf`), maintain connections
- Enforce the per-node inbound ACL packet filter
- Auto-rotate keys before expiry; report throughput counters

Language:
- **Rust** shared core compiled per-OS; mobile exposed via a **C ABI/FFI** (`agent-ffi`,
  header `crates/agent-ffi/include/whalescale.h`)

### 3.6 Dashboard — Web UI (`dashboard/`)
Features:
- Login/session, org switcher, live device list (status, overlay IP, direct/relay, last-seen)
- Network topology graph, ACL editor, latency/throughput charts, audit log
- Device approval queue (approve pending devices)

Stack:
- **React + TypeScript + Vite** (not Next.js)
- **Tailwind CSS v4**, **TanStack Query** (server state), **React Router**
- **@xyflow/react** (React Flow) for the topology graph, **Recharts** for metrics
- `VITE_DEMO=1 pnpm dev` previews with sample data, no backend needed

---

## 4. Networking Model

### 4.1 IP Addressing
Overlay uses the CGNAT range `100.64.0.0/10` (same as Tailscale) so it never clashes with
normal LANs. The coordinator allocates each device a stable overlay IP via its IPAM
(`ipam::next_free_v4`, pure + unit-tested). Example: Device A → `100.64.0.2`,
Device B → `100.64.0.3`.

### 4.2 Peer Communication Flow
1. Device enrolls with the control plane (auth key → JWT session + overlay IP)
2. Receives a **network map**: allowed peers (public key, endpoints, AllowedIPs, relay),
   filtered by ACL + tenant
3. Performs STUN to discover its reflexive endpoint; reports it
4. Attempts a **direct** hole-punched WireGuard tunnel to each peer
5. If direct fails → falls back to the **DERP-style relay**

---

## 5. Database Design (multi-tenant; `tenant_id` on every row)

### Devices Table
- id
- tenant_id
- user_id (owner)
- **public_key**  *(the private key NEVER leaves the device — zero-trust)*
- overlay_ip
- tags
- advertised_routes  *(subnet routers / exit nodes)*
- require_approval / approved  *(device approval queue)*
- key_expires_at  *(key rotation & expiry)*
- last_seen
- status

### Users Table
- id
- tenant_id
- email
- password_hash  *(Argon2id)*
- role  *(owner / admin / member)*

### Auth Keys Table
- id, tenant_id, key, require_approval, …  *(pre-auth keys for headless enrollment)*

### Supporting tables
- tenants, acl_policies, audit_log  *(all tenant-scoped)*

> Correction vs. the original draft: there is **no `private_key` column**. Storing device
> private keys server-side would break WireGuard's zero-trust model; the coordinator brokers
> public keys + endpoints only.

---

## 6. WireGuard Integration

### Interface Config
```
[Interface]
PrivateKey = <private>          # held only on-device
Address = <overlay_ip>/32
```

### Peer Config
```
[Peer]
PublicKey = <peer_key>
AllowedIPs = <peer_overlay_ip>/32[, <advertised_routes>]
Endpoint = <peer_reflexive_endpoint>   # preferred: STUN-discovered public IP:port
PersistentKeepalive = 25
```
Rendered by `agent-core/src/wgconfig.rs` (`render_quick` / `render_setconf`). The config
prefers each peer's reflexive (STUN) endpoint for direct connectivity.

---

## 7. API Design (actual surface)

### Agent / enrollment
- `POST /enroll` — register a device (public key, hostname, os, advertised routes)
- `GET  /netmap` — fetch the current network map
- `POST /rotate` — rotate to a new keypair before expiry
- `POST /endpoints` — report STUN-discovered endpoints
- `POST /stats` — report STUN RTT (latency)
- `POST /throughput` — report interface byte counters
- WebSocket — live network-map push on change

### Admin (JWT-protected, tenant-isolated)
- `POST /admin/login`, `GET /admin/me`, `POST /admin/.../users`
- `GET /admin/tenants`, `GET /admin/tenants/:id/devices`, `GET/DELETE /admin/devices/:id`
- `POST /admin/devices/:id/approve`, `GET/PUT /admin/.../acl`, audit + latency endpoints

### Dev helper
- `POST /dev/bootstrap` — mint a dev tenant, owner login, and reusable auth key *(dev-only)*

---

## 8. Security Model
- **End-to-end encryption** via WireGuard; **zero-trust data plane** — coordinator and relay
  never see plaintext (relay sees only ciphertext)
- Device **private keys never leave the device**
- **Argon2id** password hashing; signed **JWT** sessions
- **RBAC** (owner/admin/member) + **tenant isolation** enforced in the network-map builder
  (a node can never learn about peers outside its org)
- **ACL policy engine** compiled to a per-node inbound packet filter (source IPs + ports)
- **Key rotation & expiry**: expired devices quarantined from the mesh; agents auto-rotate
- **Device approval queue**: pending devices excluded from every map until approved
- TLS for API communication (deployment concern)

---

## 9. Development Phases — actual status

- **Phase 0 — Foundations** ✅ Cargo workspace, DB schema + migrations, coordinator skeleton, dashboard shell.
- **Phase 1 — Enrollment + network map** ✅ keypair gen, overlay IP allocation, `/enroll`, `/netmap`, control WebSocket, wg-config rendering. *Remaining:* real kernel-WireGuard TUN data loop wiring (currently `LogBackend`/`WgQuickBackend`).
- **Phase 2 — STUN + endpoint discovery** ✅ from-scratch RFC 5389 codec + server, reflexive endpoint discovery, `/endpoints`, live map push, config prefers reflexive endpoints. *Remaining:* multi-candidate hole-punch probing + a real NAT testbed; Redis cross-instance fanout.
- **Phase 3 — Relay fallback** ✅ DERP-style WebSocket forwarder keyed by WG pubkey, JWT-authenticated, relay regions advertised in the map. *Remaining:* latency-based region selection + automatic runtime failover.
- **Phase 4 — Dashboard MVP** ✅ admin API, React dashboard, org switcher, live device table, React Flow topology, audit log.
- **Phase 5 — ACL policy engine** ✅ Tailscale-style allow rules (groups, `tag:`/`group:`/user/`*`), enforced in the map builder, validated `GET/PUT .../acl`, device tags, ACL editor UI, **port-level inbound packet filter**.
- **Phase 5b — Auth + RBAC** ✅ Argon2 passwords, JWT sessions, roles, protected `/admin/*` with tenant isolation, dashboard login/logout. *Remaining:* OIDC/SSO as an additional login path (needs an external IdP).
- **Phase 6 — Cross-platform data plane** ✅ userspace WireGuard via boringtun (`wireguard.rs`), verified by an in-process two-peer handshake/transport test. *Remaining:* per-OS TUN glue (wintun/utun/`/dev/net/tun`) — see `docs/platform-agents.md`.
- **Phase 7 — Mobile FFI core** ✅ C ABI exposing keygen + the WireGuard `Peer`, full handshake/transport verified across the `extern "C"` boundary. *Remaining:* Swift `NEPacketTunnelProvider` + Kotlin `VpnService` shells + cross-compilation.
- **Phase 8 — Platform features** ✅ MagicDNS resolver, exit nodes / subnet routers, device approval queue, key rotation & expiry, latency & throughput metrics + charts. *Remaining:* billing hooks (Stripe), per-tenant settings polish.

**Performance:** the hot per-packet ACL filter is compiled into an O(1) lookup
(`filter::CompiledFilter`); a Criterion benchmark (`cargo bench -p ws-agent-core`) shows
**~5.9 µs → ~20 ns (~296×)** for a 1000-source-IP filter, lifting the single-core filter
ceiling from ~170k to ~50M packets/sec.

---

## 10. Deployment Strategy
- **Coordinator:** VPS / cloud (managed container or VM); migrations applied on boot
- **STUN + relay servers:** small standalone Rust binaries, geo-distributed (low latency
  depends on relays near users)
- **Database:** managed PostgreSQL; Redis for pub/sub fanout
- **Local dev without Docker:** see `docs/RUNBOOK.md` (a free cloud Postgres such as Neon works)
- `deploy/` holds docker-compose / k8s / terraform scaffolding

---

## 11. Challenges
- NAT traversal complexity (multi-candidate hole punching, symmetric NAT)
- Real-time peer/network-map updates at scale (Redis cross-instance fanout)
- Geo-distribution + latency-based relay selection
- Per-OS TUN integration and native mobile packaging

---

## 12. Genuinely-remaining work (not yet built)
- Per-OS TUN data loop wiring (wintun / utun / tun) and OS service installers
- Native mobile shells: iOS `NEPacketTunnelProvider`, Android `VpnService` + cross-compile
- OIDC/SSO login path (needs an external IdP)
- Billing hooks (Stripe) for the SaaS tier
- Live multi-host NAT testbed; Redis cross-instance map fanout
- Latency-based relay region selection + automatic direct→relay failover

> Note: MagicDNS, ACLs, multi-user orgs, exit nodes, and subnet routing — listed as "future"
> in the original draft — are **already implemented** (Phase 5 / Phase 8).

---

## 13. Repository Structure (Rust Cargo workspace + pnpm dashboard)

```
whalescale/
├─ Cargo.toml                # workspace
├─ crates/
│  ├─ coordinator/           # axum control plane (auth, netmap, ACL, admin API)
│  ├─ relay/                 # DERP-style WebSocket relay (pubkey-keyed, JWT-auth)
│  ├─ stun-server/           # from-scratch RFC 5389 STUN responder
│  ├─ stun/                  # STUN codec library
│  ├─ agent-core/            # shared client logic (boringtun, STUN, map sync, filter)
│  ├─ agent-cli/             # Linux/Windows/macOS daemon wrapping agent-core
│  ├─ agent-ffi/             # C ABI for iOS/Android (cdylib/staticlib + header)
│  └─ proto/                 # shared wire types (network map, API DTOs)
├─ clients/                  # iOS (Swift) + Android (Kotlin) shells (Phase 7, in progress)
├─ dashboard/                # React + Vite + Tailwind dashboard
├─ migrations/               # sqlx Postgres migrations
├─ deploy/                   # docker-compose, k8s, terraform
└─ docs/                     # RUNBOOK.md, platform-agents.md
```

---

## 14. Conclusion
WhaleScale is a complex but scalable networking system. The phased build shipped a working
mesh early and layered features on: Phases 0–8 are implemented in **Rust + React** with
honest "remaining" notes per phase. The biggest outstanding engineering items are the per-OS
TUN data loops, native mobile shells, and a live multi-host NAT testbed — see `README.md`
for authoritative, continuously-updated status.
