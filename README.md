# 🐋 WhaleScale

A low-latency, WireGuard-based mesh VPN — a self-hosted, multi-tenant Tailscale
alternative with a full web dashboard. Control plane built from scratch in Rust;
dashboard in React.

> **Why low latency?** WhaleScale gets peers to talk **directly** (peer-to-peer)
> instead of relaying through a server. STUN discovers each node's public
> endpoint, then peers **hole-punch** a direct UDP WireGuard tunnel. A
> DERP-style relay is only a fallback for strict NATs. See `docs/` and the
> project plan for details.

## Architecture

| Component | Crate / Dir | Status |
|-----------|-------------|--------|
| Coordinator (control plane) | `crates/coordinator` | Phase 2 ✅ |
| Shared wire types | `crates/proto` | Phase 1 ✅ |
| STUN codec (RFC 5389) | `crates/stun` | Phase 2 ✅ |
| Node agent (shared core) | `crates/agent-core` | wg-quick backend ✅ |
| Desktop/server agent CLI | `crates/agent-cli` | daemon loop ✅ |
| Mobile C ABI (iOS/Android) | `crates/agent-ffi` | Phase 7 ✅ |
| STUN server | `crates/stun-server` | Phase 2 ✅ |
| DERP-style relay | `crates/relay` | Phase 3 ✅ |
| Dashboard | `dashboard/` | Phase 4 ✅ |

## Roadmap (phased)

- **Phase 0 — Foundations** ✅ workspace, DB schema, coordinator skeleton, dashboard shell.
- **Phase 1 — Enrollment + network map** ✅ auth keys, overlay IP allocation, `/enroll`,
  `/netmap`, control WebSocket, agent keygen + wg-config rendering. *Remaining:* a real
  kernel-WireGuard backend (currently `LogBackend` prints the config).
- **Phase 2 — STUN + endpoint discovery** ✅ from-scratch RFC 5389 codec + STUN
  server, agent discovery of local + reflexive endpoints, `POST /endpoints`, and a
  connection hub that live-pushes fresh maps to connected agents. The config now
  prefers each peer's reflexive (STUN) endpoint. *Remaining:* full multi-candidate
  hole-punch probing + a real NAT testbed; Redis cross-instance fanout (Phase 2.5).
- **Phase 3 — Relay fallback** ✅ DERP-style WebSocket packet forwarder keyed by
  WG public key (sees only ciphertext), agent relay client, and relay regions
  advertised in the network map. The relay now **authenticates clients** with the
  coordinator-signed JWT (`RELAY_JWT_SECRET`). *Remaining:* latency-based region
  selection and automatic direct→relay failover at runtime.
- **Phase 4 — Dashboard MVP** ✅ admin API (`/admin/tenants`, `/admin/tenants/:id/devices`,
  `/admin/devices/:id`, audit), React dashboard with org switcher, live device table
  (status, overlay IP, direct/relay, last-seen, remove), React Flow topology graph, and
  audit log. Run with `VITE_DEMO=1 pnpm dev` to preview without a backend.
- **Auth-key management** ✅ admins generate/list/revoke pre-auth keys from the dashboard
  (`GET/POST /admin/tenants/:id/authkeys`, `POST /admin/authkeys/:id/revoke`) — reusable /
  ephemeral / require-approval / expiry flags; the raw key is shown once and only its hash
  is stored (plus a non-secret prefix for listings, tested `authkeys::generate_key`). This
  replaces the dev-only `/dev/bootstrap` for real device onboarding.
- **Team / user management** ✅ list members, invite users, change roles, and remove users
  from the dashboard (`GET /admin/tenants/:id/users`, `PATCH /admin/users/:id/role`,
  `DELETE /admin/users/:id`). RBAC is enforced by pure, tested helpers (`users::can_change_role`,
  `users::can_delete_user`): only an owner may grant/modify the owner role, and the **last owner
  can never be demoted or removed** (no org lock-out). UI gates controls by the caller's role.
- **Phase 5 — ACL policy engine** ✅ Tailscale-style allow rules (`groups`, `tag:`/`group:`/
  user/`*` selectors), enforced in the network-map builder (a peer is visible only if a rule
  permits either direction; no policy = allow-all), validated `GET/PUT /admin/.../acl` API,
  device tags, and an ACL editor UI. **Port-level filtering:** the policy's destination ports
  (e.g. `tag:server:22,443`) compile to a per-node inbound `packet_filter` (resolved source IPs
  + ports) delivered in the network map (tested `Policy::inbound_filter`).
- **Phase 5b — Auth + RBAC** ✅ Argon2-hashed passwords, signed JWT sessions, `Role`
  (owner/admin/member), `POST /admin/login` + `/admin/me` + `/admin/.../users`, and the whole
  `/admin/*` surface protected by an `AdminSession` extractor with **tenant isolation** and
  role gating. Dashboard has a login page, token storage, and sign-out. *Remaining:* OIDC/SSO
  as an additional login path (needs an external IdP), and per-rule port packet-filter delivery.
- **WireGuard backend** ✅ the agent is now a daemon: enroll → STUN discover →
  sync on an interval, applying config via a real `WgQuickBackend` (`wg-quick up`
  then `wg syncconf` for in-place updates) or `LogBackend` for dev. Run a real
  interface on Linux/macOS with `WS_BACKEND=wgquick` (needs `wireguard-tools` + root).
- **Phase 6 — Cross-platform data plane** ✅ userspace WireGuard via boringtun
  (`agent-core/src/wireguard.rs`): the `Peer` type owns the Noise handshake +
  transport, **verified in-process** by a two-peer handshake/transport test (runs on
  Windows, no TUN device needed). This is the shared core for all desktop + mobile
  clients. *Remaining:* the per-OS TUN glue (wintun/utun/`/dev/net/tun`) — see
  [docs/platform-agents.md](docs/platform-agents.md).
- **Phase 7 — Mobile FFI core** ✅ a C ABI (`crates/agent-ffi`, header
  `crates/agent-ffi/include/whalescale.h`) exposing keygen + the WireGuard `Peer`
  for iOS/Android; the full handshake + transport across the `extern "C"` boundary
  is verified by a test. *Remaining:* the Swift `NEPacketTunnelProvider` and Kotlin
  `VpnService` shells + cross-compilation (`cargo build --target …-ios` / `cargo-ndk`).
- **Phase 8 — MagicDNS** ✅ from-scratch DNS `A` resolver mapping device hostnames
  (short + FQDN via tenant suffix) to overlay `100.64.x.x` IPs, built from the network
  map and served over UDP by the agent (`WS_DNS_BIND`); verified by a real loopback
  query test. *Remaining Phase 8:* key rotation & expiry, device approval queue,
  latency charts, billing hooks.
- **Phase 8 — Exit nodes / subnet routers** ✅ devices advertise CIDRs
  (`WS_ADVERTISE_ROUTES=192.168.1.0/24`, or `0.0.0.0/0` for an exit node); the
  netmap merges them into the node's AllowedIPs (unit-tested `merge_allowed_ips`).
- **Phase 8 — Device approval queue** ✅ auth keys can `require_approval`; pending
  devices are excluded from every network map until an admin approves them
  (`POST /admin/devices/:id/approve`), with a pending badge + Approve button in the
  dashboard (tested `device_status` helper).
- **Phase 8 — Key rotation & expiry** ✅ `DEVICE_KEY_TTL_DAYS` sets a key lifetime;
  expired devices are quarantined from the mesh (shared, tested `expiry::is_active`),
  and the agent auto-rotates before expiry via `POST /rotate` (new keypair → peers
  re-learn the key on the next map push).
- **Phase 8 — Latency & throughput metrics** ✅ the agent measures its real STUN
  round-trip time (`POST /stats`) and reports interface byte counters (`POST /throughput`,
  parsed from `wg show transfer`); the coordinator keeps a rolling per-device latency
  window (tested `LatencyWindow`) and derives Tx/Rx rates (tested `bytes_per_sec`,
  reset-safe); the dashboard's **Latency** page charts RTT and shows last/avg/p95 + Tx/Rx.

**Performance:** the hot per-packet ACL filter is compiled into an O(1) lookup
(`filter::CompiledFilter`) — a Criterion benchmark (`cargo bench -p ws-agent-core`)
shows **~5.9 µs → ~20 ns (~296×)** for a 1000-source-IP filter, lifting the
single-core filter ceiling from ~170k to ~50M packets/sec.

**Quality:** the workspace is `cargo fmt` clean, passes `cargo clippy --all-targets -D warnings`,
and **40 tests** pass (incl. agent integration tests that drive the real `Agent` against a mock
coordinator: enroll → sync → version-dedup, STUN discovery/reporting, and key rotation); CI
([.github/workflows/ci.yml](.github/workflows/ci.yml)) enforces all of this plus the dashboard
build on every push.

See **[docs/RUNBOOK.md](docs/RUNBOOK.md)** to run the whole stack end-to-end without
Docker (a free cloud Postgres works).

## Local development

### Prerequisites
- Rust 1.95+, Node 20+, pnpm, and Docker (for Postgres + Redis).

### 1. Start dependencies
```bash
docker compose -f deploy/docker-compose.yml up -d
```

### 2. Run the coordinator
```bash
cp .env.example .env        # adjust if needed
cargo run -p ws-coordinator # applies migrations, listens on :8080
```
Check it: `curl localhost:8080/healthz` → `{"status":"ok"}`

### 3. Run the dashboard
```bash
cd dashboard
pnpm install
pnpm dev                    # http://localhost:5173 (live, talks to coordinator)
# or preview with sample data, no backend needed:
VITE_DEMO=1 pnpm dev
```
The dashboard proxies `/api/*` to the coordinator and shows a live
"coordinator online" pill when connected.

### 4. Run the STUN server (Phase 2) + relay (Phase 3)
```bash
STUN_BIND=0.0.0.0:3478 cargo run -p ws-stun-server
RELAY_BIND=0.0.0.0:3479 cargo run -p ws-relay
# Advertise the relay to agents via the coordinator:
#   RELAY_ADDR=<public-host>:3479 cargo run -p ws-coordinator
```

### 5. Enroll an agent (Phase 1–2)
```bash
# Mint a dev tenant, an owner login, and a reusable auth key
curl -s -XPOST localhost:8080/dev/bootstrap | jq
#   -> { auth_key: "ws-...", login: { email: "owner@dev", password: "whalescale" } }
# Sign in to the dashboard with that email/password; use auth_key below.

# Run the agent daemon; it enrolls, discovers endpoints via STUN, fetches the
# map, and applies a WireGuard config on a loop. Default LogBackend prints it.
WS_AUTH_KEY=ws-xxxx STUN_SERVER=127.0.0.1:3478 cargo run -p ws-agent-cli

# On Linux/macOS with wireguard-tools installed, configure a real interface:
sudo WS_AUTH_KEY=ws-xxxx STUN_SERVER=<host>:3478 \
     WS_BACKEND=wgquick WS_IFACE=whale0 \
     cargo run -p ws-agent-cli
```
Enroll a second machine with the same key and each agent's rendered config will
list the other as a `[Peer]` with its `100.64.x.x` AllowedIPs and reflexive
`Endpoint` for direct (hole-punched) connectivity.

## Repository layout
```
crates/        Rust workspace (coordinator, relay, stun-server, agent-*, proto)
clients/       iOS (Swift) + Android (Kotlin) wrappers around agent-core (Phase 7)
dashboard/     React + Vite + Tailwind dashboard
migrations/    sqlx Postgres migrations
deploy/        docker-compose, k8s, terraform
```
