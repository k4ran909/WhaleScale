# WhaleScale — Project Status

A from-scratch, multi-tenant, Tailscale-style WireGuard mesh VPN: Rust control
plane + agents, React dashboard. This file is the honest snapshot of what is
built, what is *proven*, and what's left.

**Quality gates (all green):** `cargo fmt --check` · `cargo clippy --all-targets
-D warnings` · **58 tests** · `pnpm build`. CI enforces them on every push.

## Architecture
```
coordinator (axum)         agent (agent-core + agent-cli)        dashboard (React)
  control plane              enroll · STUN discovery · sync         devices · map
  Postgres + in-mem stores   wg-quick / boringtun data plane        ACL · latency
  auth · ACL · netmap        MagicDNS · key rotation                audit · approve
        ▲                          ▲     ▲                                ▲
        └── HTTP/WS ───────────────┘     └── STUN ──► stun-server         │
                                         └── relay ─► relay (DERP-style)  │
        └────────────────────── admin API ──────────────────────────────┘
```
Crates: `proto` (shared types + pure helpers), `coordinator`, `stun-server`,
`relay` (lib+bin), `agent-core` (lib), `agent-cli` (bin), `agent-ffi` (C ABI for
mobile). Plus `dashboard/`.

## Built & verified (tested without external infra)
| Area | What | Proof |
|------|------|-------|
| Control plane | enroll, overlay IPAM, netmap, WS push | ipam + agent_flow tests |
| Auth / RBAC | Argon2 passwords, JWT, owner/admin/member, tenant isolation | auth tests |
| ACL engine | `group:`/`tag:`/user/`*` rules, peer visibility | acl tests |
| ACL port filter | policy → per-node inbound filter; agent enforces | acl + filter tests |
| NAT traversal | RFC 5389 STUN codec + server + client | stun + loopback tests |
| Relay | DERP-style forwarder, JWT-authenticated | relay + loopback tests |
| Path selection | direct↔relay failover policy | conn tests |
| Data plane | boringtun userspace WireGuard (handshake + transport) | wireguard + ffi tests |
| WireGuard backend | `wg-quick up` / `wg syncconf` command sequence | backend tests |
| MagicDNS | from-scratch DNS resolver (hostname → overlay IP) | magicdns + loopback tests |
| Exit nodes | advertise routes → merged AllowedIPs | netmap tests |
| Device approval | pending devices quarantined until approved | device_status tests |
| Key rotation | TTL + agent auto-rotate before expiry | expiry tests |
| Metrics | STUN-RTT latency + Tx/Rx throughput, charted | stats tests |
| Mobile core | C ABI (`whalescale.h`) for iOS/Android | ffi handshake test |

## Not yet proven / not built (each blocked by something external)
- **Live end-to-end run** — never run against a real DB (no Postgres available).
  Unblocked by a free **Neon/Supabase** URL. See [docs/RUNBOOK.md](docs/RUNBOOK.md).
- **Real tunnel** (two nodes pinging over `100.64.x.x`) — needs Linux + root +
  `wireguard-tools`. The config/command logic is tested; the live interface isn't.
- **Live packet-filter enforcement & relay failover** — the *decision functions*
  are tested; their call sites live in the platform TUN/UDP loop (device-bound).
- **Native mobile apps** — only the Rust C ABI exists; Swift `NEPacketTunnelProvider`
  / Kotlin `VpnService` shells need Xcode / Android NDK.
- **OIDC/SSO** — only password auth; real SSO needs an identity provider.
- **Redis cross-instance fanout** — single-instance fanout works; multi-coordinator
  needs the (stubbed) Redis path.
- **Billing** — needs a Stripe account.

## Take it live (no Docker)
1. Create a free Postgres at neon.tech; copy the connection string.
2. `cp .env.example .env`, set `DATABASE_URL` + a real `JWT_SECRET`.
3. `cargo run -p ws-coordinator` (auto-migrates) → `curl localhost:8080/healthz`.
4. `curl -XPOST localhost:8080/dev/bootstrap` → auth key + `owner@dev` / `whalescale`.
5. `cd dashboard && pnpm dev` → sign in; enroll an agent (`WS_AUTH_KEY=… cargo run -p ws-agent-cli`).

Full walkthrough (STUN, relay, two agents, exit nodes, MagicDNS, ACLs): **docs/RUNBOOK.md**.
Per-platform agent details: **docs/platform-agents.md**.
