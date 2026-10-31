# Whalescale — Plan

A self-hosted mesh VPN, like Tailscale and Headscale. You run the whole stack yourself: control plane, relays, clients and web UI. Nothing depends on a vendor's cloud.

> Status: planning (2026-10-29). Nothing is built yet.

---

## 1. Why build another one?

The research below (sources at the end) found these recurring problems in Tailscale, Headscale, NetBird and Netmaker:

| # | Pain point | Who has it | Whalescale answer |
|---|---|---|---|
| P1 | **No high availability for the control plane.** Only one Headscale server can run at a time. | Headscale | Run 3+ control nodes with Raft or Postgres leader election. Clients fail over automatically. |
| P2 | **Slow at scale.** Policy writes and node registration take 7–90 s at 1–2k nodes (headscale#3549). | Headscale | Send incremental netmap deltas instead of full maps. Compile the policy once and diff it. Target: policy change reaches every node in under 1 s at 10k nodes. |
| P3 | **Painful upgrades.** You can only upgrade one minor version at a time, and there is one config file, so package upgrades conflict (headscale#3548). | Headscale | Any-version-to-latest migrations, `conf.d/` overrides, `whalescale doctor` / `configtest`, built-in backup before migrate. |
| P4 | **No public ingress (Funnel).** It's "not planned" in Headscale, so people go back to Tailscale's SaaS. | Headscale | **Gateway**: expose a node service publicly through your own VPS, with automatic ACME TLS and SNI routing. |
| P5 | **No official web UI.** Community UIs are still unstable. | Headscale | A first-class web console ships in the same binary. |
| P6 | **CGNAT / symmetric NAT forces relays.** Relayed connections are slow (2.2 Mbps → 27 Mbps once a peer relay was added; India→US case). | Everyone | Smarter traversal: port prediction, UPnP/NAT-PMP/PCP, IPv6 first, and **automatic peer relays** that pick your best-connected node. |
| P7 | **Relay throughput is capped.** Native Windows DERP uploads stall around 10 Mbps (tailscale#18017). | Tailscale | Fast relay protocol (QUIC/UDP first, TCP/WS fallback). Benchmark on Windows from day 1. |
| P8 | **Blocked networks.** If `tailscale.com` is blocked, clients can't connect. | Tailscale | Your own domain. Relays work over HTTPS/443, WebSocket and QUIC, with optional domain fronting / pluggable transports. |
| P9 | **No idea whether traffic is direct or relayed.** | Everyone | Live **path view** per peer (direct / relay / which relay, RTT, loss, throughput), with alerts when a path degrades. |
| P10 | **ACL typos fail silently.** | Headscale | Policy linter, policy unit tests, dry run, and an **"explain"** command: *why can't A reach B on :443?* |
| P11 | **No flow logs or SSH session recording when self-hosted.** | Headscale | Flow logs and SSH session recording stored on your own infrastructure, with export to Prometheus, Loki and SIEM. |
| P12 | **No on-demand connect** (auto-enable off home Wi-Fi). Long-standing request (tailscale#3302). | Tailscale | Client rules: trusted SSIDs, auto exit node, per-app routing. |
| P13 | **Mobile battery drain.** | Tailscale | Push-based wake, adaptive keepalives, lazy peer connections. |
| P14 | **Mobile setup is fiddly.** The custom server URL is hidden in a debug menu. | Headscale (uses Tailscale apps) | Our own apps. Join by scanning a QR code or opening a deep link. |
| P15 | **No per-user device limits** (headscale#3543). | Headscale | Quotas per user and per group. |
| P16 | **Trust: you depend on someone else's cloud.** | Tailscale | 100% self-hosted, open source, reproducible builds. |

---

## 2. Positioning

- **Headscale** = control server only, and it borrows Tailscale's clients.
- **NetBird** = full product, but heavy (needs 2 GB RAM), and some features are cloud-only.
- **Whalescale** = the full product (control + relay + clients + UI) with Headscale's footprint: **one binary, SQLite by default, runs on a $3 VPS, HA when you want it.** Nothing is cloud-only; every feature is self-hostable.

---

## 3. Architecture

```
                     ┌───────────────────────────────────────────┐
                     │            whalescale server              │
                     │ (one Go binary; roles enabled by config)  │
                     │                                           │
   Web UI / API ───► │  control  │  relay  │  gateway  │  stun   │
   (OIDC login)      │  (netmap, │ (QUIC / │ (public   │         │
                     │  policy,  │  TCP /  │  ingress, │         │
                     │  keys)    │  WS)    │  ACME)    │         │
                     └────┬──────────────┬────────────────┬──────┘
                          │ long-poll /  │ relayed pkts   │ HTTPS in
                          │ stream (TLS) │ (E2E encrypted)│
                 ┌────────▼───┐      ┌───▼──────────┐   │
                 │  node A    │◄────►│   node B     │◄──┘
                 │ wsd agent  │ WG   │  wsd agent   │
                 └────────────┘direct└──────────────┘
```

**Components**

1. **Control plane (`control`)**: node registration, identity (OIDC plus pre-auth keys), key distribution, IP allocation (IPv4 CGNAT range + IPv6 ULA), policy compilation, DNS config, netmap streaming. Storage is SQLite by default, with Postgres or embedded Raft for HA. The control plane never sees traffic.
2. **Relay (`relay`)**: a DERP-like packet relay for when a direct path fails. It only forwards WireGuard packets, which are already encrypted. Runs on the server, a VPS, or any node (peer relay).
3. **STUN**: endpoint discovery and NAT-type detection.
4. **Gateway**: public ingress (the Funnel replacement). TLS terminates either on the node (passthrough by SNI) or at the gateway.
5. **Agent (`wsd`) + CLI (`ws`)**: runs on each device. Kernel WireGuard where available, userspace (`wireguard-go`) everywhere else. Handles NAT traversal, path selection, DNS, firewall rules and SSH.
6. **Web console**: React SPA embedded in the server binary.
7. **Mobile apps**: Android first (Go via gomobile, Kotlin UI), then iOS (NetworkExtension).

**Key protocol decisions**

- **Data plane:** standard WireGuard (Noise IK). Optional **post-quantum hybrid PSK** (Rosenpass-style ML-KEM key exchange that rotates the WG PSK), a differentiator.
- **Control protocol:** our own, built on gRPC or Connect over HTTP/2 + TLS (or Noise over WebSocket for hostile networks). Node identity is a machine key; user identity comes from OIDC.
- **Tailscale client compatibility:** *not* a goal in v1. Using our own protocol frees us from chasing Tailscale changes, which is Headscale's main burden. Revisit a compat shim later.

---

## 4. Tech stack

| Layer | Choice | Why |
|---|---|---|
| Server + agent | **Go** | `wireguard-go`, `wgctrl`, gVisor netstack, cross-compiles everywhere, single static binary |
| Storage | SQLite (default) / Postgres / embedded Raft (`hashicorp/raft`) | Small by default, HA when needed |
| API | Connect-RPC (gRPC + JSON) + OpenAPI | One API for CLI, UI, Terraform and MCP |
| Web UI | React + Vite + TypeScript, embedded with `go:embed` | Single binary |
| Auth | OIDC (Authentik, Keycloak, Google, GitHub, Zitadel) + local users + passkeys | Self-host friendly |
| Mobile | gomobile core + Kotlin / Swift UI | Shares the Go networking core |
| Packaging | Docker, Helm, `.deb`/`.rpm` (apt/yum repo), Homebrew, MSI, one-line install script | P3 |
| Observability | Prometheus metrics, OpenTelemetry traces, structured logs | P9, P11 |

---

## 5. Feature list

### Core (parity with Tailscale/Headscale)
- Mesh networking with stable IPs (`100.64.0.0/10` + IPv6 ULA)
- NAT traversal (STUN, hole punching) with relay fallback
- MagicDNS-style names (`laptop.user.ws.internal`) + split DNS + custom records
- Subnet routers (advertise LAN routes, with approval)
- Exit nodes
- ACLs (JSON/HuJSON, groups, tags, ports)
- Pre-auth keys, ephemeral nodes, key expiry
- SSH over the mesh, authorized by identity
- File send between devices (Taildrop equivalent)
- Serve (share a local port on the mesh with automatic HTTPS from an internal CA or ACME DNS-01)

### Beyond them (the reasons to choose Whalescale)
**Reliability and scale**
- HA control plane, active/standby or Raft (P1)
- Delta netmaps, targeting 10k+ nodes (P2)
- Clients cache the last netmap and keep working while the control plane is down

**Connectivity**
- Automatic peer relays: any well-connected node can volunteer to relay, and clients pick the best one by RTT (P6)
- Symmetric-NAT port prediction (birthday-style probing), UPnP / NAT-PMP / PCP, IPv6 preferred
- Relay transports: UDP/QUIC → TCP → WebSocket over 443, plus pluggable transports for censored networks (P7, P8)
- Multipath: bond Wi-Fi + 5G and fail over without dropping sessions
- Multi-hop exit (route through 2 exit nodes) and exit-node pools with health checks

**Public exposure**
- **Gateway** (Funnel replacement): `ws expose 8123 --public ha.example.com` with automatic ACME, rate limiting, optional auth wall (OIDC in front of the app) (P4)
- Named **Services** with virtual IPs, load balanced and failed over across several nodes

**Visibility**
- Live topology map: who is direct and who is relayed, RTT, loss, throughput (P9)
- Flow logs (who talked to whom, ports, bytes), kept on your infrastructure (P11)
- SSH session recording to S3 or MinIO (P11)
- Alerts: node offline, path fell back to relay, key expiring, posture failed

**Policy and security**
- Policy linter + unit tests (`tests:` block in the policy) + dry run + `ws explain A B:443` (P10)
- Policy-as-code: GitOps sync from a Git repo, plus a Terraform provider
- Device posture checks (OS version, disk encryption, firewall on, agent version)
- Network lock: nodes only accept peers signed by trusted admin keys, so a compromised control server can't inject nodes
- Post-quantum hybrid key exchange (optional)
- Per-user and per-group device quotas (P15)
- Just-in-time access: request access to a resource for N hours, approved in the UI or by webhook
- Audit log for every admin action

**Client UX**
- Join by QR code or deep link, no hidden menus (P14)
- On-demand rules: trusted SSIDs, auto exit node on untrusted Wi-Fi, per-app split tunneling (P12)
- Several networks in one client, quick switching
- Battery mode: push wake (FCM/APNs relay you self-host, or UnifiedPush), adaptive keepalive (P13)

**Operations**
- `whalescale doctor`, `configtest`, `conf.d/`, any-version upgrades with automatic backup (P3)
- One-command install on a VPS: server + relay + STUN + gateway + TLS
- Backup and restore (one command, encrypted)
- **MCP server** + REST API so AI agents can administer the network with scoped tokens (tailscale#19623 shows demand)
- Webhooks (node joined, policy changed, and so on)

---

## 6. Roadmap

### Phase 0: Foundations (2–3 weeks)
- Monorepo layout: `cmd/whalescale` (server), `cmd/wsd` (agent), `cmd/ws` (CLI), `web/`, `proto/`
- Protobuf API definitions, SQLite schema + migration framework
- CI: lint, tests, cross-compile (linux/amd64+arm64, windows, macOS)
- **Done when:** the server starts, `ws` can log in with a pre-auth key, and the node is listed

### Phase 1: MVP mesh (4–6 weeks)
- Registration, machine keys, IP allocation, netmap streaming
- Agent: kernel WG on Linux, `wireguard-go` on Windows/macOS, routes, DNS
- STUN + hole punching, relay (TCP/WS) fallback
- Basic ACLs, MagicDNS, CLI (`up`, `down`, `status`, `ping`, `netcheck`)
- **Done when:** 3 PCs (Windows + Linux + one behind CGNAT) ping each other by name, and `ws status` shows direct vs relay
- **Status (2026-10-30):** built and passing in-process end-to-end tests (direct path, relay-only, policy). Still open: the real 3-PC/CGNAT run, OS TUN mode on real machines, `ws up/down` (moved to Phase 2 with service install), and kernel WireGuard on Linux (wireguard-go everywhere for now).

### Phase 2: Usable product (4–6 weeks)
- Web console (nodes, users, keys, policy editor with lint)
- OIDC login, subnet routers, exit nodes
- Docker image + install script + `doctor`
- Path view + Prometheus metrics
- **Done when:** a homelab user can replace Headscale end to end in under 15 minutes
- **Status (2026-10-31):** built: web console (machines, topology, users, keys, routes, policy editor with live lint), admin API with API keys, OIDC console and device login, subnet routers (Linux) with approval, config file with conf.d and env layering, `configtest` and `doctor`, Prometheus metrics, path reporting, `ws up/down`, a service installer (systemd, Windows, launchd), a Docker image with Compose and Caddy, an install script, and a release workflow. Exit nodes can be advertised and approved, but client-side use moves to Phase 3. Not yet verified: the 15-minute walkthrough on a real VPS, OS TUN mode and the subnet router on real machines, the Windows service, and the Docker image.

### Phase 3: Differentiators (6–8 weeks)
- **Status (2026-11-01):** exit nodes done on the client, carried over from Phase 2 (`ws up --exit-node`, fails closed, per-OS socket bypass). Next: Gateway, policy tests and `explain`, peer relays.
- QUIC relay, peer relays, NAT port prediction, UPnP/PCP
- Gateway (public ingress) + Serve with automatic TLS
- Policy tests + `explain` + GitOps sync
- SSH over the mesh + session recording
- Flow logs
- **Done when:** the CGNAT→CGNAT case gets a direct or peer-relay path, and a public HTTPS service is exposed with one command

### Phase 4: Scale and HA (4–6 weeks)
- Delta netmaps, load tests at 10k simulated nodes
- HA control plane (Postgres leader election, then Raft)
- Network lock, posture checks, quotas, JIT access, audit log
- **Done when:** killing the leader causes no data-plane disruption, and a policy push to 10k nodes finishes in under 1 s

### Phase 5: Mobile and polish (6–10 weeks)
- Android app (QR join, on-demand rules, battery mode), then iOS
- Multi-network client, multipath, post-quantum PSK
- MCP server, Terraform provider, Helm chart
- Security audit (internal first, then external before 1.0)

---

## 7. Security principles
- The control plane is **untrusted for traffic**: it never holds private keys, and nodes generate their own keys.
- Network lock gives defense in depth even against a compromised control server.
- Minimal attack surface: relays only see WireGuard ciphertext.
- Signed releases, reproducible builds, SBOM.
- Fuzz testing on the netmap parser, policy engine and relay framing.
- Admin actions logged and authenticated (OIDC + passkeys / TOTP for local users).

## 8. Non-goals (for now)
- Compatibility with official Tailscale clients
- Commercial SaaS hosting (self-hosting comes first; this could change later)
- Replacing general-purpose VPN providers for anonymity

## 9. Open questions
1. **License**: AGPLv3 for the server (keeps forks open) + BSD for the agent? Or Apache-2.0 everywhere for adoption?
2. **Control transport**: Connect-RPC over TLS, or Noise over WebSocket (better in hostile networks)? Supporting both is possible.
3. **Raft vs Postgres** for HA. Raft keeps the single-binary story; Postgres is simpler to operate for people who already run it.
4. Name and domain: `whalescale` (check trademark proximity to "Tailscale" before a public launch).
5. Is a desktop GUI (tray app) in Phase 2 or Phase 5?

## 10. Success metrics
- Install to first ping: **under 10 minutes**
- Direct-connection rate in a CGNAT test matrix: **above Tailscale's on the same setups**
- Relay throughput on Windows: **≥ 100 Mbps** on a 1 Gbps VPS
- Server RAM at 100 nodes: **< 128 MB**
- Policy propagation at 10k nodes: **< 1 s**

---

## Sources
- [headscale#3435 – Funnel support (not planned)](https://github.com/juanfont/headscale/issues/3435)
- [headscale#2845 – Tailscale Services](https://github.com/juanfont/headscale/issues/2845)
- [headscale#3548 – Make upgrades easier](https://github.com/juanfont/headscale/issues/3548)
- [headscale issues list (scale, quotas, web UI)](https://github.com/juanfont/headscale/issues)
- [Tailscale vs Headscale 2026 – VPNSmith](https://www.vpnsmith.com/en/blog/tailscale-vs-headscale-self-host-2026)
- [HN: Headscale in production](https://news.ycombinator.com/item?id=43563824)
- [tailscale#18017 – slow DERP uploads on Windows](https://github.com/tailscale/tailscale/issues/18017)
- [tailscale#3302 – on-demand / auto exit node](https://github.com/tailscale/tailscale/issues/3302)
- [tailscale#19623 – official MCP server request](https://github.com/tailscale/tailscale/issues/19623)
- [Tailscale blog – Peer relays across CGNAT (India → US)](https://tailscale.com/blog/peer-relays-international-networks)
- [AWS Marketplace Tailscale reviews (battery, blocking)](https://aws.amazon.com/marketplace/reviews/reviews-list/prodview-jvxfapco43wr4?page=2)
- [Mesh VPN comparison 2026 – wz-it](https://wz-it.com/en/blog/mesh-vpn-comparison-2026-overview/)
- [NetBird vs Headscale – SelfHost Atlas](https://selfhostatlas.com/compare/netbird-vs-headscale)
- [Headscale vs NetBird – selfhosting.sh](https://selfhosting.sh/compare/headscale-vs-netbird/)
- [Headscale vs NetBird vs Netmaker – fastfox.pro](https://fastfox.pro/blog/reviews/headscale-netbird-netmaker-vpn/)
- [OpenVPN blog – own your control plane](https://blog.openvpn.net/tailscale-headscale-alternatives-self-hosted-control-plane)
