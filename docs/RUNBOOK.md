# Running WhaleScale end-to-end (no Docker)

You only need **PostgreSQL** + the Rust toolchain + Node/pnpm. Docker is optional —
any Postgres works, including a **free serverless one** you can create in a browser.

## 1. Get a Postgres (pick one)

- **Free cloud (no install):** create a project at <https://neon.tech> or
  <https://supabase.com>. Copy the connection string, e.g.
  `postgres://USER:PASS@HOST/db?sslmode=require`.
- **Local install:** install PostgreSQL, then
  `createdb whalescale` → `postgres://localhost/whalescale`.

```bash
cp .env.example .env
# edit .env: set DATABASE_URL to your connection string, and a real JWT_SECRET
```

> The coordinator runs migrations automatically on startup — no manual SQL.

## 2. Start the control plane

Open three terminals (or run them in the background):

```bash
# Coordinator (applies migrations, serves :8080). Advertise a relay so agents
# get a fallback path:
RELAY_ADDR=127.0.0.1:3479 cargo run -p ws-coordinator

# STUN server (endpoint discovery)
STUN_BIND=0.0.0.0:3478 cargo run -p ws-stun-server

# Relay (DERP-style fallback). Set RELAY_JWT_SECRET to the same value as the
# coordinator's JWT_SECRET so the relay only accepts authenticated clients.
RELAY_BIND=0.0.0.0:3479 RELAY_JWT_SECRET="$JWT_SECRET" cargo run -p ws-relay
```

Sanity check: `curl localhost:8080/healthz` → `{"status":"ok"}`.

## 3. Create an org + credentials

```bash
curl -s -XPOST localhost:8080/dev/bootstrap | jq
# -> { auth_key: "ws-...", login: { email: "owner@dev", password: "whalescale" }, ... }
```

## 4. Open the dashboard

```bash
cd dashboard && pnpm install && pnpm dev   # http://localhost:5173
```
Sign in with `owner@dev` / `whalescale`. You'll see the live device table, network
map, ACL editor, and audit log — all talking to the real coordinator.

## 5. Enroll agents

**Two separate machines** (best — shows real NAT traversal). On each:

```bash
WS_AUTH_KEY=ws-... \
STUN_SERVER=<coordinator-host>:3478 \
WS_BACKEND=wgquick WS_IFACE=whale0 \
WS_DNS_BIND=127.0.0.1:5353 \
sudo -E cargo run -p ws-agent-cli
```
Then from one node: `ping 100.64.0.2`, or with MagicDNS configured
(`echo "nameserver 127.0.0.1" ...`): `ping <other-hostname>`.

**Single machine (quick demo, LogBackend)** — the agents print the WireGuard
config instead of creating interfaces, so give each its own DNS port and skip STUN
(both can't bind the same WG port locally):

```bash
# agent A
WS_AUTH_KEY=ws-... WS_HOSTNAME=node-a WS_DNS_BIND=127.0.0.1:5353 cargo run -p ws-agent-cli
# agent B (another terminal)
WS_AUTH_KEY=ws-... WS_HOSTNAME=node-b WS_DNS_BIND=127.0.0.1:5354 cargo run -p ws-agent-cli
```
Both appear in the dashboard with their `100.64.x.x` addresses; the rendered
configs list each other as peers.

### Exit node / subnet router
Add `WS_ADVERTISE_ROUTES` when enrolling:
```bash
WS_ADVERTISE_ROUTES=0.0.0.0/0        cargo run -p ws-agent-cli   # exit node
WS_ADVERTISE_ROUTES=192.168.1.0/24   cargo run -p ws-agent-cli   # subnet router
```
Peers' network maps will list those CIDRs in the node's AllowedIPs.

## 6. Try MagicDNS
With an agent's MagicDNS bound at `127.0.0.1:5353`:
```bash
nslookup -port=5353 node-b 127.0.0.1     # -> 100.64.0.x
```

## 7. Lock it down with an ACL
In the dashboard's **ACL Policy** page, e.g.:
```json
{ "groups": { "group:eng": ["owner@dev"] },
  "acls": [ { "action": "accept", "src": ["group:eng"], "dst": ["*:*"] } ] }
```
Save — connected agents immediately receive filtered maps.

---

### Notes
- `/dev/bootstrap` and the open helpers are **dev-only**; remove before production.
- Real interfaces (`WS_BACKEND=wgquick`) need `wireguard-tools` + root on Linux/macOS.
- Binding MagicDNS to `:53` (instead of `:5353`) needs privileges but lets the OS
  resolver use it directly.
