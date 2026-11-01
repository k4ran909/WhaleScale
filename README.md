# Whalescale

A self-hosted mesh VPN: control plane, relay, STUN, web console and clients, all yours. One server binary with SQLite. See [plan.md](plan.md) for the vision and roadmap.

> **Status: Phase 3 complete.** WireGuard mesh with NAT traversal and relay fallback, MagicDNS, ACLs, a web console, OIDC login, subnet routers, exit nodes, a gateway for publishing services on the internet, a system service and `ws up/down`. See [Known gaps](#known-gaps).

## How it fits together

```
 browser ──► web console ─┐
 ws login ───────────────►│ whalescale serve  (control API, admin API, relay, STUN, OIDC, metrics)
                          └──────────────┬──────────────────────────────┐
                                  wsd (node A)  ◄── WireGuard ──►  wsd (node B)
                                                 direct UDP, or via relay
```

- **`whalescale`** (server): registration, the network map stream, the policy engine, the admin API and web console, browser login (OIDC), an embedded relay (`/relay`, WebSocket), STUN (UDP) and Prometheus metrics.
- **`wsd`** (agent): wireguard-go plus a socket layer that finds direct paths (sealed disco pings, STUN, call-me-maybe hole punching) and falls back to the relay. It also runs the packet filter, the MagicDNS resolver and subnet routing.
- **`ws`** (CLI): `login`, `up`, `down`, `status`, `ping`, `netcheck`, `logout`.

## Server setup

### Docker (automatic HTTPS)

```bash
cd deploy
echo "WS_DOMAIN=ws.example.com" > .env       # DNS must point here; open TCP 80/443, UDP 3478-3480
docker compose up -d
docker compose exec whalescale whalescale users create karan
docker compose exec whalescale whalescale apikeys create     # sign in to https://ws.example.com with this
```

### Bare metal (Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/k4ran909/WhaleScale/main/deploy/install.sh | sh -s -- --server
sudoedit /etc/whalescale/config.yaml          # public-url, TLS; see deploy/config.example.yaml
sudo whalescale configtest                    # shows every value and where it came from
sudo systemctl enable --now whalescale
sudo whalescale doctor                        # checks health, TLS expiry, relays (WebSocket and QUIC), both STUN ports, OIDC
```

Settings layer as: config file, then `conf.d/*.yaml` (upgrades never touch these), then `WHALESCALE_*` environment variables, then flags. Unknown keys are errors.

## Adding devices

```bash
curl -fsSL https://raw.githubusercontent.com/k4ran909/WhaleScale/main/deploy/install.sh | sh   # installs ws + wsd service
sudo ws login --server https://ws.example.com   # opens a browser login (OIDC), or use WS_AUTHKEY=wskey-...
sudo ws up
ws status                                       # peers, direct/relay path, latency
ping laptop.whale.internal
```

On Windows, unzip the release, put [`wintun.dll`](https://www.wintun.net/) next to `wsd.exe`, and in an Administrator terminal run `wsd install-service`, then `ws login --server ...` and `ws up`.

## Web console

Served at the server's URL. Sign in with an API key (`whalescale apikeys create`), or with your identity provider if OIDC is configured (only emails in `oidc-admins` get in). Pages:

- **Machines:** online state, addresses, OS and routes.
- **Topology:** a from/to matrix showing direct or relayed paths, with latency, as the nodes report it.
- **Users**, **Keys** (pre-auth and API keys) and **Routes** (approve subnets and exit nodes).
- **Access policy:** an editor with live validation and lint warnings.

## Subnet routers

On a Linux machine in your LAN (OS TUN mode):

```bash
sudo ws up --advertise-routes 192.168.1.0/24
```

Approve the route in the console (Routes), or with `whalescale routes approve <machine> 192.168.1.0/24`. Other machines use it once they opt in with `ws up --accept-routes`. The router enables forwarding and masquerades mesh traffic, and undoes both on shutdown.

## SSH over the mesh

Log in to your machines without managing SSH keys: your mesh identity is the credential, and the access policy decides who may log in where, and as which local user.

```json
"ssh": [
  { "action": "accept", "src": ["group:admins"], "dst": ["node:nas"], "users": ["root", "$user"], "record": true }
]
```

```bash
sudo ws up --ssh              # on the server machine (Linux or macOS)
ws ssh karan@nas              # from any machine; or plain: ssh karan@nas.whale.internal
```

- **Identity:** the source mesh address identifies the person. WireGuard ties every peer's addresses to its key, so they can't be spoofed (the same model Tailscale SSH uses).
- **Local users:** `"$user"` means "your own username on the mesh". An SSH rule also opens TCP 22 from its sources, and nothing else.
- **No host-key prompts:** each machine's SSH host key is distributed in the network map. `ws ssh` hands it to your `ssh` client.
- **Recording:** with `"record": true`, session output (never keystrokes) is recorded in asciinema format and uploaded to the server. If the upload fails, a copy is kept on the machine. Admins can view or download recordings in the console (SSH recordings); downloads play with `asciinema play`.
- **What's supported:** shells, commands, PTYs and window resizing. Not SFTP, port forwarding, or a Windows SSH server yet.

## Flow logs

Off by default, for privacy. With `flow-logs: true` on the server, every machine reports, every 30 seconds:

- each connection it took part in: who opened it, to which address and port, and bytes and packets each way;
- every inbound attempt the access policy refused.

Records stay on your server for `flow-log-retention` (default `168h`) and are pruned hourly.

```bash
$ whalescale flows --since 1h --denied
TIME      REPORTED BY  CLIENT  SERVER    PROTO  VERDICT  SENT  RECEIVED
14:02:31  nas          guest   nas:22    tcp    DENY     0 B   180 B
```

The console's Flows page shows the same, filterable by machine, time range and verdict. Logging never changes enforcement: it uses its own table, so policy changes still apply immediately, even to open connections.

## Router port mapping

`wsd` asks your home router to forward its WireGuard UDP port, trying PCP, then NAT-PMP, then UPnP. When that works, peers connect directly with no manual port forward. The mapping is renewed at half its lifetime and removed when `wsd` stops. Turn it off with `wsd --portmap=false`.

`ws netcheck` shows what the router supports. It also warns about double NAT, where the router's own "public" address is private or CGNAT (common with Jio and Airtel home connections): a mapping can't help there, and a peer relay is the answer.

For UPnP, the agent only uses the router's answer, and only follows a description URL that points back at the router, so another device on the LAN can't redirect it.

## Relays and hard NATs

When two machines can't connect directly, Whalescale tries, in order:

1. **Hole punching:** STUN, simultaneous pings, and router port mapping.
2. **Symmetric-NAT port prediction:** when a peer's NAT gives every destination its own port (it reports two STUN ports on one IP), nodes probe the ports that NAT will likely hand out next. That breaks the hardest common case, symmetric NAT against a restrictive NAT, whenever the NAT allocates ports in sequence.
3. **A peer relay:** see below.
4. **The server relay, preferably over QUIC:** UDP datagrams on `relay-quic-listen` (default `:3480`). This avoids the slowdown of tunneling TCP inside the TCP-based WebSocket relay. The relay's self-signed certificate is pinned through the network map, so it needs no public CA and works behind Caddy. Where UDP is blocked, nodes fall back to the WebSocket relay over HTTPS and retry QUIC every 10 minutes. `ws status` shows which one is in use.

## Peer relays

When two machines can't connect directly (both behind strict or carrier-grade NAT, as on Jio and Airtel mobile data), their traffic goes through the server's WebSocket relay. A peer relay is a faster UDP path. Any well-connected machine, such as a VPS or a home server with a port forward, can offer to forward for the others:

```bash
sudo ws up --relay                  # on the well-connected machine
whalescale relays approve vps       # on the server, or approve it under Routes in the console
ws status                           # peers now show "peer-relay via vps"
```

- **Path order:** direct first, then a peer relay (only after a ping through it succeeds), then the server relay.
- **No new port:** it uses the machine's existing WireGuard UDP socket, so a port forward or NAT mapping it already has keeps working.
- **What it sees:** only WireGuard ciphertext and sealed discovery messages.
- **Who it serves:** only nodes the server lists. Registrations are sealed with each node's discovery key, and forwarding is accepted only from the address a node registered from, so nobody can register or send as another node.
- **Withdrawal is safe:** taking approval away falls back to the server relay without dropping connections.

## Exit nodes

Send all of a device's internet traffic through another machine, such as your home server when you're on café Wi-Fi.

```bash
sudo ws up --advertise-exit-node          # on the exit machine (Linux); approve it under Routes
sudo ws up --exit-node homelab            # on the device; --exit-node= (empty) stops
ws status                                 # "exit node: homelab (active)"
```

- **Fails closed.** If the exit node goes offline, internet traffic is blocked rather than leaking out of the local network, and resumes when it returns.
- **Your LAN keeps working** (printers, the router's admin page), because local routes still win.
- **The agent's own traffic stays off the tunnel** (WireGuard, discovery, the control connection, the relay):
  - Linux: socket marks and policy routing, as wg-quick does.
  - Windows: sockets pinned to the physical adapter (`IP_UNICAST_IF`).
  - macOS: sockets pinned with `IP_BOUND_IF`.
  - Switching networks (say, Wi-Fi to Ethernet) is picked up within 10 s.
- **Policy:** exit traffic must be allowed by the policy. Allow-all covers it; otherwise grant `0.0.0.0/0:*` and `::/0:*` to the users who may use exit nodes.

## Gateway: publish a service on the internet

A self-hosted counterpart to Tailscale Funnel. A machine publishes a local web app at `https://<name>.<gateway domain>`, even from behind CGNAT. No port forwarding is needed.

1. **On the server:** set `gateway-domain: apps.example.com` and add a wildcard DNS record `*.apps.example.com` pointing at the server. For HTTPS, either:
   - set `tls-acme: true`: the server gets Let's Encrypt certificates itself, and port 443 must be reachable; or
   - use the Docker Compose setup with `WS_GATEWAY_DOMAIN`: Caddy gets certificates on demand.
2. **On the machine:**

   ```bash
   ws expose 8123 --name ha        # publishes http://localhost:8123
   ws expose                       # shows the public URL and whether it is live
   ws expose --remove ha
   ```

3. **Approve it:** in the console (Gateway) or with `whalescale exposures approve ha`. Until then nothing is reachable.

How it works and what keeps it safe:

- The machine keeps one WebSocket to the server and multiplexes requests over it (yamux).
- Each request names the service, and the machine only ever connects to its own localhost ports that it chose to expose.
- Certificates are only requested for live names, so strangers can't make the server request certificates for arbitrary hosts.
- Names are first come, first served across all machines, and changing a published port needs approval again.
- WebSockets and streaming responses pass through.
- Apps see the visitor's address in `X-Forwarded-For`. The header is trusted from a reverse proxy on a private network, such as Caddy.

## Access policy

Without one, every node can reach every other node. Edit it in the console, or point `policy:` at a JSON file (the server reloads it within 5 s; an invalid file keeps the previous policy). Receiving nodes drop anything not allowed. Replies to a node's own connections are always let back in.

```json
{
  "groups": { "group:admins": ["karan"] },
  "acls": [
    { "action": "accept", "src": ["group:admins"], "dst": ["*:*"] },
    { "action": "accept", "src": ["guest"], "dst": ["node:nas:445,8000-8100"] },
    { "action": "accept", "src": ["karan"], "dst": ["192.168.1.0/24:*"] }
  ]
}
```

Selectors are `*`, a user, `group:NAME`, `node:NAME` or a CIDR. A CIDR destination grants access through subnet routers that serve it. A user or node selector grants that device only, not the networks behind it.


### Policy from a Git repository

Keep the policy in Git and review changes like code. Point the server at the file's raw URL on a branch:

```yaml
policy-url: https://raw.githubusercontent.com/you/infra/main/whalescale/policy.json
policy-url-token-file: /etc/whalescale/repo-token       # private repositories
policy-webhook-secret-file: /etc/whalescale/hook-secret # optional push webhook
```

- **How updates arrive:** the server polls with ETags every `policy-sync-interval` (default 1 minute). A push webhook to `POST /policy/sync` applies changes at once; it verifies GitHub and Gitea HMAC signatures and the GitLab token.
- **Bad versions are refused:** a version that doesn't parse, or fails its own `tests`, is refused, and the previous policy stays in force.
- **Outages:** the last good copy is cached, so a restart while the repository is unreachable still enforces it. With no copy at all, the server refuses to start rather than run without your policy.
- **Read-only elsewhere:** the console shows the policy as read-only, with the revision, last sync time and any sync error.

### Policy tests

Pin down intent with `tests`. A policy that fails its own tests is refused when saved in the console, when a policy file is reloaded, and by `whalescale policy check`. At server startup failures are only logged, so an outdated test can't lock anyone out.

```json
"tests": [
  { "src": "guest", "accept": ["node:nas:445"], "deny": ["karan:22"] },
  { "src": "karan", "accept": ["192.168.1.10:443"] }
]
```

`src` is a user, `node:NAME` or an IP. `accept` and `deny` entries are `<user|node:NAME|IP>:<port>`.

### Why can't A reach B?

```bash
$ whalescale policy explain guest karan:22
guest → karan port 22: DENIED  (using the policy saved in the console)
  - acls[1]: guest → karan:80,443 covers guest → karan but only ports 80,443
  - acls[0]: group:admins → *:* would allow it for sources group:admins
  - replies to connections karan opens to guest are still allowed
```

The console's Access policy page has the same "Explain access" panel, and it evaluates your unsaved edits. For subnet addresses, explain also warns when the policy allows something that no approved router serves.

## Operations

| Command | What |
|---|---|
| `whalescale configtest` | Validate config; show each value and its source |
| `whalescale doctor` | End-to-end checks of a running server |
| `whalescale users / preauthkeys / apikeys / nodes / routes / exposures` | Admin from the server host |
| `whalescale policy check FILE` | Validate, lint and run a policy file's tests |
| `whalescale policy explain SRC DST:PORT` | Why a connection is allowed or denied |
| `whalescale flows [--node N] [--since 1h] [--denied]` | Connection logs (with `flow-logs: true`) |
| `wsd install-service / uninstall-service` | systemd, a Windows service or launchd |
| `GET /metrics` on `metrics-listen` (default `127.0.0.1:9090`) | Nodes, online count, direct/relay paths, relay traffic |

## Layout

| Path | What |
|---|---|
| `cmd/whalescale`, `cmd/wsd`, `cmd/ws` | Server, agent, CLI |
| `proto/`, `gen/` | APIs (protobuf / Connect-RPC) and generated code |
| `web/` | Console source (React + TS); `web/dist` is the committed build embedded in the server |
| `deploy/` | Docker Compose, install script, systemd unit, example config |
| `internal/store`, `internal/config` | SQLite + migrations; config layering |
| `internal/control`, `internal/server` | Control and admin APIs, OIDC, console, metrics |
| `internal/policy`, `internal/filter` | ACL compiler; stateful packet filter |
| `internal/meshconn`, `internal/disco`, `internal/stun`, `internal/relay` | Paths: direct vs relay |
| `internal/engine`, `internal/daemon`, `internal/localapi` | Agent core, lifecycle, `ws` ↔ `wsd` API |
| `internal/dnsserver`, `internal/osnet` | MagicDNS; per-OS addresses, routes, split DNS, forwarding |

## Known gaps

- **OS TUN mode and the Linux subnet router have not been run on real machines.** Userspace mode is covered by end-to-end tests. The Windows service and Docker image are also untested.
- **Exit nodes**: the exit side (forwarding + NAT) is Linux-only; DNS queries still go to the device's own DNS servers rather than through the exit node.
- Subnet routing is Linux-only for now.
- Nodes authenticate with a bearer token rather than a Noise handshake bound to the machine key.
- Discovery pings every peer every 3 s, which is fine for small networks; limiting it to active peers is Phase 4 work.

## Development

Requires Go 1.27+ and Node 22 (only to rebuild the console).

```bash
make generate test      # protobuf codegen + tests (needs buf, protoc-gen-go, protoc-gen-connect-go)
make web                # rebuild web/dist after changing web/src (CI checks it is current)
cd web && npm run dev   # console dev server, proxying to a local server on :8080
```

End-to-end tests run real servers and agents in one process: direct paths, relay-only fallback, policy enforcement, subnet route approval, and OIDC console and device login against a fake identity provider (`internal/engine`, `internal/server`).
