# Whalescale

A self-hosted mesh VPN: control plane, relay, STUN, web console and clients, all yours. One server binary with SQLite. See [plan.md](plan.md) for the vision and roadmap.

> **Status: Phase 3 in progress.** WireGuard mesh with NAT traversal and relay fallback, MagicDNS, ACLs, a web console, OIDC login, subnet routers, exit nodes, a system service and `ws up/down`. See [Known gaps](#known-gaps).

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
echo "WS_DOMAIN=ws.example.com" > .env       # DNS must point here; open TCP 80/443, UDP 3478-3479
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
sudo whalescale doctor                        # checks health, TLS expiry, relay, both STUN ports, OIDC
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

## Operations

| Command | What |
|---|---|
| `whalescale configtest` | Validate config; show each value and its source |
| `whalescale doctor` | End-to-end checks of a running server |
| `whalescale users / preauthkeys / apikeys / nodes / routes` | Admin from the server host |
| `whalescale policy check FILE` | Validate and lint a policy file |
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
