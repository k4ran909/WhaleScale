# Whalescale

A self-hosted mesh VPN: control plane, relay, STUN, clients and (soon) a web console, all yours. See [plan.md](plan.md) for the vision and roadmap.

> **Status: Phase 1 (MVP mesh).** Nodes get WireGuard tunnels to each other, with direct paths found by NAT hole punching and a WebSocket relay as fallback. MagicDNS names, an ACL policy and `ws status/ping/netcheck` all work. Tested end to end in userspace mode. OS TUN mode is implemented for Linux, Windows and macOS but not yet tested on real machines; see [Known gaps](#known-gaps).

## How it fits together

```
 ws login ──► whalescale serve ◄── wsd (node A)      wsd (node B)
              control API + relay + STUN      ▲  WireGuard  ▲
                                              └── direct UDP ┘   (or via relay)
```

- **`whalescale`** (server): registration, the network map stream, the policy engine, an embedded relay (`/relay`, WebSocket) and STUN (UDP).
- **`wsd`** (agent): wireguard-go plus a custom socket layer that finds direct paths (sealed disco pings, STUN, call-me-maybe hole punching) and falls back to the relay. It also runs the packet filter and a MagicDNS resolver.
- **`ws`** (CLI): `login`, `status`, `ping`, `netcheck`, `logout`.

## Quick start

On the server (a VPS with a public IP is ideal):

```bash
whalescale users create karan
whalescale preauthkeys create --user karan --reusable --expiration 24h
whalescale serve --listen :443 --tls-cert cert.pem --tls-key key.pem \
  --public-url https://ws.example.com --stun-listen :3478,:3479
```

Open TCP 443 and UDP 3478–3479. Two STUN ports let nodes detect symmetric NAT.

On each PC (as root / Administrator for OS TUN mode):

```bash
WS_AUTHKEY=wskey-... ws login --server https://ws.example.com
wsd                       # real interface; or: wsd --tun=userspace (no admin)
ws status                 # peers + direct/relay path + latency
ws ping laptop            # "pong from laptop via 203.0.113.7:41641 in 12ms"
ws netcheck               # public address, NAT type, relay reachability
ping laptop.whale.internal
```

Run `ws` and `wsd` as the same user so they share the state file and socket. On Windows, OS TUN mode needs [`wintun.dll`](https://www.wintun.net/) next to `wsd.exe`.

## Access policy

Without `--policy`, every node can reach every other node. With a policy, anything not allowed is dropped by the receiving node, and replies to connections a node opened itself are still let in:

```json
{
  "groups": { "group:admins": ["karan"] },
  "acls": [
    { "action": "accept", "src": ["group:admins"], "dst": ["*:*"] },
    { "action": "accept", "src": ["guest"], "dst": ["node:nas:445,8000-8100"] }
  ]
}
```

Selectors are `*`, a user name, `group:NAME`, `node:NAME` or a CIDR. Check a policy with `whalescale policy check policy.json`. Unknown fields and undefined groups are errors, not silent no-ops. The server reloads the file within 5 s of a change, and if a new version is invalid it keeps the old one.

## Layout

| Path | What |
|---|---|
| `cmd/whalescale`, `cmd/wsd`, `cmd/ws` | Server, agent, CLI |
| `proto/`, `gen/` | API (protobuf / Connect-RPC) and generated code |
| `internal/store` | SQLite + ordered migrations |
| `internal/control`, `internal/server` | Control API, network maps, server assembly |
| `internal/policy`, `internal/filter` | ACL compiler; stateful per-node packet filter |
| `internal/meshconn` | WireGuard `conn.Bind`: path discovery, direct vs relay |
| `internal/disco`, `internal/stun`, `internal/relay` | Sealed ping/pong/call-me-maybe; STUN; WebSocket relay |
| `internal/engine`, `internal/localapi` | Agent core; `ws` ↔ `wsd` socket API |
| `internal/dnsserver`, `internal/osnet` | MagicDNS; per-OS address/route/split-DNS setup |

## Known gaps

- **OS TUN mode is untested on real machines.** The Linux (`ip`, `resolvectl`), Windows (`netsh`, NRPT) and macOS (`ifconfig`, `/etc/resolver`) paths compile but haven't been run yet. Userspace mode is covered by the end-to-end tests.
- **No CGNAT test yet.** The Phase 1 acceptance test (3 PCs, one behind CGNAT) needs real hardware.
- `wsd` runs in the foreground. A service install and `ws up/down` come in Phase 2.
- Nodes still authenticate with a bearer token rather than a Noise handshake bound to the machine key.
- Discovery pings every peer every 3 s, which is fine for small networks. Limiting it to active peers is Phase 4 work.
- Linux uses wireguard-go, not kernel WireGuard.

## Development

Requires Go 1.27+.

```bash
go install github.com/bufbuild/buf/cmd/buf@v1.57.0
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.6
go install connectrpc.com/connect/cmd/protoc-gen-connect-go@v1.18.1
make generate test
```

`internal/engine` has the end-to-end tests: a real server and two agents in one process, covering the direct path, relay-only fallback and policy enforcement. Set `WS_TEST_LOG=1` to see their logs. SQLite is pure Go (`modernc.org/sqlite`), so builds need no CGO.
