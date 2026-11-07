# Networking

How traffic moves: subnet routers, exit nodes, relays for hard NATs, peer relays, router port mapping, roaming and multipath.

- [Subnet routers](#subnet-routers)
- [Exit nodes](#exit-nodes)
- [Relays and hard NATs](#relays-and-hard-nats)
- [Peer relays](#peer-relays)
- [Router port mapping](#router-port-mapping)
- [Roaming and multipath](#roaming-and-multipath)

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
- **DNS goes through the exit node too.** The device's MagicDNS resolver sends every lookup (not just mesh names) over the tunnel to the exit node, which resolves it with its own resolvers. Neither the café's DNS server nor anyone watching that network sees which sites you look up. While the exit node can't be used, lookups fail rather than fall back to the local resolver. The OS is pointed at MagicDNS for all names on Linux (systemd-resolved) and Windows (NRPT); macOS still sends only mesh names there.
- **Your LAN keeps working** (printers, the router's admin page), because local routes still win.
- **The agent's own traffic stays off the tunnel** (WireGuard, discovery, the control connection, the relay):
  - Linux: socket marks and policy routing, as wg-quick does.
  - Windows: sockets pinned to the physical adapter (`IP_UNICAST_IF`).
  - macOS: sockets pinned with `IP_BOUND_IF`.
  - Switching networks (say, Wi-Fi to Ethernet) is picked up within 10 s.
- **Policy:** exit traffic must be allowed by the policy. Allow-all covers it; otherwise grant `0.0.0.0/0:*` and `::/0:*` to the users who may use exit nodes.

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

## Router port mapping

`wsd` asks your home router to forward its WireGuard UDP port, trying PCP, then NAT-PMP, then UPnP. When that works, peers connect directly with no manual port forward. The mapping is renewed at half its lifetime and removed when `wsd` stops. Turn it off with `wsd --portmap=false`.

`ws netcheck` shows what the router supports. It also warns about double NAT, where the router's own "public" address is private or CGNAT (common with Jio and Airtel home connections): a mapping can't help there, and a peer relay is the answer.

For UPnP, the agent only uses the router's answer, and only follows a description URL that points back at the router, so another device on the LAN can't redirect it.

## Roaming and multipath

Connections survive the network changing under them:

- **Dead paths are noticed in about 2 seconds.**
  - While traffic flows over a direct path that has gone quiet, the machine probes it, and an unanswered probe moves traffic to a relay at once.
  - Seeing a peer's traffic arrive through a relay is treated as a sign its direct path just died.
  - Before this, a dead path was only dropped after its 6.5-second trust window.
- **Network changes trigger an immediate recheck.** When the machine's addresses change (Wi-Fi off, onto cellular), it does four things right away:
  - reconnects the relay, whose old connection may be silently dead;
  - re-runs STUN;
  - advertises its new addresses;
  - re-proves every direct path, keeping traffic on the relay meanwhile.
- **`ws up --multipath`** sends every packet over the direct path *and* a relay. WireGuard drops whichever copy arrives second, so a dying link loses nothing; in tests, cutting the direct path left no gap beyond the normal packet spacing. It uses twice the bandwidth while a direct path is up, so it's for links where a two-second blip matters (calls, SSH over flaky Wi-Fi).
