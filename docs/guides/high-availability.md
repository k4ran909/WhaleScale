# High availability and scale

Run several servers that take over from each other, and what one server handles.

- [Several servers (failover)](#several-servers-failover)
- [Scale](#scale)

## Several servers (failover)

Run two or more servers against one PostgreSQL database, on different hosts, and a server can fail without taking the network with it:

```yaml
# on every server: the same database, its own public URL
db: postgres://whalescale:PASSWORD@db.internal:5432/whalescale?sslmode=require
public-url: https://ws1.example.com     # ws2.example.com on the second, ...
```

```bash
whalescale cluster      # who's up, and who leads
```

- **Machines keep working through a server failure.** Every machine learns every running server's address. When its server stops or crashes, it moves to another within about a second.
- **Direct connections don't notice.** WireGuard traffic between machines never goes through a server; the failover test sends traffic continuously while a server dies and loses none.
- **Relayed connections pause briefly.** All machines use the oldest running server's relay, so they meet on the same one. If that server goes away they move to the next: at once on a clean shutdown, or within the heartbeat timeout (3× the watch interval, 15 s by default) after a crash.
- **Changes reach every server.** A change made on one server (a policy save, an approval, a machine joining) reaches machines on the others within a quarter of a second. Who is online is shared too.
- **One leader for periodic jobs.** One server at a time holds the leader lease and runs grant expiry, log pruning and Git policy sync. Another takes over when it stops (`whalescale_leader` in `/metrics`).
- **The database is the one shared piece.** Make PostgreSQL itself highly available (a managed service, or Patroni) to remove the last single point of failure. Back it up with `pg_dump`.
- **On a single host,** servers can instead share an SQLite file (each with its own `listen`, `public-url`, `stun-listen` and `relay-quic-listen`). That covers crashes and zero-downtime upgrades without running PostgreSQL.

Some things still belong to one server:
- a browser login must finish on the server that started it;
- a gateway tunnel serves public requests only on its own server;
- SSH recordings are saved on the server that received them (point `recordings-dir` at shared storage to view them from any server);
- the console's topology view shows the paths of that server's machines.

## Scale

Each change to the network (a node coming online, an endpoint moving, a policy push) is turned into one shared snapshot. Every node then gets only the part that concerns it: changed peers, a new packet filter, or nothing at all. The policy compiler works on groups of nodes with identical access rather than on node pairs, and merges source addresses into CIDRs, so `"*"` over 10,000 machines costs a few prefixes rather than 20,000.

`make loadtest` connects 10,010 simulated nodes (100 teams, shared servers) to one control server and times policy pushes. On a laptop (i5-10200H):

| | Time to reach all 10,010 nodes | Sent |
|---|---|---|
| Policy push changing ports | 0.1–0.25 s | 4 MB |
| Policy push giving every node 100 more peers | 0.4–1.3 s, depending on machine load | 390 MB |
| All nodes connecting at once | ~0.5 s | 240 MB |

Older clients that don't ask for deltas still get complete maps, now only when something relevant to them changed.

On the machines themselves, path discovery is lazy in networks of more than 100 peers. Only peers with WireGuard traffic in the last two minutes are kept probed, and `ws status` shows the rest as `idle`. The first packets to an idle peer go through the relay at once while a direct path is found, usually within a round trip or two. Smaller networks keep every path warm.
