# Monitoring and operations

Flow logs, metrics, rate limits and the commands for running a server day to day.

- [Flow logs](#flow-logs)
- [Operations](#operations)

## Flow logs

Off by default, for privacy. With `flow-logs: true` on the server, every machine reports, every 30 seconds:

- each connection it took part in: who opened it, to which address and port, and bytes and packets each way;
- every inbound attempt the access policy refused.

Records stay on your server for `flow-log-retention` (default `168h`) and are pruned hourly. Each machine may store up to 1,000 records per 30 seconds (with bursts to 2,000); a machine reporting more has the excess dropped and counted in `whalescale_flow_records_dropped_total`.

```bash
$ whalescale flows --since 1h --denied
TIME      REPORTED BY  CLIENT  SERVER    PROTO  VERDICT  SENT  RECEIVED
14:02:31  nas          guest   nas:22    tcp    DENY     0 B   180 B
```

The console's Flows page shows the same, filterable by machine, time range and verdict. Logging never changes enforcement: it uses its own table, so policy changes still apply immediately, even to open connections.

## Operations

| Command | What |
|---|---|
| `whalescale configtest` | Validate config; show each value and its source |
| `whalescale doctor` | End-to-end checks of a running server |
| `whalescale users / preauthkeys / apikeys / nodes / routes / exposures` | Admin from the server host |
| `whalescale policy check FILE` | Validate, lint and run a policy file's tests |
| `whalescale policy explain SRC DST:PORT` | Why a connection is allowed or denied |
| `whalescale flows [--node N] [--since 1h] [--denied]` | Connection logs (with `flow-logs: true`) |
| `whalescale audit [--since 24h] [--actor X] [--action X] / --verify` | Audit log; check its hash chain |
| `whalescale access list [--all] / approve ID / deny ID / revoke ID` | Temporary access requests |
| `whalescale apikeys create --scope read` | An API key that can look but not change anything (monitoring, AI agents) |
| `ws mcp` | MCP server for AI agents |
| `wsd install-service / uninstall-service` | systemd, a Windows service or launchd |
| `GET /metrics` on `metrics-listen` (default `127.0.0.1:9090`) | Nodes, online count, direct/relay paths, relay traffic, map updates, snapshots, policy compiles and rate-limited requests |

Requests anyone can make (registering, browser logins, API key logins) are rate limited per client address: `rate-limit` per minute (60 by default; IPv6 counted per /64). Behind a reverse proxy on another host, list it in `trusted-proxies` so the limit applies to each client rather than to the proxy; `X-Forwarded-For` is believed only from those addresses and loopback.
