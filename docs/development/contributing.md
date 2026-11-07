# Contributing

Building, testing and finding your way around the code.

- [Layout](#layout)
- [Development](#development)

## Layout

| Path | What |
|---|---|
| `cmd/whalescale`, `cmd/wsd`, `cmd/ws` | Server, agent, CLI |
| `proto/`, `gen/` | APIs (protobuf / Connect-RPC) and generated code |
| `web/` | Console source (React + TS); `web/dist` is the committed build embedded in the server |
| `deploy/` | Docker Compose, Helm chart, install script, systemd unit, example config |
| `terraform/` | Terraform / OpenTofu provider (its own Go module) |
| `internal/store`, `internal/config` | SQLite + migrations; config layering |
| `internal/control`, `internal/server` | Control and admin APIs, network snapshots and deltas, OIDC, console, metrics |
| `internal/netmap` | Client side of map deltas |
| `internal/policy`, `internal/filter` | ACL compiler; stateful packet filter |
| `internal/meshconn`, `internal/disco`, `internal/stun`, `internal/relay` | Paths: direct vs relay |
| `internal/engine`, `internal/daemon`, `internal/localapi` | Agent core, lifecycle, `ws` ↔ `wsd` API |
| `internal/dnsserver`, `internal/osnet` | MagicDNS; per-OS addresses, routes, split DNS, forwarding |

## Development

Requires Go 1.27+ and Node 22 (only to rebuild the console).

```bash
make generate test      # protobuf codegen + tests (needs buf, protoc-gen-go, protoc-gen-connect-go)
make web                # rebuild web/dist after changing web/src (CI checks it is current)
cd web && npm run dev   # console dev server, proxying to a local server on :8080
```

CI runs on GitHub Actions (`.github/workflows/`) or on a self-hosted Woodpecker server (`.woodpecker/`, set up as in [CI on Woodpecker](ci.md), e.g. on Dokploy).

Fuzz targets cover everything that parses input from the network: policies, map deltas, QUIC relay frames, disco messages, packets entering the filter, DNS queries and machine proofs. Run one with `go test ./internal/disco -run '^$' -fuzz FuzzParse`.

End-to-end tests run real servers and agents in one process: direct paths, relay-only fallback, policy enforcement, subnet route approval, and OIDC console and device login against a fake identity provider (`internal/engine`, `internal/server`).
