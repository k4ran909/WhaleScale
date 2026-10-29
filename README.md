# Whalescale

A self-hosted mesh VPN: control plane, relays, clients and web console, all yours. See [plan.md](plan.md) for the full vision and roadmap.

> **Status: Phase 0 (foundations).** Nodes can register with a pre-auth key and see each other in the network map. There is **no data plane yet**: no WireGuard tunnels until Phase 1.

## Layout

| Path | What |
|---|---|
| `cmd/whalescale` | Server: control plane + admin CLI |
| `cmd/ws` | Client CLI (`login`, `status`, `logout`) |
| `cmd/wsd` | Node agent (stub until Phase 1) |
| `proto/` | API definitions (protobuf, Connect-RPC) |
| `gen/` | Generated code (`make generate`, don't edit) |
| `internal/store` | SQLite store + embedded migrations |
| `internal/control` | ControlService implementation |
| `internal/clientstate` | Client machine key + credentials on disk |
| `web/` | Web console (Phase 2) |

## Quick start

```bash
make build                      # or: go build -o bin/ ./cmd/...

# server
bin/whalescale users create alice
bin/whalescale preauthkeys create --user alice --reusable --expiration 1h
bin/whalescale serve --listen 127.0.0.1:8080

# each PC
WS_AUTHKEY=wskey-... bin/ws login --server http://127.0.0.1:8080
bin/ws status

# back on the server
bin/whalescale nodes list
```

For anything beyond localhost, serve over TLS (`--tls-cert/--tls-key`, or a reverse proxy such as Caddy). Pre-auth keys and node tokens are bearer secrets.

## Development

Requires Go 1.27+. Codegen tools:

```bash
go install github.com/bufbuild/buf/cmd/buf@v1.57.0
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.6
go install connectrpc.com/connect/cmd/protoc-gen-connect-go@v1.18.1
make generate test
```

SQLite runs through `modernc.org/sqlite` (pure Go), so builds need no CGO. New schema changes go in `internal/store/migrations/NNNN_name.sql`. They are applied in order on startup, so a database can jump any number of versions at once.
