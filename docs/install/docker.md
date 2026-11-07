# Docker Compose

Runs the server in Docker behind [Caddy](https://caddyserver.com/), which gets HTTPS certificates automatically. The files are in [`deploy/`](../../deploy).

## Before you start

- A machine with Docker and Docker Compose.
- A domain name whose DNS points at it, e.g. `ws.example.com`.
- **TCP 80 and 443** and **UDP 3478–3480** reachable from the internet.

## Install

```bash
git clone https://github.com/k4ran909/WhaleScale.git
cd WhaleScale/deploy
echo "WS_DOMAIN=ws.example.com" > .env
docker compose up -d
docker compose logs whalescale | grep setup_code   # the code that creates your admin account
```

Open `https://ws.example.com` and create your admin account with that setup code. Then [add your devices](../guides/devices.md).

## Options

Add these to `.env`:

| Variable | |
|---|---|
| `WS_DOMAIN` | The server's name (required). |
| `WS_GATEWAY_DOMAIN` | Let machines [publish services](../guides/gateway.md) at `<name>.WS_GATEWAY_DOMAIN` (needs a wildcard DNS record pointing here). |

Browser sign-in with an OpenID Connect provider and other settings go in [`docker-compose.yml`](../../deploy/docker-compose.yml) as `WHALESCALE_*` environment variables (every flag of `whalescale serve` has one).

## Day to day

```bash
docker compose exec whalescale whalescale doctor          # end-to-end checks
docker compose exec whalescale whalescale setup-code      # the setup code again, until the first admin exists
docker compose logs -f whalescale
git pull && docker compose up -d --build                  # upgrade
```

Prefer a ready-made image? Release builds publish `ghcr.io/k4ran909/whalescale` for amd64 and arm64; use it in place of `build: ..`.
