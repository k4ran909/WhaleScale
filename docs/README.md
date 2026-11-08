# Whalescale documentation

New here? Start with **[Getting started](getting-started.md)**: a server, an admin account and your first devices in about ten minutes.

## Install the server

| Guide | For |
|---|---|
| [Linux, one command](install/linux.md) | Any Linux machine with systemd. The quickest way. |
| [Docker Compose](install/docker.md) | Docker, with Caddy for HTTPS |
| [Dokploy](install/dokploy.md) | A Dokploy panel, behind its Traefik |
| [Kubernetes (Helm)](install/kubernetes.md) | A cluster, with an ingress and a UDP load balancer |

## Guides

| Guide | What it covers |
|---|---|
| [Adding devices](guides/devices.md) | Windows installer and tray icon, macOS and Linux, `.deb` and `.rpm` packages, join codes, several networks, verifying downloads |
| [Android app](guides/android.md) | Joining from a phone with a QR code, and building the APK |
| [Web console](guides/console.md) | Signing in, admin accounts, two-factor sign-in, API keys |
| [Access policy](guides/access-policy.md) | Rules, temporary access, device posture and limits, policy from Git, tests, "why can't A reach B?" |
| [Networking](guides/networking.md) | Subnet routers, exit nodes, relays and hard NATs, peer relays, port mapping, roaming and multipath |
| [SSH over the mesh](guides/ssh.md) | Key-free SSH by identity, and session recordings |
| [Gateway](guides/gateway.md) | Publish a service on the internet with HTTPS |
| [Security features](guides/security.md) | Network lock, post-quantum protection, audit log |
| [Monitoring and operations](guides/monitoring.md) | Flow logs, metrics, rate limits, everyday commands |
| [Automation](guides/automation.md) | AI agents (MCP), Terraform and OpenTofu |
| [High availability and scale](guides/high-availability.md) | Several servers with failover, and the numbers |

## Reference

| Page | |
|---|---|
| [Architecture](reference/architecture.md) | How the pieces fit, with diagrams |
| [Security review](reference/security-review.md) | Threat model, findings and what the server can and can't see |
| [Known gaps](reference/known-gaps.md) | What isn't done or tested yet |
| [Configuration example](../deploy/config.example.yaml) | Every server setting, explained |

## Development

| Page | |
|---|---|
| [Contributing](development/contributing.md) | Code layout, building and testing |
| [CI on Woodpecker](development/ci.md) | The self-hosted CI and release pipelines, and their secrets |
| [Real-world test plan](development/real-world-test.md) | Checks to run on real machines and networks |
| [Roadmap](../plan.md) | Phases, what's done and what's next |
