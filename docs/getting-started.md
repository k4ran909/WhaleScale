# Getting started

From nothing to two devices talking to each other, in about ten minutes.

## 1. Run the server

On a Linux machine whose domain name points at it (open TCP 443 and UDP 3478–3480):

```bash
curl -fsSL https://raw.githubusercontent.com/k4ran909/WhaleScale/main/deploy/install.sh | sh -s -- --server --domain ws.example.com
```

It installs the server with automatic HTTPS and prints a **setup code**. Prefer containers or a platform? See [Docker](install/docker.md), [Dokploy](install/dokploy.md) or [Kubernetes](install/kubernetes.md).

## 2. Create your admin account

Open `https://ws.example.com`, enter the setup code, and choose your name and password. The setup page closes for good once the account exists. You can turn on [two-factor sign-in](guides/console.md) from the sidebar.

## 3. Add your devices

In the dashboard, **Machines → Add device** makes a *join code* and shows the steps for each system:

| Device | How |
|---|---|
| **Windows** | Run `whalescale-setup-windows-amd64.exe` from the [latest release](https://github.com/k4ran909/WhaleScale/releases/latest) and paste the join code. A tray icon shows the connection. |
| **macOS, Linux** | `curl -fsSL https://raw.githubusercontent.com/k4ran909/WhaleScale/main/deploy/install.sh \| sh -s -- --join <join code>` |

Each device appears on the Machines page as it joins.

## 4. Use it

```bash
ws status                    # your devices, and whether each path is direct or relayed
ping laptop.whale.internal   # every device has a name
```

Next: decide who can reach what with the [access policy](guides/access-policy.md), or reach a whole LAN through a [subnet router](guides/networking.md#subnet-routers).

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

The [architecture](reference/architecture.md) page explains it with diagrams: keys, the network map, and how devices find a direct path through routers.
