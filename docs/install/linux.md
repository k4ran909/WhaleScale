# Linux server (one command)

The quickest way to run Whalescale: one command turns a Linux machine with systemd into a ready server, with HTTPS from Let's Encrypt.

## Before you start

| You need | Why |
|---|---|
| A Linux machine with systemd (Ubuntu, Debian, Fedora, RHEL…), amd64 or arm64 | Runs the server as a service |
| A domain name whose DNS points at it, e.g. `ws.example.com` | The address devices and browsers use, and the HTTPS certificate |
| **TCP 443** and **UDP 3478–3480** reachable from the internet | HTTPS (console, API, relay); STUN and the QUIC relay |

Nothing else to install: the server is one program with its own database (SQLite), certificates and relay.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/k4ran909/WhaleScale/main/deploy/install.sh | sh -s -- --server --domain ws.example.com --email you@example.com
```

When it finishes it prints the address and a **setup code**:

```
Whalescale server is running.

  Open        https://ws.example.com
  Setup code  ABCD-EFGH   (creates your admin account; works once)
```

Open the address, enter the setup code, and create your admin account. That page closes for good once the account exists. Then [add your devices](../guides/devices.md).

### What the command does

1. Downloads the latest release for this machine, checks its signature (when `minisign` is installed) and its checksum, and installs `whalescale`, `ws` and `wsd` to `/usr/local/bin`.
2. Creates a `whalescale` system user and writes `/etc/whalescale/config.yaml`: your domain, automatic HTTPS, STUN on 3478–3479 and the QUIC relay on 3480.
3. Checks the configuration (`whalescale configtest`).
4. Installs the hardened systemd unit ([`deploy/whalescale.service`](../../deploy/whalescale.service)) and starts it.
5. Opens TCP 443 and UDP 3478–3480 in `ufw` or `firewalld` if one is active. Cloud firewalls and security groups are up to you.
6. Prints the setup code from the server's log.

### Options

| Option | |
|---|---|
| `--domain NAME` | The server's name. Asked for if you leave it out. |
| `--email ADDRESS` | Contact for Let's Encrypt's expiry warnings. |
| `--gateway-domain NAME` | Let machines [publish services](../guides/gateway.md) at `<name>.NAME` (needs a wildcard DNS record `*.NAME`). |
| `--db postgres://…` | Use PostgreSQL instead of SQLite, to run [several servers](../guides/high-availability.md) that take over from each other. |
| `--version vX.Y.Z` | A specific release instead of the latest. |

## After installing

```bash
sudo whalescale doctor              # end-to-end checks: health, TLS, relays, STUN, OIDC
sudo journalctl -u whalescale -f    # the server's log
sudo whalescale setup-code          # the setup code again, until the first admin exists
```

Lost the admin password? `sudo whalescale admins reset-password NAME` prints a new one.

## Configuration

`/etc/whalescale/config.yaml` holds the settings; every key is a flag of `whalescale serve`, and [`deploy/config.example.yaml`](../../deploy/config.example.yaml) lists them with explanations. Put your own changes in `/etc/whalescale/conf.d/*.yaml` so upgrades never touch them, then:

```bash
sudo whalescale configtest          # every value and where it came from
sudo systemctl restart whalescale
```

Settings layer as: config file, then `conf.d/*.yaml` (upgrades never touch these), then `WHALESCALE_*` environment variables, then flags. Unknown keys are errors.

Using your own certificates instead of Let's Encrypt: replace `tls-acme: true` with `tls-cert:` and `tls-key:` paths.

## Upgrading

Run the same command again. It replaces the programs, keeps your configuration and data, and restarts the service.

## Uninstalling

```bash
sudo systemctl disable --now whalescale
sudo rm /etc/systemd/system/whalescale.service /usr/local/bin/{whalescale,ws,wsd}
sudo rm -r /etc/whalescale /var/lib/whalescale   # the configuration and the database: this deletes your network
```
