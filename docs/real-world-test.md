# Real-world test plan

Everything Phases 0–2 built that the automated tests can't cover: a real VPS, real interfaces, real NAT. Work through it top to bottom and tick each box. When something fails, keep the output of `ws status`, `ws netcheck`, `wsd --verbose` (or the service log) and `whalescale doctor`. That's what's needed to debug it.

**You need:**
- A VPS with a public IPv4 address and a DNS name pointing at it (any $4–6/month box: Hetzner, DigitalOcean, Oracle free tier...).
- Your Windows PC.
- A Linux machine (a second PC, a Raspberry Pi, or WSL won't do: it needs real interfaces).
- Ideally, one device behind CGNAT: a laptop tethered to mobile data (Jio/Airtel 4G/5G is CGNAT).

There are no release downloads yet, so build the binaries yourself:

```bash
# on your PC, in the repo
GOOS=linux  GOARCH=amd64 go build -o dist/linux/   ./cmd/...
GOOS=windows GOARCH=amd64 go build -o dist/windows/ ./cmd/...
# (use GOARCH=arm64 for a Raspberry Pi 4/5 or an ARM VPS)
```

---

## 1. Server on the VPS (target: under 15 minutes)

Start a timer: this step is Phase 2's "replace Headscale in 15 minutes" goal.

**Option A, Docker** (needs Docker on the VPS):

```bash
git clone https://github.com/k4ran909/WhaleScale && cd WhaleScale/deploy
echo "WS_DOMAIN=ws.example.com" > .env
docker compose up -d --build
docker compose exec whalescale whalescale users create karan
docker compose exec whalescale whalescale apikeys create
docker compose exec whalescale whalescale preauthkeys create --user karan --reusable --expiration 24h
```

**Option B, bare metal:**

```bash
scp dist/linux/whalescale root@VPS:/usr/local/bin/
ssh root@VPS
useradd --system --home /var/lib/whalescale --shell /usr/sbin/nologin whalescale
mkdir -p /etc/whalescale/conf.d
# copy deploy/config.example.yaml to /etc/whalescale/config.yaml and set public-url + TLS
# (certbot certonly --standalone -d ws.example.com gives you the cert files)
whalescale configtest
cp deploy/whalescale.service /etc/systemd/system/ && systemctl daemon-reload && systemctl enable --now whalescale
```

Open the firewall: **TCP 443** (and 80 for Docker/Caddy), **UDP 3478 and 3479**.

- [ ] `whalescale doctor` (Docker: `docker compose exec whalescale whalescale doctor`) shows no ✘
- [ ] `https://ws.example.com` shows the console sign-in; the API key signs you in
- [ ] Timer stopped at: ____ min (goal: < 15)

## 2. Windows PC (OS TUN mode)

1. Download `wintun.dll` (amd64) from https://www.wintun.net/ and put it next to `wsd.exe`.
2. In an **Administrator** PowerShell, in the folder with the binaries:

```powershell
.\wsd.exe install-service
$env:WS_AUTHKEY = "wskey-..."
.\ws.exe login --server https://ws.example.com
.\ws.exe up
.\ws.exe status
```

- [ ] `install-service` succeeds; `Get-Service Whalescale` shows Running
- [ ] `Get-NetAdapter Whalescale` exists with address 100.64.x.x
- [ ] `ws status` shows this node and the relay connected
- [ ] `Get-Acl C:\ProgramData\Whalescale` only lists SYSTEM and Administrators
- [ ] Log at `C:\ProgramData\Whalescale\wsd.log` has no errors

## 3. Linux machine (OS TUN mode)

```bash
sudo install -m 0755 ws wsd /usr/local/bin/
sudo wsd install-service
sudo WS_AUTHKEY=wskey-... ws login --server https://ws.example.com
sudo ws up
ws status   # needs sudo if the state dir is root-only
```

- [ ] `systemctl status wsd` is active
- [ ] `ip addr show whale0` has 100.64.x.x; `ip route` has `100.64.0.0/10 dev whale0`
- [ ] `resolvectl status whale0` lists the node's own IP as DNS server for `whale.internal`

## 4. The mesh (Phase 1 goal)

From each machine, to each other machine:

```bash
ws status                       # path column: "direct ..." or "relay"
ws ping <other>                 # "pong from X via ip:port" = direct
ping <other>.whale.internal     # OS-level MagicDNS + tunnel
```

- [ ] Windows ↔ Linux: `ping` by name works both ways
- [ ] The console's Topology page shows the same paths
- [ ] `ws netcheck` on each machine; NAT type: ______ / ______

## 5. CGNAT device

Tether a laptop to mobile data (or put any machine behind CGNAT), install as in step 2/3, then:

- [ ] `ws netcheck` reports the NAT type (symmetric is expected on Jio/Airtel)
- [ ] `ping <home-pc>.whale.internal` works (direct or relay; both count)
- [ ] Path is: direct / relay (circle one). If relay: latency ____ ms, `iperf3` throughput ____ Mbps
- [ ] If relayed: on the VPS (or any machine with a public IP), run `sudo ws up --relay` and `whalescale relays approve <it>`; the path becomes `peer-relay via <it>`. Latency ____ ms, throughput ____ Mbps (compare with the server relay above)

## 6. Access policy

In the console's Access policy page, save:

```json
{ "acls": [ { "action": "accept", "src": ["node:<linux-name>"], "dst": ["node:<windows-name>:*"] } ] }
```

- [ ] Linux → Windows still pings; Windows → Linux new connections fail
- [ ] Windows can still answer Linux (e.g. `curl` from Linux to a Windows web server works)
- [ ] Restore allow-all afterwards (delete the rules or save `*` → `*:*`)

## 7. Subnet router (Linux)

On the Linux machine, which must be on a LAN with something reachable (a router at 192.168.1.1, a NAS...):

```bash
sudo ws up --advertise-routes 192.168.1.0/24
```

Approve it in the console (Routes), then on the Windows PC (away from that LAN, e.g. on mobile data):

```powershell
.\ws.exe up --accept-routes
ping 192.168.1.1
```

- [ ] Route shows as pending, then approved, in the console
- [ ] Windows reaches a LAN host through the router
- [ ] `sudo iptables -t nat -S | grep whalescale` shows the MASQUERADE rule; after `sudo ws down` it's gone

## 8. Exit node

On the Linux machine (it must have internet access):

```bash
sudo ws up --advertise-exit-node
```

Approve both exit routes (`0.0.0.0/0`, `::/0`) in the console. Then on the Windows PC:

```powershell
.\ws.exe up --exit-node <linux-name>
.\ws.exe status          # "exit node: <linux-name> (active)"
curl.exe https://ifconfig.me
```

- [ ] `ifconfig.me` shows the Linux machine's public IP, not the PC's
- [ ] `ping 8.8.8.8` works (replies come back through the exit node)
- [ ] The PC's LAN still works (`ping` your router's LAN IP)
- [ ] `ws status` shows peers still connected directly (the tunnel didn't loop into itself)
- [ ] Stop the Linux machine's wsd: internet on the PC stops (fails closed); start it: internet comes back
- [ ] Switch the PC from Wi-Fi to Ethernet (or tethering): the tunnel recovers within ~10 s
- [ ] `ws up --exit-node=` (empty): traffic goes direct again, `route print` has no `0.0.0.0/1` routes

## 9. Gateway

On the VPS, set `gateway-domain: apps.example.com` (Docker: `WS_GATEWAY_DOMAIN` in `.env`) and add a DNS record `*.apps.example.com` pointing at the VPS. Then on a machine running some local web app (or `python -m http.server 8000`):

```bash
ws expose 8000 --name test
whalescale exposures approve test     # on the server, or approve in the console
```

- [ ] `whalescale doctor` shows "gateway: *.apps.example.com resolves to this server"
- [ ] `https://test.apps.example.com` loads from a phone on mobile data, with a valid certificate
- [ ] Before approval it answers 404, and no certificate is requested
- [ ] A WebSocket app (e.g. Home Assistant) works through it
- [ ] "Take offline" in the console makes it 404 within seconds

## 10. Service lifecycle

- [ ] Reboot each machine: the tunnel comes back up on its own
- [ ] `ws down`: peers show it offline within ~30 s; `ws up` brings it back
- [ ] `wsd uninstall-service` removes the service cleanly (state kept)

---

Report results by ticking the boxes and noting failures. Each failure becomes an issue to fix before Phase 3.
