# Running the server on Dokploy

[`deploy/dokploy/docker-compose.yml`](../deploy/dokploy/docker-compose.yml) runs the Whalescale server
behind Dokploy's Traefik. Traefik handles HTTPS for the console, the API and
the WebSocket relay. STUN and the QUIC relay use UDP, which Traefik doesn't
carry, so those ports are published on the host directly.

## 1. DNS and firewall

- **DNS:** point a name (say `ws.example.com`) at the Dokploy host.
  - **Cloudflare users:** if the record is proxied (orange cloud), HTTPS works but UDP doesn't get through. Either make the record DNS-only, or keep it proxied and add `WS_UDP_HOST` (step 2) with the server's IP or a DNS-only name.
- **Firewall:** allow UDP **3478, 3479 and 3480** on the host and in your cloud provider's security group. TCP 80/443 are already open for Dokploy.

  ```bash
  sudo ufw allow 3478:3480/udp
  ```

## 2. Create the app

1. Dokploy → your project → **Create Service → Compose**.
2. **Source:** this GitHub repository, branch `main`, compose path `./deploy/dokploy/docker-compose.yml`.
3. **Environment:**

   ```
   WS_DOMAIN=ws.example.com
   # optional:
   # WS_UDP_HOST=203.0.113.10      # when UDP must go elsewhere than WS_DOMAIN
   # WS_POST_QUANTUM=true          # post-quantum pre-shared keys between machines
   ```
4. **Domains:** add `ws.example.com` → service `whalescale`, container port **8080**, HTTPS on (Let's Encrypt).
5. **Deploy.** The first build takes a few minutes (it compiles the server from source).

Open `https://ws.example.com`: on a new server you should see **Create your admin account**.

## 3. Create your admin account

Open `https://ws.example.com`. The first visit shows **Create your admin account**, which asks for a one-time setup code:

- **Where to find it:** Dokploy → your app → **Logs**, the line with `setup_code=ABCD-EFGH`. The server prints it at start, and again whenever the setup page is opened, so the newest log line has it.
- **Or on the host:** `docker exec <container> whalescale setup-code` (find the container with `docker ps --filter name=whalescale`).

Pick a name and a password, and you're signed in. The setup page is gone from then on: it only exists while the server has no admin. Your account also gets a user of the same name, which new devices belong to by default.

Forgot the password? On the host: `docker exec <container> whalescale admins reset-password <name>` prints a new one. The image has no shell, so Dokploy's web terminal can't open in it, but `docker exec` with a command works. Without host access, a Dokploy **Schedule Job** (Compose, service `whalescale`, command `whalescale admins reset-password <name>`) does the same: run it once, read the log, delete the job.

## 4. Add devices

In the dashboard: **Machines → Add device**. It gives you a join code and shows the steps for Windows, macOS and Linux, then tells you when the device has joined.

- **Windows:** download the installer it links to, run it, paste the code.
- **macOS and Linux:** `curl -fsSL https://raw.githubusercontent.com/k4ran909/WhaleScale/main/deploy/install.sh | sh -s -- --join <code>`

`docker exec <container> whalescale doctor` checks HTTPS, both STUN ports and the relays from the server's side.

## What's already set

- **Rate limits per client:** `trusted-proxies` covers Docker's private networks, so Traefik's `X-Forwarded-For` names each client. The server's port 8080 isn't published, so only containers on those networks can reach it.
- **Data:** the database, SSH recordings and keys live in the `whalescale-data` volume. Back it up, or switch to PostgreSQL with `WHALESCALE_DB=postgres://...`.
- **Metrics:** on `127.0.0.1:9090` of the host only.
- **Not covered here:** the gateway (`gateway-domain`). It needs a wildcard certificate, which Caddy in [`deploy/docker-compose.yml`](../deploy/docker-compose.yml) gets on demand. With Traefik you'd set up a DNS-challenge wildcard yourself.

## If something's off

- **`ws status` shows every peer as `relay`, never `direct`:** UDP isn't reaching the server. Check the firewall, the cloud security group and the Cloudflare proxy (step 1). `whalescale doctor` reports each STUN port and the QUIC relay.
- **Machines reconnect every minute or so:** a proxy timeout is closing long-lived connections (map updates, the relay). Raise the read timeout on Traefik's `websecure` entrypoint in Dokploy's Traefik settings (`respondingTimeouts.readTimeout`).
- **Registrations get 429:** more than 60 a minute from one address. Raise `WHALESCALE_RATE_LIMIT` in the environment for a big rollout.
