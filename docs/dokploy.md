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

Open `https://ws.example.com`: you should see the console's sign-in page.

## 3. The first admin

The image has no shell, so Dokploy's web terminal can't open in it. Run the
admin commands with `docker exec` on the Dokploy host, which needs no shell:

```bash
docker ps --filter name=whalescale --format '{{.Names}}'     # find the container
docker exec <container> whalescale users create you
docker exec <container> whalescale apikeys create            # sign in to the console with this
docker exec <container> whalescale preauthkeys create --user you --reusable
docker exec <container> whalescale doctor                    # checks HTTPS, relays, both STUN ports
```

Without host access, use Dokploy's **Schedule Jobs** instead: a Compose job for service `whalescale`, command `whalescale users create you`. Run it once and read the output in the job's log. Keys are shown only once, so copy them from the log, then delete the job.

## 4. Add machines

```bash
WS_AUTHKEY=wskey-... sudo ws login --server https://ws.example.com
sudo ws up
ws status
```

On Windows, in an Administrator terminal: `wsd install-service`, then the same `ws login` and `ws up`.

## What's already set

- **Rate limits per client:** `trusted-proxies` covers Docker's private networks, so Traefik's `X-Forwarded-For` names each client. The server's port 8080 isn't published, so only containers on those networks can reach it.
- **Data:** the database, SSH recordings and keys live in the `whalescale-data` volume. Back it up, or switch to PostgreSQL with `WHALESCALE_DB=postgres://...`.
- **Metrics:** on `127.0.0.1:9090` of the host only.
- **Not covered here:** the gateway (`gateway-domain`). It needs a wildcard certificate, which Caddy in [`deploy/docker-compose.yml`](../deploy/docker-compose.yml) gets on demand. With Traefik you'd set up a DNS-challenge wildcard yourself.

## If something's off

- **`ws status` shows every peer as `relay`, never `direct`:** UDP isn't reaching the server. Check the firewall, the cloud security group and the Cloudflare proxy (step 1). `whalescale doctor` reports each STUN port and the QUIC relay.
- **Machines reconnect every minute or so:** a proxy timeout is closing long-lived connections (map updates, the relay). Raise the read timeout on Traefik's `websecure` entrypoint in Dokploy's Traefik settings (`respondingTimeouts.readTimeout`).
- **Registrations get 429:** more than 60 a minute from one address. Raise `WHALESCALE_RATE_LIMIT` in the environment for a big rollout.
