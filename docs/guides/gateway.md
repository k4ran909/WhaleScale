# Gateway: publish a service on the internet

A self-hosted counterpart to Tailscale Funnel. A machine publishes a local web app at `https://<name>.<gateway domain>`, even from behind CGNAT. No port forwarding is needed.

1. **On the server:** set `gateway-domain: apps.example.com` and add a wildcard DNS record `*.apps.example.com` pointing at the server. For HTTPS, either:
   - set `tls-acme: true`: the server gets Let's Encrypt certificates itself, and port 443 must be reachable; or
   - use the Docker Compose setup with `WS_GATEWAY_DOMAIN`: Caddy gets certificates on demand.
2. **On the machine:**

   ```bash
   ws expose 8123 --name ha        # publishes http://localhost:8123
   ws expose                       # shows the public URL and whether it is live
   ws expose --remove ha
   ```

3. **Approve it:** in the console (Gateway) or with `whalescale exposures approve ha`. Until then nothing is reachable.

How it works and what keeps it safe:

- The machine keeps one WebSocket to the server and multiplexes requests over it (yamux).
- Each request names the service, and the machine only ever connects to its own localhost ports that it chose to expose.
- Certificates are only requested for live names, so strangers can't make the server request certificates for arbitrary hosts.
- Names are first come, first served across all machines, and changing a published port needs approval again.
- WebSockets and streaming responses pass through.
- Apps see the visitor's address in `X-Forwarded-For`. The header is trusted from a reverse proxy on a private network, such as Caddy.
