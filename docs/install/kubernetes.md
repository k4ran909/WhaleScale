# Kubernetes (Helm)

The chart in [`deploy/helm/whalescale`](../../deploy/helm/whalescale) runs the server as a StatefulSet.

```bash
helm install ws deploy/helm/whalescale \
  --set publicURL=https://ws.example.com \
  --set ingress.enabled=true --set ingress.className=nginx --set ingress.tlsSecretName=ws-tls
```

- **Two services:** HTTPS (console, API, WebSocket relay) goes through your ingress. STUN and the QUIC relay are UDP, so they get a `LoadBalancer` service (`ws-whalescale-udp`, ports 3478–3480) with `externalTrafficPolicy: Local`, which keeps machines' real addresses visible to STUN.
- **DNS:** point the public hostname at the ingress. If the UDP load balancer has a different address, set `udp.host` to it.
- **Database:** SQLite on a persistent volume by default. With `database.url` (or an existing Secret) it uses PostgreSQL.
- **Failover:** install a second release with its own `publicURL` against the same PostgreSQL database.
- **Other settings:** `config:` takes any other server setting (`post-quantum: true`, `flow-logs: true`, `policy-url`, ...), and `oidc:` sets up browser login.
- **Behind the ingress:** set `config.trusted-proxies` to your ingress controller's pod range so rate limits apply per client.
- **Hardened pod:** runs as non-root with a read-only root filesystem and no service-account token.
- **Images:** release builds publish `ghcr.io/k4ran909/whalescale` for amd64 and arm64.

Settings layer as: config file, then `conf.d/*.yaml` (upgrades never touch these), then `WHALESCALE_*` environment variables, then flags. Unknown keys are errors.
