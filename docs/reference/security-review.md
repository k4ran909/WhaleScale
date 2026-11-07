# Internal security review

**Date:** 2026-11-02 · **Scope:** the server, `wsd` / `ws`, the web console, the MCP server and the Terraform provider at this commit · **Kind:** internal, ahead of an external audit before 1.0.

This is a first pass by the project itself. It doesn't replace an independent audit; it is meant to fix what can be found from the inside and to give external auditors a map.

## Threat model

| Actor | Can | Must not be able to |
|---|---|---|
| Internet attacker (no credentials) | Reach the HTTPS API, STUN, relays and the gateway | Join the network, read traffic, exhaust the server, learn secrets |
| A member machine (or a stolen node token) | Use its own node token: maps, updates, relay, uploads | Impersonate other machines, reach what the policy forbids, take the server down |
| A local user on a member machine | Use the machine's network as the policy allows for that machine | Read the machine's keys or token, reconfigure `wsd` |
| An admin API key holder | What the key's scope allows (admin or read) | More than the scope; act without being audited |
| A compromised control server | Change policy, routes, DNS and SSH rules for existing members | With the network lock on: add machines or change trusted keys. Ever: read WireGuard traffic |
| A passive recorder (today, decrypting later with a quantum computer) | Store all traffic | With `post-quantum: true`: decrypt it |

## How it was reviewed

- **Manual code review:** authentication paths (node tokens, API keys and scopes, console sessions, OIDC) and every unauthenticated endpoint.
- **Input bounds and per-identity resource limits.**
- **Relay and peer-relay forwarding:** checked for spoofing.
- **Gateway routing:** host matching and forwarded headers.
- **Local trust boundaries:** state files and the local API socket.
- **Injection:** SQL, HTML and file paths.
- **Dependencies:** scanned with `govulncheck` v1.8.0 for both Go modules (the server and the Terraform provider).
- **Proof for every fix:** each fix has a test, and each test was checked to fail without the fix.

## Findings

| # | Severity | Finding | Status |
|---|---|---|---|
| 1 | High (Windows) | `wsd` keeps its state in `C:\ProgramData\Whalescale`, which inherits read access for every local user. Unix modes (0600) do nothing on Windows. So any local user could read the node token and WireGuard private key, enough to impersonate the machine. | **Fixed:** the state directory (and the local API socket's) gets a protected DACL: SYSTEM and Administrators only. Existing files are re-permissioned the next time state is saved. Test: `clientstate.TestProtectRemovesUserAccess`. |
| 2 | Medium | No request size limit on the admin API. The control API allowed 33 MB on every call, though only recording uploads need it. Bodies are read before authentication, so anyone could make the server buffer large requests. | **Fixed:** admin calls are capped at 16 MB, control calls at 4 MB, recording uploads at 33 MB, all enforced before the handler reads. Test: `server.TestRequestSizeLimits`. |
| 3 | Medium | A node token could open unlimited map streams, each costing a goroutine and per-change work. | **Fixed:** at most 8 per machine. Test: `control.TestMapStreamLimit`. |
| 4 | Low | Starting a browser login needs no credentials and holds a slot for 10 minutes. The 1,000-slot list was easy to fill, blocking new device logins. | **Mitigated:** 20,000 slots. A reverse proxy rate limit on `/whalescale.v1.ControlService/Register` remains the real defence (see below). |
| 5 | High (dependency) | 13 vulnerabilities in the Go 1.27.0 standard library reachable from our code: HTTP/2 and `net/http` request handling, TLS, `net/textproto`, `html/template`, x509. | **Fixed:** the toolchain is pinned to go1.27.3 in both modules (go1.27.2 fixed 12 of the 13; go1.27.3 fixed GO-2026-6809, distrusting compromised intermediate CAs in `crypto/x509`, once it passed the project's two-week rule). `govulncheck` now reports no vulnerabilities affecting our code in either module. |
| 6 | Medium (dependency) | `go-jose` v4.1.0 (OIDC token verification): panic in JWE decryption (GO-2026-4945). | **Fixed:** v4.1.6. |
| 7 | Low (dependency) | The Terraform provider pulled in `grpc` v1.79.3 with three advisories (panic on a missing authority header, HTTP/2 memory exhaustion, xDS RBAC). The plugin's gRPC server only talks to the local Terraform process. | **Fixed:** grpc v1.84.0. |
| 8 | Info | The README could be read as saying the network lock protects everything. It protects membership only; policy, SSH rules, DNS and routes still come from the server. | **Documented** in the README's network lock section. |

## Controls verified (no change needed)

- **Secrets at rest:**
  - node tokens, pre-auth keys, API keys and session tokens are stored only as SHA-256 hashes;
  - generated secrets carry 192 bits (pre-auth and API keys) or 256 bits (node and session tokens) of randomness, so online guessing is infeasible.
- **Console sessions:**
  - the cookie is `HttpOnly`, `Secure` (behind HTTPS) and `SameSite=Lax`;
  - cookie-authenticated API calls must carry the Connect protocol header, which a cross-site form can't add (CSRF);
  - read-only API keys stay read-only in sessions they open.
- **OIDC:** the authorization code flow with state and PKCE (S256); ID tokens are verified with `go-oidc`.
- **Webhooks:** HMAC-SHA256 and token checks use constant-time comparison.
- **Console hardening:**
  - a CSP of `default-src 'self'` with `frame-ancestors 'none'`, plus `X-Frame-Options: DENY` and `nosniff`;
  - no raw HTML rendering anywhere (React escapes everything).
- **SQL:** every query is parameterized. The few query fragments chosen at runtime are constants (dialect helpers).
- **File paths:** recording file names are built from a sanitized machine name and random bytes, never from request data.
- **Relays:**
  - the server relay labels frames with the sender's authenticated key, so the source can't be spoofed;
  - peer relays only forward between machines that registered with sealed discovery messages, and the payload is WireGuard ciphertext either way.
- **Gateway:**
  - public requests reach only live (advertised and approved) exposures;
  - incoming `X-Forwarded-*` headers are replaced, not trusted.
- **Windows Firewall:** the agent allows inbound traffic on the Whalescale adapter only (rule `WhalescaleIn`), because Windows would otherwise drop everything peers send. Whalescale's stateful filter is then what enforces the access policy there; other adapters keep their firewall settings.
- **Machine-local services:** MagicDNS and the mesh SSH server bind to the machine's mesh address only, never the LAN.
- **WireGuard routing:** each peer's allowed IPs are its mesh addresses plus approved routes, so packets can't claim another source; the stateful filter then applies the policy.
- **Input bounds on node reports:** endpoints, routes, exposures, path reports, flow records, OS strings and recording size are all bounded.
- **Network lock:**
  - chain verification refuses forged extensions, keys removed from the list, rollbacks, swapped histories and tampered states;
  - node signatures can't be moved to another key (unit and end-to-end tests).
- **Post-quantum exchange:** a key is applied only after both sides confirm, a mismatch falls back to plain WireGuard, and older peers never get one (tests under 40% message loss).
- **Audit log:** hash-chained; edits and deletions are detected.
- **Console accounts:**
  - Passwords are stored as argon2id hashes (19 MiB, 2 passes, OWASP's minimum), at least 10 characters.
  - Sign-in with an unknown name takes as long as with a wrong password.
  - Changing a password, or deleting an account, ends all its sessions.
  - The first account can only be created with a one-time setup code that the server prints in its own log, so whoever finds a fresh server first can't claim it. Setup closes for good once the account exists; racing setups can't both succeed (`server.TestFirstRunSetup`, `store.TestAdmins`).
- **Parsers:** fuzz targets cover policies, map deltas, QUIC relay frames, disco messages, packets entering the filter, DNS queries and machine proofs.
- **Exit nodes and DNS:** a machine using an exit node resolves every name through it and fails closed when it can't, so lookups don't leak to the local network (end to end in `engine.TestExitNode`).

## Residual risks and recommendations

1. **Machine keys are files.** Requests are bound to the machine key: each carries an HMAC keyed by the X25519 secret between the machine and the server, over the method, the server, the path, the time and a nonce (`internal/nodeauth`). Once a machine has signed a request, its bearer token is refused (`control.TestMachineProofs`; end to end in `engine.TestRelayFallback` and `TestGateway`). A token or header seen in transit, in a log or by a TLS-inspecting proxy is useless, and a proxy can't relay a machine's requests once the machine has pinned the server key. What remains:
   - Anyone who copies a machine's whole state, private key included, can still act as it until it's removed. File protection (finding 1) is the guard; hardware-backed keys (TPM, Secure Enclave) would close it.
   - Each server keeps its own nonce cache. Behind one hostname shared by several servers, a captured proof could be replayed against another server within the five-minute window. Give each server its own public URL (the failover setup already does).
   - Machines that never upgrade keep using their tokens.
   - A machine that logged in with an older client learns the server key from its first network map (trust on first use, over TLS).
2. **The control server is trusted for policy.** See finding 8. Use the network lock, keep the policy in Git with review, and watch the audit log.
3. **Rate limits are per address.** Starting a browser login (finding 4), `Register`, `WaitRegistration` and the `/auth/*` endpoints are limited per client (`rate-limit`, 60 a minute by default; IPv6 per /64; `X-Forwarded-For` only from `trusted-proxies`; tests `server.TestLimiter` and `TestRateLimitedEndpoints`). Someone with many addresses can still spread requests across them, and STUN isn't limited. A proxy or firewall in front can add global limits. Password sign-in is limited the same way, per address, not per account: there's no lockout, which would let anyone lock the admin out. Use a long password, or OIDC with your provider's protections.
4. **Uploads are budgeted per machine, not globally.** Each machine may store `recording-quota-mb` of SSH recordings (1 GiB by default; over it, new uploads are refused and old ones kept) and about 1,000 flow records per 30 seconds (`control.TestRecordingQuota`, `TestFlowBudget`). Total use still grows with the number of machines: set `recording-retention`, and watch the recordings directory and the database size.
5. **Self-reported data:** flow logs, path reports and posture attributes (OS and client version) come from the machines themselves. Posture checks keep honest machines up to date; they don't stop a compromised machine that lies.
6. **The post-quantum layer is hybrid:** the exchange is authenticated with X25519 (the disco keys). It protects recorded traffic against future decryption, but not against an active quantum attacker during the exchange.
7. **Secrets in Terraform state:** `whalescale_preauth_key.key` is stored in Terraform state. Protect state storage (encrypted remote backends).
8. **Supply chain:** dependencies are pinned and versions are at least two weeks old when adopted. `govulncheck` runs in CI on every change and nightly (`.woodpecker/vuln.yaml`), so a new advisory reachable from our code fails the build. It also lists GO-2026-5932 in `golang.org/x/crypto`, which concerns the deprecated `openpgp` package; we don't import it, and its only fix so far is an untagged development snapshot, so it waits for a tagged release.
9. **External audit:** before 1.0, commission an independent review. Focus on the cryptographic protocols (network lock, post-quantum exchange, disco), NAT traversal edge cases and the Windows service.
