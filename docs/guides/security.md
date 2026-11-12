# Security features

Network lock, post-quantum protection and the tamper-evident audit log. For the threat model, see the [security review](../reference/security-review.md).

- [Network lock](#network-lock)
- [Post-quantum protection](#post-quantum-protection)
- [Audit log](#audit-log)

## Network lock

By default, every machine trusts the control server to say who its peers are. With the network lock on, a machine accepts a peer only if one of *your* lock keys signed that peer's WireGuard key. The keys live on admins' own machines, never on the server, so even a compromised server can't add a machine to your network or change which keys are trusted.

```bash
ws lock keygen --out ~/wslock.key                 # on your laptop; prints wslock:...
export WS_API_KEY=wsapi-...                        # from 'whalescale apikeys create'
ws lock init --key ~/wslock.key --trust wslock:<a colleague's key>   # turn it on, sign every machine
ws lock sign --key ~/wslock.key                    # later: sign machines added since
ws lock status                                     # on any machine
```

- **New machines start out refused.** Until someone runs `ws lock sign`, other machines refuse a new one, and its `ws lock status` says so.
- **Changing the trusted keys:** `add-key` / `remove-key` change who's trusted. Each change must be signed by a currently trusted key, and every machine checks that itself.
- **No rollback.** A machine remembers the newest key list it has verified and never goes back to an older one or a different history. If the server sends lock data that doesn't verify, the machine keeps enforcing what it knows and reports the problem in `ws lock status`.
- **Turning it off:** `ws lock disable` stops filtering (signed like any change); `enable` turns it back on.
- **First contact:** a machine trusts the first key list it sees. To rule out a malicious server at that moment, log in with `ws login --lock-trust wslock:...`.
- **What it doesn't cover:** the lock controls *membership*. The access policy, SSH rules, DNS and routes still come from the server, so a compromised server can't add machines but can change what existing members may do. Watch the audit log, and keep the policy in Git (`policy-url`) so changes are reviewed.

## Post-quantum protection

Turn it on in the console (**Settings → Post-quantum protection**), or in the server config:

```yaml
post-quantum: true
```

WireGuard's handshake uses X25519, which a future quantum computer could break. Someone recording your traffic today could then decrypt it later ("harvest now, decrypt later"). With `post-quantum` on, every pair of machines also agrees on a WireGuard pre-shared key through an ML-KEM-768 key exchange (the NIST post-quantum standard) and replaces it every two minutes. WireGuard mixes that key into each handshake, so recorded traffic stays secret unless both X25519 and ML-KEM are broken. This is the approach Rosenpass pioneered, built in.

- **Hidden and authenticated:** the exchange runs inside the encrypted discovery messages, so it's authenticated and its contents are hidden.
- **Never out of step:** keys change only after both sides confirm they have the new one. Peers compare key fingerprints in their regular pings and start over if they ever disagree (after a restart, say), so the feature can't strand a connection.
- **Older clients are unaffected:** they don't answer the exchange and simply keep using plain WireGuard.
- **Visible in status:** `ws status` marks protected peers with `(pq)`.

## Audit log

Every change to users, machines, keys, route/relay/gateway approvals and the access policy is recorded with who made it. That covers the console, the admin API, `whalescale` commands on the server host, node registrations, console sign-ins, and policy updates from Git or the policy file. Actors look like `oidc:you@example.com`, `api-key:ab12cd`, `cli:root`, `user:alice` or `git`.

```bash
whalescale audit --since 24h            # or the console's "Audit log" page
whalescale audit --actor cli: --action policy
whalescale audit --verify               # check the hash chain
```

Each entry's hash covers the previous one, so editing or deleting an entry in the database breaks the chain at that point. The chain can't show that the *newest* entries were cut off, so `--verify` prints the head hash: note it somewhere else now and then.
