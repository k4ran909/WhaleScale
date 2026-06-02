# Platform Agents (Phase 6 / 7)

Every WhaleScale client — Linux, Windows, macOS, iOS, Android — shares one Rust
core (`crates/agent-core`). The only per-platform code is the **TUN device + UDP
event loop** that moves packets between the OS and the shared WireGuard core.

## Layers

```
┌─────────────────────────────────────────────────────────┐
│ agent-core (shared, cross-platform, unit-tested)         │
│   keys · client · discovery (STUN) · relay_client        │
│   wireguard (boringtun: handshake + transport)  ← tested │
│   wgconfig · backend (wg-quick)                          │
└───────────────┬─────────────────────────────────────────┘
                │ platform TUN backend implements the pump:
                │   TUN packet  -> Peer::encapsulate -> UDP send
                │   UDP datagram-> Peer::decapsulate -> TUN write
   ┌────────────┼───────────────┬───────────────┬───────────┐
   │ Linux      │ Windows       │ macOS         │ iOS/Android│
   │ /dev/net/  │ wintun.dll    │ utun (kernel  │ Network-   │
   │ tun (or    │ (`wintun`     │ control       │ Extension /│
   │ kernel WG  │  crate)       │ socket)       │ VpnService │
   │ via wg-    │               │               │ + Rust FFI │
   │ quick)     │               │               │            │
   └────────────┴───────────────┴───────────────┴───────────┘
```

## Two data-plane options

1. **Kernel WireGuard** (Linux, and macOS/Windows with the official app): use the
   existing [`WgQuickBackend`](../crates/agent-core/src/backend.rs). Fastest; no
   userspace crypto. Requires `wireguard-tools` + privileges.

2. **Userspace WireGuard** via boringtun
   ([`wireguard.rs`](../crates/agent-core/src/wireguard.rs)): the `Peer` type owns
   the Noise handshake + transport. This is what mobile and dependency-free
   desktop builds use. The handshake and transport are **verified in-process** by
   `wireguard::tests::handshake_and_transport_between_two_peers` (no TUN device or
   network needed), so the crypto path is proven on every platform including
   Windows CI.

## What each platform backend must implement

A `TunnelBackend`-style pump around `wireguard::Peer`:

- Open the OS TUN device (wintun / utun / `/dev/net/tun`) and assign the overlay
  IP + routes from the network map.
- Bind the WireGuard UDP socket (same port reported to STUN in `discovery`).
- Loop:
  - TUN → `Peer::encapsulate(packet)` → `Action::ToNetwork` → send via the path
    chosen by `conn::select_path` (a healthy direct endpoint, else the relay via
    `relay_client`, else optimistic direct). Record when a direct handshake last
    succeeded so the next selection can prefer/abandon the direct path.
  - UDP → `Peer::decapsulate(datagram)` → `Action::ToTunnel` → **check
    `agent.inbound_allowed(&packet)`** (ACL port filter) → write to TUN if allowed.
  - Drive periodic timers (handshake refresh / keepalive).

The ACL packet filter (`NetworkMap.packet_filter`) is enforced here: after a
packet is decrypted, `filter::parse_ipv4` extracts its source IP + destination
port and `filter::allows_inbound` drops anything the tenant's policy disallows
(both unit-tested in `agent-core/src/filter.rs`).

### Mobile specifics (Phase 7)

Mobile clients link the **`whalescale` C ABI** (`crates/agent-ffi`, header at
`crates/agent-ffi/include/whalescale.h`). The app supplies the TUN device + UDP
socket; the library does all WireGuard crypto. The FFI surface is tiny:

```c
int32_t  ws_generate_keypair(uint8_t *out_private, uint8_t *out_public);
WsPeer  *ws_peer_new(const uint8_t *priv, const uint8_t *peer_pub, uint32_t index);
int32_t  ws_peer_encapsulate(WsPeer*, in, in_len, out, out_cap, out_len*); // TUN->UDP
int32_t  ws_peer_decapsulate(WsPeer*, in, in_len, out, out_cap, out_len*); // UDP->TUN
void     ws_peer_free(WsPeer*);
```

The full handshake + transport over this boundary is verified by
`ws-agent-ffi`'s `handshake_and_transport_through_ffi` test.

- **iOS**: `cargo build --target aarch64-apple-ios` → static lib; a
  `NEPacketTunnelProvider` reads `packetFlow` packets, calls `ws_peer_encapsulate`,
  and `sendto` on its UDP socket (and the reverse with `ws_peer_decapsulate`).
  Swift imports the header via a bridging header / module map.
- **Android**: `cargo-ndk` builds the `.so` per ABI; a `VpnService` pumps its
  `protect()`ed `DatagramSocket` and the TUN `ParcelFileDescriptor` through the
  same calls via JNI.

Both reuse `agent-core` unchanged — only the TUN/socket glue is native.
