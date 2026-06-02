//! Userspace WireGuard data plane via boringtun.
//!
//! This is the **cross-platform core** shared by every client: Linux, Windows
//! (wintun), macOS (utun), and the FFI core for iOS/Android. A platform TUN
//! backend pumps packets between the OS tunnel device and a UDP socket; this
//! module owns the per-peer WireGuard cryptography (Noise handshake + transport)
//! and is independent of any OS networking, so it is fully unit-tested here.

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};

/// What the caller should do with the buffer after an operation.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Nothing to send.
    None,
    /// Send these bytes to the peer over UDP.
    ToNetwork(Vec<u8>),
    /// Deliver these decrypted bytes to the local TUN device.
    ToTunnel(Vec<u8>),
}

/// A single WireGuard peer session.
pub struct Peer {
    tunn: Tunn,
}

impl Peer {
    /// Create a session from this node's private key and the peer's public key.
    pub fn new(private_key: [u8; 32], peer_public: [u8; 32], index: u32) -> anyhow::Result<Self> {
        let secret = StaticSecret::from(private_key);
        let public = PublicKey::from(peer_public);
        let tunn = Tunn::new(secret, public, None, None, index, None)
            .map_err(|e| anyhow::anyhow!("failed to create WireGuard session: {e}"))?;
        Ok(Self { tunn })
    }

    /// Encrypt an outbound IP packet (or trigger a handshake when `packet` is
    /// empty / the session is not yet established).
    pub fn encapsulate(&mut self, packet: &[u8]) -> anyhow::Result<Action> {
        let mut buf = vec![0u8; packet.len() + 148];
        Ok(to_action(self.tunn.encapsulate(packet, &mut buf)))
    }

    /// Process an inbound UDP datagram from the peer.
    pub fn decapsulate(&mut self, datagram: &[u8]) -> anyhow::Result<Action> {
        let mut buf = vec![0u8; datagram.len() + 148];
        Ok(to_action(self.tunn.decapsulate(None, datagram, &mut buf)))
    }
}

fn to_action(result: TunnResult) -> Action {
    match result {
        TunnResult::Done => Action::None,
        TunnResult::WriteToNetwork(b) => Action::ToNetwork(b.to_vec()),
        TunnResult::WriteToTunnelV4(b, _) => Action::ToTunnel(b.to_vec()),
        TunnResult::WriteToTunnelV6(b, _) => Action::ToTunnel(b.to_vec()),
        TunnResult::Err(e) => {
            tracing::debug!(error = ?e, "wireguard op error");
            Action::None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal valid 20-byte IPv4 header so boringtun routes the decrypted
    /// payload to `WriteToTunnelV4`.
    fn ipv4_packet() -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45; // version 4, IHL 5
        p[3] = 20; // total length
        p[8] = 64; // TTL
        p[9] = 0; // protocol
        p[12..16].copy_from_slice(&[100, 64, 0, 1]); // src
        p[16..20].copy_from_slice(&[100, 64, 0, 2]); // dst
        p
    }

    #[test]
    fn handshake_and_transport_between_two_peers() {
        let a_priv: [u8; 32] = rand::random();
        let b_priv: [u8; 32] = rand::random();
        let a_pub = PublicKey::from(&StaticSecret::from(a_priv)).to_bytes();
        let b_pub = PublicKey::from(&StaticSecret::from(b_priv)).to_bytes();

        let mut a = Peer::new(a_priv, b_pub, 0).unwrap();
        let mut b = Peer::new(b_priv, a_pub, 1).unwrap();

        // 1. A initiates the handshake.
        let init = match a.encapsulate(&[]).unwrap() {
            Action::ToNetwork(d) => d,
            other => panic!("expected handshake init, got {other:?}"),
        };

        // 2. B processes init and produces the response.
        let resp = match b.decapsulate(&init).unwrap() {
            Action::ToNetwork(d) => d,
            other => panic!("expected handshake response, got {other:?}"),
        };

        // 3. A processes the response (handshake complete).
        a.decapsulate(&resp).unwrap();

        // 4. A sends a data packet to B.
        let packet = ipv4_packet();
        let encrypted = match a.encapsulate(&packet).unwrap() {
            Action::ToNetwork(d) => d,
            other => panic!("expected encrypted data, got {other:?}"),
        };

        // 5. B decrypts it and recovers the original packet.
        let delivered = match b.decapsulate(&encrypted).unwrap() {
            Action::ToTunnel(d) => d,
            other => panic!("expected delivered packet, got {other:?}"),
        };
        assert_eq!(delivered, packet, "B must recover A's exact packet");
    }
}
