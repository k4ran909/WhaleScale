//! WireGuard (Curve25519) key generation and encoding.

use base64::Engine;
// Use boringtun's re-exported x25519 so the whole agent shares one version.
use boringtun::x25519::{PublicKey, StaticSecret};

/// Decode a base64-encoded key into exactly 32 bytes (the WireGuard key size).
pub fn decode_key(b64: &str) -> Option<[u8; 32]> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    bytes.try_into().ok()
}

/// A WireGuard keypair, base64-encoded the way `wg` expects.
#[derive(Debug, Clone)]
pub struct WgKeypair {
    pub private_key: String,
    pub public_key: String,
}

impl WgKeypair {
    /// Generate a fresh keypair using the OS CSPRNG.
    pub fn generate() -> Self {
        let bytes: [u8; 32] = rand::random();
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        let b64 = base64::engine::general_purpose::STANDARD;
        WgKeypair {
            private_key: b64.encode(secret.to_bytes()),
            public_key: b64.encode(public.as_bytes()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_distinct_32_byte_base64_keys() {
        let b64 = base64::engine::general_purpose::STANDARD;
        let kp = WgKeypair::generate();
        assert_eq!(b64.decode(&kp.private_key).unwrap().len(), 32);
        assert_eq!(b64.decode(&kp.public_key).unwrap().len(), 32);
        assert_ne!(kp.private_key, kp.public_key);

        // Two generations differ.
        assert_ne!(WgKeypair::generate().private_key, kp.private_key);
    }
}
