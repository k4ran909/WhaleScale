//! Shared wire types for WhaleScale: API DTOs and the network map exchanged
//! between the coordinator and node agents.
//!
//! These types are the contract between the control plane (`coordinator`) and
//! the data plane (`agent-core`). Keep them backwards-compatible.

use std::net::SocketAddr;

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Overlay CGNAT range used for node addressing (same range Tailscale uses).
pub const OVERLAY_IPV4_RANGE: &str = "100.64.0.0/10";

// ---------------------------------------------------------------------------
// Enrollment
// ---------------------------------------------------------------------------

/// Request sent by an agent to register a new device with the coordinator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRequest {
    /// Pre-auth key (or short-lived OAuth token) authorizing enrollment.
    pub auth_key: String,
    /// WireGuard public key (base64), generated locally by the agent.
    pub public_key: String,
    /// Human-friendly hostname.
    pub hostname: String,
    /// OS identifier, e.g. "linux", "windows", "macos", "ios", "android".
    pub os: String,
    /// Subnets this node routes for other peers (subnet router), or
    /// `0.0.0.0/0` to act as an exit node. CIDR strings, e.g. `192.168.1.0/24`.
    #[serde(default)]
    pub advertised_routes: Vec<String>,
}

/// Response granting the device its identity and overlay address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub device_id: Uuid,
    pub tenant_id: Uuid,
    /// Assigned overlay address (CGNAT), e.g. 100.64.0.5/32.
    pub overlay_ip: IpNet,
    /// JWT the agent uses to authenticate subsequent control-plane calls.
    pub session_token: String,
    /// When the device's WireGuard key expires (None = never). The agent should
    /// rotate before this time.
    #[serde(default)]
    pub key_expires_at: Option<DateTime<Utc>>,
}

/// Request to rotate this device's WireGuard key (authenticated by the session
/// token). The agent generates a new keypair and sends the new public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateRequest {
    pub new_public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateResponse {
    /// The new expiry after rotation (None = never).
    #[serde(default)]
    pub key_expires_at: Option<DateTime<Utc>>,
}

/// Latency statistics shared by the agent (reporting) and coordinator (storing).
pub mod stats {
    use std::collections::VecDeque;

    use serde::{Deserialize, Serialize};

    /// A single round-trip-time measurement (e.g. STUN RTT), in milliseconds.
    #[derive(Debug, Clone, Copy, Serialize, Deserialize)]
    pub struct LatencySample {
        pub rtt_ms: u32,
    }

    /// Cumulative interface byte counters reported by an agent.
    #[derive(Debug, Clone, Copy, Serialize, Deserialize)]
    pub struct ThroughputSample {
        pub tx_bytes: u64,
        pub rx_bytes: u64,
    }

    /// Bytes/second between two cumulative counter readings `secs` apart.
    /// Counter resets (a smaller `curr` than `prev`) yield `0.0`.
    pub fn bytes_per_sec(prev: u64, curr: u64, secs: f64) -> f64 {
        if secs <= 0.0 {
            return 0.0;
        }
        curr.saturating_sub(prev) as f64 / secs
    }

    /// A fixed-capacity rolling window of latency samples.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct LatencyWindow {
        samples: VecDeque<u32>,
        cap: usize,
    }

    impl LatencyWindow {
        pub fn new(cap: usize) -> Self {
            Self {
                samples: VecDeque::with_capacity(cap),
                cap: cap.max(1),
            }
        }

        /// Add a sample, evicting the oldest when at capacity.
        pub fn push(&mut self, rtt_ms: u32) {
            if self.samples.len() == self.cap {
                self.samples.pop_front();
            }
            self.samples.push_back(rtt_ms);
        }

        pub fn last(&self) -> Option<u32> {
            self.samples.back().copied()
        }

        pub fn avg(&self) -> Option<f64> {
            if self.samples.is_empty() {
                return None;
            }
            let sum: u64 = self.samples.iter().map(|&x| x as u64).sum();
            Some(sum as f64 / self.samples.len() as f64)
        }

        pub fn min(&self) -> Option<u32> {
            self.samples.iter().copied().min()
        }

        pub fn max(&self) -> Option<u32> {
            self.samples.iter().copied().max()
        }

        /// 95th-percentile latency (nearest-rank).
        pub fn p95(&self) -> Option<u32> {
            if self.samples.is_empty() {
                return None;
            }
            let mut sorted: Vec<u32> = self.samples.iter().copied().collect();
            sorted.sort_unstable();
            let idx = ((sorted.len() - 1) * 95) / 100;
            Some(sorted[idx])
        }

        pub fn samples(&self) -> Vec<u32> {
            self.samples.iter().copied().collect()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn window_aggregates_and_evicts() {
            let mut w = LatencyWindow::new(3);
            assert_eq!(w.avg(), None);
            w.push(10);
            w.push(20);
            w.push(30);
            assert_eq!(w.last(), Some(30));
            assert_eq!(w.avg(), Some(20.0));
            assert_eq!(w.min(), Some(10));
            assert_eq!(w.max(), Some(30));
            // Eviction: oldest (10) drops out.
            w.push(40);
            assert_eq!(w.samples(), vec![20, 30, 40]);
            assert_eq!(w.avg(), Some(30.0));
        }

        #[test]
        fn p95_nearest_rank() {
            let mut w = LatencyWindow::new(100);
            for i in 1..=100 {
                w.push(i);
            }
            assert_eq!(w.p95(), Some(95));
        }

        #[test]
        fn rate_and_counter_reset() {
            assert_eq!(bytes_per_sec(1000, 5000, 4.0), 1000.0);
            assert_eq!(bytes_per_sec(5000, 1000, 4.0), 0.0); // reset
            assert_eq!(bytes_per_sec(0, 100, 0.0), 0.0); // no elapsed time
        }
    }
}

/// Key-expiry helpers, shared by the coordinator (to quarantine expired devices)
/// and the agent (to rotate before expiry).
pub mod expiry {
    use chrono::{DateTime, Duration, Utc};

    /// A device is active unless it has an expiry in the past.
    pub fn is_active(expires_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
        match expires_at {
            Some(t) => t > now,
            None => true,
        }
    }

    /// True if the key is still valid but expires within `window`.
    pub fn expires_within(
        expires_at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
        window: Duration,
    ) -> bool {
        match expires_at {
            Some(t) => t > now && t - now <= window,
            None => false,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn active_and_expiry_windows() {
            let now = Utc::now();
            assert!(is_active(None, now), "no expiry = active");
            assert!(is_active(Some(now + Duration::hours(1)), now));
            assert!(
                !is_active(Some(now - Duration::hours(1)), now),
                "past = inactive"
            );

            assert!(expires_within(
                Some(now + Duration::hours(12)),
                now,
                Duration::days(1)
            ));
            assert!(!expires_within(
                Some(now + Duration::days(5)),
                now,
                Duration::days(1)
            ));
            assert!(!expires_within(None, now, Duration::days(1)));
            assert!(!expires_within(
                Some(now - Duration::hours(1)),
                now,
                Duration::days(1)
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// Endpoint discovery (STUN results)
// ---------------------------------------------------------------------------

/// A candidate endpoint the agent believes peers may reach it on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub addr: SocketAddr,
    pub kind: EndpointKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointKind {
    /// Address observed on a local interface.
    Local,
    /// Server-reflexive address learned via STUN.
    Stun,
}

/// Periodic update from an agent reporting its discovered endpoints so the
/// coordinator can share them with peers for hole punching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointUpdate {
    pub device_id: Uuid,
    pub endpoints: Vec<Endpoint>,
}

// ---------------------------------------------------------------------------
// Network map
// ---------------------------------------------------------------------------

/// A peer entry as seen by a single node. The coordinator filters this per-node
/// according to ACL policy and tenant isolation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerNode {
    pub device_id: Uuid,
    pub hostname: String,
    pub public_key: String,
    /// Overlay address(es) this peer owns / routes (AllowedIPs).
    pub allowed_ips: Vec<IpNet>,
    /// Candidate endpoints for direct connection (best-effort, may be stale).
    pub endpoints: Vec<Endpoint>,
    /// Relay region id to use as fallback when direct fails.
    pub relay_region: Option<String>,
    pub online: bool,
    pub last_seen: Option<DateTime<Utc>>,
}

/// The full view delivered to one node: itself plus its permitted peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMap {
    /// Monotonic version; agents ignore maps older than what they hold.
    pub version: u64,
    pub self_node: SelfNode,
    pub peers: Vec<PeerNode>,
    pub relays: Vec<RelayRegion>,
    /// MagicDNS suffix for the tenant, e.g. "tenant-name.whale.net".
    pub dns_suffix: Option<String>,
    /// Inbound packet filter for `self_node`, derived from the tenant's ACL
    /// policy. Empty means "no port filtering" (allow-all, the default when no
    /// policy is configured).
    #[serde(default)]
    pub packet_filter: Vec<FilterRule>,
}

/// Which destination ports a [`FilterRule`] applies to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ports {
    /// All ports.
    All,
    /// A specific set of ports.
    List(Vec<u16>),
}

/// One inbound packet-filter rule: traffic from any of `src_ips` to this node
/// is permitted on `ports`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterRule {
    pub src_ips: Vec<IpNet>,
    pub ports: Ports,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfNode {
    pub device_id: Uuid,
    pub overlay_ip: IpNet,
    pub hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayRegion {
    pub id: String,
    pub name: String,
    /// Public host:port the relay listens on.
    pub addr: SocketAddr,
}

// ---------------------------------------------------------------------------
// Realtime control channel (coordinator <-> agent over WebSocket)
// ---------------------------------------------------------------------------

/// Messages the coordinator pushes to a connected agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// A fresh network map (sent on connect and on any change).
    NetworkMap(NetworkMap),
    /// Lightweight liveness ping.
    Ping,
}

/// Messages an agent sends to the coordinator over the control channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// Report newly discovered endpoints.
    Endpoints(EndpointUpdate),
    /// Liveness response.
    Pong,
}

// ---------------------------------------------------------------------------
// Relay (DERP-style) data plane framing
// ---------------------------------------------------------------------------
//
// The relay forwards opaque, already-encrypted WireGuard packets between peers
// that cannot connect directly. It is keyed by WireGuard public key and never
// sees plaintext. The first WebSocket message a client sends is a JSON
// [`RelayHello`]; everything after is a binary frame:
//
//     [u8 key_len][key bytes (utf-8 base64 pubkey)][payload...]
//
// Client -> relay: `key` is the destination peer. Relay -> client: `key` is the
// source peer. Same layout in both directions.
pub mod relay {
    use serde::{Deserialize, Serialize};

    /// First message a client sends to register on the relay.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RelayHello {
        /// This client's WireGuard public key (base64).
        pub public_key: String,
        /// Session token (coordinator-issued JWT) for authorization.
        pub token: String,
    }

    /// Encode a relay frame addressed to / originating from `key`.
    pub fn encode_frame(key: &str, payload: &[u8]) -> Vec<u8> {
        let key_bytes = key.as_bytes();
        let mut buf = Vec::with_capacity(1 + key_bytes.len() + payload.len());
        buf.push(key_bytes.len() as u8);
        buf.extend_from_slice(key_bytes);
        buf.extend_from_slice(payload);
        buf
    }

    /// Decode a relay frame into `(key, payload)`.
    pub fn decode_frame(buf: &[u8]) -> Option<(String, &[u8])> {
        let key_len = *buf.first()? as usize;
        let key_end = 1 + key_len;
        if buf.len() < key_end {
            return None;
        }
        let key = std::str::from_utf8(&buf[1..key_end]).ok()?.to_string();
        Some((key, &buf[key_end..]))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn frame_roundtrip() {
            let payload = b"encrypted-wireguard-bytes";
            let frame = encode_frame("PEERKEYBASE64==", payload);
            let (key, got) = decode_frame(&frame).expect("decodes");
            assert_eq!(key, "PEERKEYBASE64==");
            assert_eq!(got, payload);
        }

        #[test]
        fn rejects_truncated_frame() {
            // Claims a 200-byte key but provides none.
            assert!(decode_frame(&[200, 1, 2, 3]).is_none());
        }
    }
}
