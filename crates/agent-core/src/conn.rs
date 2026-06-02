//! Direct vs. relay path selection for a peer connection.
//!
//! WhaleScale prefers a **direct** (hole-punched) WireGuard path for the lowest
//! latency, and falls back to a **relay** when the direct path isn't working.
//! The runtime data loop records when a direct handshake/keepalive last
//! succeeded and calls [`select_path`] to choose where to send a peer's packets.
//!
//! The policy is pure and unit-tested here; only the call site (which feeds in
//! live handshake timing) is part of the platform data loop.

use std::net::SocketAddr;

use chrono::{DateTime, Duration, Utc};

/// Where to send a peer's traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Path {
    /// Send directly to this endpoint (hole-punched).
    Direct(SocketAddr),
    /// Relay through this region.
    Relay(String),
}

/// Choose a path for a peer:
///  1. a **healthy** direct endpoint (a direct handshake succeeded within
///     `direct_timeout`) is always preferred;
///  2. otherwise fall back to the **relay** if one is available;
///  3. otherwise, as a last resort, try the direct endpoint optimistically
///     (better than nothing while we wait for a relay or a handshake);
///  4. if there's neither a direct endpoint nor a relay, return `None`.
pub fn select_path(
    best_direct: Option<SocketAddr>,
    last_direct_ok: Option<DateTime<Utc>>,
    relay_region: Option<&str>,
    now: DateTime<Utc>,
    direct_timeout: Duration,
) -> Option<Path> {
    let direct_healthy = matches!(last_direct_ok, Some(t) if now - t <= direct_timeout);

    if let Some(addr) = best_direct {
        if direct_healthy {
            return Some(Path::Direct(addr));
        }
    }
    if let Some(region) = relay_region {
        return Some(Path::Relay(region.to_string()));
    }
    // Last resort: optimistic direct (no relay to fall back to).
    best_direct.map(Path::Direct)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> SocketAddr {
        "203.0.113.7:51820".parse().unwrap()
    }

    const TIMEOUT: Duration = Duration::seconds(30);

    #[test]
    fn healthy_direct_is_preferred_over_relay() {
        let now = Utc::now();
        let path = select_path(Some(addr()), Some(now), Some("local"), now, TIMEOUT);
        assert_eq!(path, Some(Path::Direct(addr())));
    }

    #[test]
    fn stale_direct_falls_back_to_relay() {
        let now = Utc::now();
        let stale = now - Duration::seconds(120);
        let path = select_path(Some(addr()), Some(stale), Some("local"), now, TIMEOUT);
        assert_eq!(path, Some(Path::Relay("local".into())));
    }

    #[test]
    fn no_direct_uses_relay() {
        let now = Utc::now();
        let path = select_path(None, None, Some("local"), now, TIMEOUT);
        assert_eq!(path, Some(Path::Relay("local".into())));
    }

    #[test]
    fn optimistic_direct_when_no_relay_and_unproven() {
        let now = Utc::now();
        // Endpoint known, never confirmed, and no relay -> try direct anyway.
        let path = select_path(Some(addr()), None, None, now, TIMEOUT);
        assert_eq!(path, Some(Path::Direct(addr())));
    }

    #[test]
    fn nothing_usable_is_none() {
        let now = Utc::now();
        assert_eq!(select_path(None, None, None, now, TIMEOUT), None);
    }
}
