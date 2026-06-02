//! Render WireGuard configuration from a network map, in two flavors:
//!  - [`render`] / [`render_quick`]: `wg-quick` format (includes `Address`), used
//!    to bring the interface *up*.
//!  - [`render_setconf`]: stripped `wg setconf`/`syncconf` format (no `Address`
//!    or comments), used to update an already-up interface without dropping it.
//!
//! Direct endpoints come from STUN (Phase 2); peers without a known endpoint are
//! still listed and will connect once an endpoint is learned or via the relay.

use std::fmt::Write as _;

use ws_proto::{Endpoint, EndpointKind, NetworkMap};

/// Choose the best endpoint to dial for a peer: prefer the server-reflexive
/// (STUN) address, which is what a peer on a different network must use; fall
/// back to a local-network address otherwise.
fn best_endpoint(endpoints: &[Endpoint]) -> Option<&Endpoint> {
    endpoints
        .iter()
        .find(|e| matches!(e.kind, EndpointKind::Stun))
        .or_else(|| endpoints.first())
}

/// Write the `[Peer]` sections shared by both formats. `comments` adds a
/// `# hostname` line (valid for wg-quick, omitted for `wg setconf`).
fn write_peers(out: &mut String, map: &NetworkMap, comments: bool) {
    for peer in &map.peers {
        let _ = writeln!(out, "[Peer]");
        if comments {
            let _ = writeln!(out, "# {}", peer.hostname);
        }
        let _ = writeln!(out, "PublicKey = {}", peer.public_key);
        let allowed: Vec<String> = peer.allowed_ips.iter().map(|n| n.to_string()).collect();
        let _ = writeln!(out, "AllowedIPs = {}", allowed.join(", "));
        if let Some(ep) = best_endpoint(&peer.endpoints) {
            let _ = writeln!(out, "Endpoint = {}", ep.addr);
        }
        let _ = writeln!(out, "PersistentKeepalive = 25");
        let _ = writeln!(out);
    }
}

/// wg-quick config (with `Address`) used to bring the interface up.
pub fn render_quick(map: &NetworkMap, private_key: &str, listen_port: u16) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "[Interface]");
    let _ = writeln!(out, "PrivateKey = {private_key}");
    let _ = writeln!(out, "Address = {}", map.self_node.overlay_ip);
    let _ = writeln!(out, "ListenPort = {listen_port}");
    let _ = writeln!(out);
    write_peers(&mut out, map, true);
    out
}

/// Stripped `wg setconf`/`syncconf` config (no `Address`, no comments) used to
/// update a running interface in place.
pub fn render_setconf(map: &NetworkMap, private_key: &str, listen_port: u16) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "[Interface]");
    let _ = writeln!(out, "PrivateKey = {private_key}");
    let _ = writeln!(out, "ListenPort = {listen_port}");
    let _ = writeln!(out);
    write_peers(&mut out, map, false);
    out
}

/// Backwards-compatible alias for the wg-quick renderer.
pub fn render(map: &NetworkMap, private_key: &str, listen_port: u16) -> String {
    render_quick(map, private_key, listen_port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use ws_proto::{Endpoint, EndpointKind, NetworkMap, PeerNode, SelfNode};

    fn sample_map() -> NetworkMap {
        NetworkMap {
            version: 1,
            self_node: SelfNode {
                device_id: uuid::Uuid::nil(),
                overlay_ip: "100.64.0.1/32".parse().unwrap(),
                hostname: "self".into(),
            },
            peers: vec![PeerNode {
                device_id: uuid::Uuid::nil(),
                hostname: "peer-a".into(),
                public_key: "PEERKEYBASE64".into(),
                allowed_ips: vec!["100.64.0.2/32".parse().unwrap()],
                endpoints: vec![Endpoint {
                    addr: "203.0.113.5:51820".parse::<SocketAddr>().unwrap(),
                    kind: EndpointKind::Stun,
                }],
                relay_region: None,
                online: true,
                last_seen: None,
            }],
            relays: vec![],
            dns_suffix: None,
            packet_filter: vec![],
        }
    }

    #[test]
    fn renders_interface_and_peer() {
        let cfg = render(&sample_map(), "PRIVKEYBASE64", 51820);
        assert!(cfg.contains("[Interface]"));
        assert!(cfg.contains("PrivateKey = PRIVKEYBASE64"));
        assert!(cfg.contains("Address = 100.64.0.1/32"));
        assert!(cfg.contains("[Peer]"));
        assert!(cfg.contains("PublicKey = PEERKEYBASE64"));
        assert!(cfg.contains("AllowedIPs = 100.64.0.2/32"));
        assert!(cfg.contains("Endpoint = 203.0.113.5:51820"));
    }

    #[test]
    fn setconf_omits_address_and_comments() {
        let cfg = render_setconf(&sample_map(), "PRIVKEYBASE64", 51820);
        assert!(!cfg.contains("Address ="), "setconf must not carry Address");
        assert!(!cfg.contains("# peer-a"), "setconf must not carry comments");
        assert!(cfg.contains("PublicKey = PEERKEYBASE64"));
        assert!(cfg.contains("Endpoint = 203.0.113.5:51820"));
    }
}
