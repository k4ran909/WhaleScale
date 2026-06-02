//! Inbound packet-filter enforcement (ACL port rules).
//!
//! The coordinator compiles the tenant's ACL policy into a per-node
//! [`FilterRule`] set delivered in the network map (`NetworkMap.packet_filter`).
//! After WireGuard decrypts an inbound packet, the platform TUN loop calls
//! [`allows_inbound`] before writing it to the tunnel device, dropping anything
//! the policy doesn't permit.
//!
//! The packet inspection and rule matching are pure and unit-tested here; only
//! the call site (the OS TUN write path) is platform-specific.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;
use ws_proto::{FilterRule, Ports};

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

/// The fields of an inbound packet relevant to filtering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketMeta {
    pub src: IpAddr,
    /// Destination port for TCP/UDP; `None` for other protocols (e.g. ICMP).
    pub dst_port: Option<u16>,
}

/// Parse the source address and destination port from an IPv4 packet.
/// Returns `None` for non-IPv4 or truncated input.
pub fn parse_ipv4(pkt: &[u8]) -> Option<PacketMeta> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if ihl < 20 || pkt.len() < ihl {
        return None;
    }
    let protocol = pkt[9];
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);

    let dst_port = match protocol {
        PROTO_TCP | PROTO_UDP if pkt.len() >= ihl + 4 => {
            Some(u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]))
        }
        _ => None,
    };

    Some(PacketMeta {
        src: IpAddr::V4(src),
        dst_port,
    })
}

/// Decide whether an inbound packet is permitted by the node's packet filter.
///
/// An empty filter means "no port filtering" (allow-all) — consistent with the
/// coordinator, which leaves the filter empty when no ACL policy is configured.
pub fn allows_inbound(filter: &[FilterRule], meta: &PacketMeta) -> bool {
    if filter.is_empty() {
        return true;
    }
    filter.iter().any(|rule| {
        let src_ok = rule.src_ips.iter().any(|net| net.contains(&meta.src));
        if !src_ok {
            return false;
        }
        match (&rule.ports, meta.dst_port) {
            (Ports::All, _) => true,
            (Ports::List(ports), Some(p)) => ports.contains(&p),
            // A port-restricted rule can't match a packet with no port (ICMP).
            (Ports::List(_), None) => false,
        }
    })
}

/// Port matcher for a compiled filter entry.
#[derive(Debug, Clone)]
enum PortMatcher {
    All,
    Set(HashSet<u16>),
}

impl PortMatcher {
    fn from_ports(ports: &Ports) -> Self {
        match ports {
            Ports::All => PortMatcher::All,
            Ports::List(p) => PortMatcher::Set(p.iter().copied().collect()),
        }
    }

    fn allows(&self, port: Option<u16>) -> bool {
        match self {
            PortMatcher::All => true,
            PortMatcher::Set(set) => port.is_some_and(|p| set.contains(&p)),
        }
    }

    /// Combine two matchers (a source IP allowed by multiple rules).
    fn merge(&mut self, other: &PortMatcher) {
        match (&mut *self, other) {
            (PortMatcher::All, _) => {}
            (slot, PortMatcher::All) => *slot = PortMatcher::All,
            (PortMatcher::Set(a), PortMatcher::Set(b)) => a.extend(b.iter().copied()),
        }
    }
}

/// A packet filter compiled for fast per-packet evaluation.
///
/// ACL source selectors resolve to peer overlay `/32`s, so the common case is an
/// exact-IP `HashMap` lookup (O(1)) instead of scanning every rule's IP list.
/// Non-`/32` CIDRs (rare) fall back to a short linear scan. This is what the
/// agent uses on the inbound data path; [`allows_inbound`] is the reference impl.
#[derive(Debug, Clone)]
pub struct CompiledFilter {
    exact: HashMap<u32, PortMatcher>,
    nets: Vec<(IpNet, PortMatcher)>,
    empty: bool,
}

impl Default for CompiledFilter {
    /// An empty filter that allows everything (the no-policy default).
    fn default() -> Self {
        Self::compile(&[])
    }
}

impl CompiledFilter {
    /// Compile a rule set into the fast lookup form.
    pub fn compile(rules: &[FilterRule]) -> Self {
        let mut exact: HashMap<u32, PortMatcher> = HashMap::new();
        let mut nets: Vec<(IpNet, PortMatcher)> = Vec::new();

        for rule in rules {
            let pm = PortMatcher::from_ports(&rule.ports);
            for net in &rule.src_ips {
                match net {
                    IpNet::V4(v4) if v4.prefix_len() == 32 => {
                        let bits = u32::from(v4.addr());
                        exact
                            .entry(bits)
                            .and_modify(|existing| existing.merge(&pm))
                            .or_insert_with(|| pm.clone());
                    }
                    _ => nets.push((*net, pm.clone())),
                }
            }
        }

        Self {
            exact,
            nets,
            empty: rules.is_empty(),
        }
    }

    /// Whether a parsed inbound packet is permitted. Empty filter = allow-all.
    pub fn allows(&self, meta: &PacketMeta) -> bool {
        if self.empty {
            return true;
        }
        if let IpAddr::V4(v4) = meta.src {
            if let Some(pm) = self.exact.get(&u32::from(v4)) {
                if pm.allows(meta.dst_port) {
                    return true;
                }
            }
        }
        self.nets
            .iter()
            .any(|(net, pm)| net.contains(&meta.src) && pm.allows(meta.dst_port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal IPv4 packet with the given protocol + dst port.
    fn packet(protocol: u8, src: [u8; 4], dst_port: u16) -> Vec<u8> {
        let mut p = vec![0u8; 24];
        p[0] = 0x45; // version 4, IHL 5 (20 bytes)
        p[3] = 24; // total length
        p[8] = 64; // TTL
        p[9] = protocol;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&[100, 64, 0, 1]); // dst overlay
        p[20..22].copy_from_slice(&1234u16.to_be_bytes()); // src port
        p[22..24].copy_from_slice(&dst_port.to_be_bytes()); // dst port
        p
    }

    fn rule(src_cidr: &str, ports: Ports) -> FilterRule {
        FilterRule {
            src_ips: vec![src_cidr.parse().unwrap()],
            ports,
        }
    }

    #[test]
    fn parses_tcp_src_and_dst_port() {
        let meta = parse_ipv4(&packet(PROTO_TCP, [100, 64, 0, 10], 22)).unwrap();
        assert_eq!(meta.src, "100.64.0.10".parse::<IpAddr>().unwrap());
        assert_eq!(meta.dst_port, Some(22));
    }

    #[test]
    fn rejects_non_ipv4() {
        assert!(parse_ipv4(&[0x60, 0, 0, 0]).is_none()); // IPv6 nibble
        assert!(parse_ipv4(&[0x45, 0]).is_none()); // truncated
    }

    #[test]
    fn empty_filter_allows_everything() {
        let meta = parse_ipv4(&packet(PROTO_TCP, [203, 0, 113, 5], 80)).unwrap();
        assert!(allows_inbound(&[], &meta));
    }

    #[test]
    fn enforces_source_and_port() {
        let filter = vec![rule("100.64.0.10/32", Ports::List(vec![22, 443]))];

        // Allowed source + allowed port.
        let ok = parse_ipv4(&packet(PROTO_TCP, [100, 64, 0, 10], 22)).unwrap();
        assert!(allows_inbound(&filter, &ok));

        // Allowed source, disallowed port.
        let bad_port = parse_ipv4(&packet(PROTO_TCP, [100, 64, 0, 10], 80)).unwrap();
        assert!(!allows_inbound(&filter, &bad_port));

        // Disallowed source.
        let bad_src = parse_ipv4(&packet(PROTO_TCP, [100, 64, 0, 11], 22)).unwrap();
        assert!(!allows_inbound(&filter, &bad_src));
    }

    #[test]
    fn all_ports_rule_allows_icmp() {
        let filter = vec![rule("100.64.0.0/10", Ports::All)];
        // ICMP (protocol 1) has no port.
        let icmp = parse_ipv4(&packet(1, [100, 64, 0, 10], 0)).unwrap();
        assert_eq!(icmp.dst_port, None);
        assert!(allows_inbound(&filter, &icmp));
    }

    #[test]
    fn compiled_matches_reference() {
        let filter = vec![
            rule("100.64.0.10/32", Ports::List(vec![22, 443])),
            rule("100.64.0.0/10", Ports::All), // a CIDR (fallback) rule
        ];
        let compiled = CompiledFilter::compile(&filter);

        // Check a spread of sources/ports against both implementations.
        for (src, port) in [
            ([100, 64, 0, 10], 22),
            ([100, 64, 0, 10], 80),
            ([100, 64, 0, 11], 22),
            ([203, 0, 113, 5], 443),
        ] {
            let meta = parse_ipv4(&packet(PROTO_TCP, src, port)).unwrap();
            assert_eq!(
                compiled.allows(&meta),
                allows_inbound(&filter, &meta),
                "mismatch for {src:?}:{port}"
            );
        }
    }

    #[test]
    fn empty_compiled_filter_allows_all() {
        let compiled = CompiledFilter::compile(&[]);
        let meta = parse_ipv4(&packet(PROTO_TCP, [1, 2, 3, 4], 9999)).unwrap();
        assert!(compiled.allows(&meta));
    }
}
