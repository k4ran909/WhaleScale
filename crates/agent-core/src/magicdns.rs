//! MagicDNS: resolve peer hostnames (e.g. `prod-server-1` or
//! `prod-server-1.dev.whale.net`) to their overlay `100.64.x.x` address.
//!
//! Includes a minimal, dependency-free DNS codec (enough for `A` queries) and a
//! [`Resolver`] built from the current [`NetworkMap`]. The agent runs the
//! [`serve`] loop on a local address (Tailscale uses `100.100.100.100:53`) and
//! points the OS resolver at it.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use tokio::net::UdpSocket;
use ws_proto::NetworkMap;

const QTYPE_A: u16 = 1;

/// A parsed DNS question.
#[derive(Debug, Clone)]
pub struct Query {
    pub id: u16,
    pub name: String,
    pub qtype: u16,
    /// Raw question bytes (QNAME+QTYPE+QCLASS), echoed into the response.
    question: Vec<u8>,
}

/// Parse a single-question DNS query. Returns `None` for malformed input or
/// compressed question names (which queries never use).
pub fn parse_query(buf: &[u8]) -> Option<Query> {
    if buf.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount < 1 {
        return None;
    }

    let mut off = 12;
    let mut labels = Vec::new();
    loop {
        let len = *buf.get(off)? as usize;
        if len == 0 {
            off += 1;
            break;
        }
        if len & 0xC0 != 0 {
            return None; // compression pointer — not valid in a question
        }
        off += 1;
        let label = buf.get(off..off + len)?;
        labels.push(std::str::from_utf8(label).ok()?.to_string());
        off += len;
    }

    let qtype = u16::from_be_bytes([*buf.get(off)?, *buf.get(off + 1)?]);
    off += 4; // skip QTYPE + QCLASS

    Some(Query {
        id,
        name: labels.join("."),
        qtype,
        question: buf.get(12..off)?.to_vec(),
    })
}

/// Build a response for `query`, answering with `ip` (or NXDOMAIN when `None`).
pub fn build_response(query: &Query, ip: Option<Ipv4Addr>) -> Vec<u8> {
    let mut out = Vec::with_capacity(query.question.len() + 28);
    out.extend_from_slice(&query.id.to_be_bytes());
    // QR=1, RD=1, RA=1; RCODE 0 (NOERROR) when answered, 3 (NXDOMAIN) otherwise.
    let flags: u16 = if ip.is_some() { 0x8180 } else { 0x8183 };
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&(ip.is_some() as u16).to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    out.extend_from_slice(&query.question);

    if let Some(ip) = ip {
        out.extend_from_slice(&[0xC0, 0x0C]); // NAME: pointer to question at offset 12
        out.extend_from_slice(&QTYPE_A.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        out.extend_from_slice(&60u32.to_be_bytes()); // TTL 60s
        out.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        out.extend_from_slice(&ip.octets());
    }
    out
}

/// Name → overlay IPv4 lookup table.
#[derive(Debug, Default, Clone)]
pub struct Resolver {
    table: HashMap<String, Ipv4Addr>,
}

impl Resolver {
    /// Build a resolver from the network map. Each device is reachable by its
    /// short hostname and, if the tenant has a DNS suffix, its FQDN.
    pub fn from_netmap(map: &NetworkMap) -> Self {
        let mut table = HashMap::new();
        let suffix = map.dns_suffix.as_deref();

        let mut insert = |host: &str, ip: std::net::IpAddr| {
            if let std::net::IpAddr::V4(v4) = ip {
                table.insert(host.to_ascii_lowercase(), v4);
                if let Some(suffix) = suffix {
                    table.insert(format!("{host}.{suffix}").to_ascii_lowercase(), v4);
                }
            }
        };

        insert(&map.self_node.hostname, map.self_node.overlay_ip.addr());
        for peer in &map.peers {
            if let Some(net) = peer.allowed_ips.first() {
                insert(&peer.hostname, net.addr());
            }
        }

        Resolver { table }
    }

    /// Resolve a name (case-insensitive, trailing dot optional).
    pub fn resolve(&self, name: &str) -> Option<Ipv4Addr> {
        let key = name.trim_end_matches('.').to_ascii_lowercase();
        self.table.get(&key).copied()
    }
}

/// Serve MagicDNS over UDP, answering `A` queries from the shared resolver
/// (which the agent updates whenever the network map changes).
pub async fn serve(socket: UdpSocket, resolver: Arc<Mutex<Resolver>>) -> anyhow::Result<()> {
    let mut buf = [0u8; 512];
    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "magicdns recv failed");
                continue;
            }
        };
        let Some(query) = parse_query(&buf[..len]) else {
            continue;
        };
        let ip = if query.qtype == QTYPE_A {
            resolver.lock().unwrap().resolve(&query.name)
        } else {
            None
        };
        let resp = build_response(&query, ip);
        let _ = socket.send_to(&resp, src).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ws_proto::{NetworkMap, PeerNode, SelfNode};

    fn encode_query(id: u16, name: &str) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&id.to_be_bytes());
        q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD set
        q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        q.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR counts
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&QTYPE_A.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
        q
    }

    fn sample_map() -> NetworkMap {
        NetworkMap {
            version: 1,
            self_node: SelfNode {
                device_id: uuid::Uuid::nil(),
                overlay_ip: "100.64.0.1/32".parse().unwrap(),
                hostname: "my-laptop".into(),
            },
            peers: vec![PeerNode {
                device_id: uuid::Uuid::nil(),
                hostname: "prod-server-1".into(),
                public_key: "k".into(),
                allowed_ips: vec!["100.64.0.2/32".parse().unwrap()],
                endpoints: vec![],
                relay_region: None,
                online: true,
                last_seen: None,
            }],
            relays: vec![],
            dns_suffix: Some("dev.whale.net".into()),
            packet_filter: vec![],
        }
    }

    #[test]
    fn resolver_maps_short_and_fqdn() {
        let r = Resolver::from_netmap(&sample_map());
        assert_eq!(
            r.resolve("prod-server-1"),
            Some(Ipv4Addr::new(100, 64, 0, 2))
        );
        assert_eq!(
            r.resolve("prod-server-1.dev.whale.net"),
            Some(Ipv4Addr::new(100, 64, 0, 2))
        );
        assert_eq!(r.resolve("MY-LAPTOP"), Some(Ipv4Addr::new(100, 64, 0, 1)));
        assert_eq!(r.resolve("unknown"), None);
    }

    #[test]
    fn query_response_roundtrip() {
        let q = parse_query(&encode_query(0x1234, "prod-server-1.dev.whale.net")).unwrap();
        assert_eq!(q.id, 0x1234);
        assert_eq!(q.name, "prod-server-1.dev.whale.net");
        assert_eq!(q.qtype, QTYPE_A);

        let resp = build_response(&q, Some(Ipv4Addr::new(100, 64, 0, 2)));
        // Answer count = 1, and the trailing RDATA is the IP.
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
        assert_eq!(&resp[resp.len() - 4..], &[100, 64, 0, 2]);
    }

    #[tokio::test]
    async fn serves_a_query_over_loopback() {
        let resolver = Arc::new(Mutex::new(Resolver::from_netmap(&sample_map())));
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(serve(socket, resolver));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(&encode_query(1, "prod-server-1"), addr)
            .await
            .unwrap();

        let mut buf = [0u8; 512];
        let len = client.recv(&mut buf).await.unwrap();
        assert_eq!(
            &buf[len - 4..len],
            &[100, 64, 0, 2],
            "answer should carry the overlay IP"
        );
    }
}
