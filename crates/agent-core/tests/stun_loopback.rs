//! Integration test: the agent's STUN discovery against a real (loopback)
//! STUN responder built from the shared `ws-stun` codec.

use std::net::{IpAddr, Ipv4Addr};

use tokio::net::UdpSocket;
use ws_agent_core::discovery::discover_endpoints;
use ws_proto::EndpointKind;
use ws_stun::{encode_binding_response, parse_header, TYPE_BINDING_REQUEST};

#[tokio::test]
async fn discovers_reflexive_address_over_loopback() {
    // Minimal STUN responder on loopback.
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let Ok((len, src)) = server.recv_from(&mut buf).await else {
                continue;
            };
            if let Some(h) = parse_header(&buf[..len]) {
                if h.msg_type == TYPE_BINDING_REQUEST {
                    let resp = encode_binding_response(h.txid, src);
                    let _ = server.send_to(&resp, src).await;
                }
            }
        }
    });

    let discovery = discover_endpoints(server_addr, 0).await.unwrap();

    let stun = discovery
        .endpoints
        .iter()
        .find(|e| matches!(e.kind, EndpointKind::Stun))
        .expect("a STUN-discovered endpoint");

    // The responder sees us on loopback; the reflexive port must be real.
    assert_eq!(stun.addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_ne!(stun.addr.port(), 0);
    // A round-trip time was measured.
    assert!(discovery.stun_rtt_ms.is_some());
}
