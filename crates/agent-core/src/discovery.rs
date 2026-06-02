//! Endpoint discovery: learn the addresses peers can reach this node on.
//!
//! Gathers two kinds of [`Endpoint`]:
//!  - **Local**: the source address the OS uses to reach the network, paired
//!    with our WireGuard UDP port.
//!  - **STUN**: the server-reflexive (public) address learned by querying a
//!    STUN server — what peers behind a different NAT must dial.
//!
//! Both are reported to the coordinator so it can hand them to peers for hole
//! punching. NOTE: to be valid for WireGuard, the STUN query must originate
//! from the *same* UDP socket/port WireGuard uses; we bind `wg_port` here.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context;
use tokio::net::UdpSocket;
use ws_proto::{Endpoint, EndpointKind};
use ws_stun::{
    encode_binding_request, parse_header, parse_xor_mapped_address, random_transaction_id,
};

/// Result of an endpoint-discovery pass.
pub struct Discovery {
    pub endpoints: Vec<Endpoint>,
    /// Measured STUN round-trip time in milliseconds, if STUN succeeded.
    pub stun_rtt_ms: Option<u32>,
}

/// Query `stun_server` from a socket bound to `wg_port` and return our local +
/// reflexive endpoints plus the measured STUN RTT. `wg_port` may be 0.
pub async fn discover_endpoints(
    stun_server: SocketAddr,
    wg_port: u16,
) -> anyhow::Result<Discovery> {
    let bind_ip = if stun_server.is_ipv6() {
        "[::]"
    } else {
        "0.0.0.0"
    };
    let socket = UdpSocket::bind(format!("{bind_ip}:{wg_port}"))
        .await
        .context("failed to bind discovery socket")?;
    let local_port = socket.local_addr()?.port();

    let mut endpoints = Vec::new();

    // Local endpoint (best-effort source IP towards the STUN server).
    if let Some(local_ip) = local_ip_towards(stun_server).await {
        endpoints.push(Endpoint {
            addr: SocketAddr::new(local_ip, local_port),
            kind: EndpointKind::Local,
        });
    }

    // STUN reflexive endpoint + RTT.
    let mut stun_rtt_ms = None;
    match query_stun(&socket, stun_server).await {
        Ok((reflexive, rtt_ms)) => {
            endpoints.push(Endpoint {
                addr: reflexive,
                kind: EndpointKind::Stun,
            });
            stun_rtt_ms = Some(rtt_ms);
        }
        Err(e) => tracing::warn!(error = %e, "STUN discovery failed"),
    }

    Ok(Discovery {
        endpoints,
        stun_rtt_ms,
    })
}

/// Send a single Binding Request and await the reflexive address, returning the
/// address and the round-trip time in milliseconds.
async fn query_stun(
    socket: &UdpSocket,
    stun_server: SocketAddr,
) -> anyhow::Result<(SocketAddr, u32)> {
    let txid = random_transaction_id();
    let req = encode_binding_request(txid);
    let started = std::time::Instant::now();
    socket
        .send_to(&req, stun_server)
        .await
        .context("failed to send STUN request")?;

    let mut buf = [0u8; 1500];
    let len = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut buf))
        .await
        .context("STUN response timed out")?
        .context("STUN recv failed")?;
    let rtt_ms = started.elapsed().as_millis().min(u32::MAX as u128) as u32;

    // Validate the transaction id matches before trusting the address.
    let header = parse_header(&buf[..len]).context("invalid STUN response header")?;
    if header.txid != txid {
        anyhow::bail!("STUN transaction id mismatch");
    }
    let addr =
        parse_xor_mapped_address(&buf[..len]).context("no XOR-MAPPED-ADDRESS in response")?;
    Ok((addr, rtt_ms))
}

/// Determine the local source IP the OS would use to reach `target`, using the
/// classic connected-UDP-socket trick (sends no packets).
async fn local_ip_towards(target: SocketAddr) -> Option<std::net::IpAddr> {
    let bind_ip = if target.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let probe = UdpSocket::bind(bind_ip).await.ok()?;
    probe.connect(target).await.ok()?;
    probe.local_addr().ok().map(|a| a.ip())
}
