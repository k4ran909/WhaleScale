//! WhaleScale STUN server (RFC 5389 Binding).
//!
//! Listens on UDP and answers Binding Requests with the sender's reflexive
//! (public) `IP:port` as XOR-MAPPED-ADDRESS, so agents can learn how peers see
//! them through NAT. Stateless — every datagram is handled independently.

use std::net::SocketAddr;

use tokio::net::UdpSocket;
use ws_stun::{encode_binding_response, parse_header, TYPE_BINDING_REQUEST};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let bind: SocketAddr = std::env::var("STUN_BIND")
        .unwrap_or_else(|_| "0.0.0.0:3478".to_string())
        .parse()?;

    let socket = UdpSocket::bind(bind).await?;
    tracing::info!(%bind, "STUN server listening");

    serve(socket).await
}

/// Run the STUN response loop on an already-bound socket. Exposed so tests can
/// drive it over loopback.
pub async fn serve(socket: UdpSocket) -> anyhow::Result<()> {
    let mut buf = [0u8; 1500];
    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "recv_from failed");
                continue;
            }
        };

        let Some(header) = parse_header(&buf[..len]) else {
            tracing::debug!(%src, "dropping non-STUN / bad-cookie datagram");
            continue;
        };
        if header.msg_type != TYPE_BINDING_REQUEST {
            continue;
        }

        let resp = encode_binding_response(header.txid, src);
        if let Err(e) = socket.send_to(&resp, src).await {
            tracing::warn!(error = %e, %src, "failed to send STUN response");
        } else {
            tracing::trace!(%src, "answered Binding Request");
        }
    }
}
