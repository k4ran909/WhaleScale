//! Relay (DERP-style) fallback client.
//!
//! When direct hole-punching to a peer fails, the agent tunnels its already-
//! encrypted WireGuard packets through a relay. This client connects to the
//! relay, registers its public key, and sends/receives opaque frames addressed
//! by peer public key.

use anyhow::Context;
use futures::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use ws_proto::relay::{decode_frame, encode_frame, RelayHello};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub struct RelayClient {
    ws: Ws,
    public_key: String,
}

impl RelayClient {
    /// Connect to a relay at `url` (e.g. `ws://relay:3479/relay`) and register.
    pub async fn connect(url: &str, public_key: &str, token: &str) -> anyhow::Result<Self> {
        let (mut ws, _resp) = connect_async(url).await.context("relay connect failed")?;
        let hello = RelayHello {
            public_key: public_key.to_string(),
            token: token.to_string(),
        };
        ws.send(Message::Text(serde_json::to_string(&hello)?))
            .await
            .context("relay hello failed")?;
        Ok(Self {
            ws,
            public_key: public_key.to_string(),
        })
    }

    /// Relay `payload` to peer `dst_public_key`.
    pub async fn send(&mut self, dst_public_key: &str, payload: &[u8]) -> anyhow::Result<()> {
        self.ws
            .send(Message::Binary(encode_frame(dst_public_key, payload)))
            .await
            .context("relay send failed")
    }

    /// Await the next relayed frame as `(src_public_key, payload)`.
    /// Returns `None` when the connection closes.
    pub async fn recv(&mut self) -> anyhow::Result<Option<(String, Vec<u8>)>> {
        while let Some(msg) = self.ws.next().await {
            match msg.context("relay recv failed")? {
                Message::Binary(buf) => {
                    if let Some((src, payload)) = decode_frame(&buf) {
                        return Ok(Some((src, payload.to_vec())));
                    }
                }
                Message::Close(_) => return Ok(None),
                _ => continue,
            }
        }
        Ok(None)
    }

    pub fn public_key(&self) -> &str {
        &self.public_key
    }
}
