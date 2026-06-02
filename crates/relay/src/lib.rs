//! WhaleScale DERP-style relay: an authenticated WebSocket packet forwarder
//! used when two peers cannot hole-punch a direct path. It forwards opaque,
//! already-encrypted WireGuard frames keyed by public key and never sees
//! plaintext.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use futures::{SinkExt, StreamExt};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::Deserialize;
use tokio::sync::mpsc;
use ws_proto::relay::{decode_frame, encode_frame, RelayHello};

/// Minimal view of a coordinator-issued session token (we only need to confirm
/// the signature + expiry — the relay never inspects the payload otherwise).
#[derive(Debug, Deserialize)]
struct TokenClaims {
    #[allow(dead_code)]
    exp: usize,
}

/// Verify a coordinator-signed JWT (HS256, checks expiry).
pub fn verify_token(secret: &str, token: &str) -> bool {
    decode::<TokenClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .is_ok()
}

/// Registry of connected clients: public key -> outbound queue. When a JWT
/// secret is configured, clients must present a valid coordinator token.
#[derive(Clone, Default)]
pub struct RelayState {
    peers: Arc<Mutex<HashMap<String, mpsc::UnboundedSender<Vec<u8>>>>>,
    jwt_secret: Option<Arc<String>>,
}

impl RelayState {
    /// Create a relay state. Pass `Some(secret)` (the coordinator's JWT secret)
    /// to require authenticated clients; `None` accepts any client (dev only).
    pub fn new(jwt_secret: Option<String>) -> Self {
        Self {
            peers: Arc::new(Mutex::new(HashMap::new())),
            jwt_secret: jwt_secret.map(Arc::new),
        }
    }

    fn authorize(&self, token: &str) -> bool {
        match &self.jwt_secret {
            Some(secret) => verify_token(secret, token),
            None => true, // dev mode: no secret configured
        }
    }

    fn register(&self, key: String) -> mpsc::UnboundedReceiver<Vec<u8>> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.peers.lock().unwrap().insert(key, tx);
        rx
    }

    fn unregister(&self, key: &str) {
        self.peers.lock().unwrap().remove(key);
    }

    /// Forward `payload` to `dst`, tagged with the `src` key. Returns false if
    /// the destination is not currently connected.
    fn forward(&self, src: &str, dst: &str, payload: &[u8]) -> bool {
        let peers = self.peers.lock().unwrap();
        if let Some(tx) = peers.get(dst) {
            tx.send(encode_frame(src, payload)).is_ok()
        } else {
            false
        }
    }
}

/// Build the relay router. `verify` authorizes a `RelayHello` (return the
/// accepted public key, or `None` to reject). Inject coordinator JWT validation
/// here; the default accepts the advertised key (dev only).
pub fn router(state: RelayState) -> Router {
    Router::new()
        .route("/relay", get(ws_upgrade))
        .with_state(state)
}

async fn ws_upgrade(ws: WebSocketUpgrade, State(state): State<RelayState>) -> Response {
    ws.on_upgrade(move |socket| handle(socket, state))
}

async fn handle(socket: WebSocket, state: RelayState) {
    let (mut sender, mut receiver) = socket.split();

    // First message must be a RelayHello.
    let hello = match receiver.next().await {
        Some(Ok(Message::Text(text))) => match serde_json::from_str::<RelayHello>(&text) {
            Ok(h) => h,
            Err(e) => {
                tracing::debug!(error = %e, "bad RelayHello");
                return;
            }
        },
        _ => return,
    };

    // Authenticate the client against the coordinator-issued token.
    if !state.authorize(&hello.token) {
        tracing::debug!(key = %hello.public_key, "relay: rejected unauthenticated client");
        return;
    }

    let my_key = hello.public_key;
    let mut rx = state.register(my_key.clone());
    tracing::debug!(key = %my_key, "relay client connected");

    // Writer task: drain outbound queue to the socket.
    let writer = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            if sender.send(Message::Binary(frame)).await.is_err() {
                break;
            }
        }
    });

    // Reader loop: forward each frame to its destination.
    while let Some(Ok(msg)) = receiver.next().await {
        match msg {
            Message::Binary(buf) => {
                if let Some((dst, payload)) = decode_frame(&buf) {
                    if !state.forward(&my_key, &dst, payload) {
                        tracing::trace!(%dst, "relay: destination not connected");
                    }
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    state.unregister(&my_key);
    writer.abort();
    tracing::debug!(key = %my_key, "relay client disconnected");
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde::Serialize;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Serialize)]
    struct Claims {
        sub: String,
        exp: usize,
    }

    fn token(secret: &str, exp_offset: i64) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let claims = Claims {
            sub: "device".into(),
            exp: (now + exp_offset) as usize,
        };
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    #[test]
    fn accepts_valid_rejects_invalid() {
        let secret = "coordinator-secret";
        assert!(verify_token(secret, &token(secret, 3600)), "valid token");
        // Beyond jsonwebtoken's default 60s expiry leeway.
        assert!(!verify_token(secret, &token(secret, -120)), "expired token");
        assert!(
            !verify_token(secret, &token("other-secret", 3600)),
            "wrong secret"
        );
        assert!(!verify_token(secret, "not-a-jwt"), "garbage");
    }

    #[test]
    fn dev_mode_accepts_any_token() {
        let state = RelayState::default(); // no secret
        assert!(state.authorize("anything"));
    }

    #[test]
    fn configured_state_requires_valid_token() {
        let secret = "s";
        let state = RelayState::new(Some(secret.to_string()));
        assert!(state.authorize(&token(secret, 3600)));
        assert!(!state.authorize("garbage"));
    }
}
