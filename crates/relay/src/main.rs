//! WhaleScale relay server entrypoint.

use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let bind: SocketAddr = std::env::var("RELAY_BIND")
        .unwrap_or_else(|_| "0.0.0.0:3479".to_string())
        .parse()?;

    // Set RELAY_JWT_SECRET to the coordinator's JWT_SECRET to require
    // authenticated clients (recommended). Unset = dev mode (open).
    let jwt_secret = std::env::var("RELAY_JWT_SECRET").ok();
    if jwt_secret.is_none() {
        tracing::warn!(
            "RELAY_JWT_SECRET not set — relay is accepting unauthenticated clients (dev only)"
        );
    }

    let app = ws_relay::router(ws_relay::RelayState::new(jwt_secret));
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(%bind, "relay listening on /relay");

    axum::serve(listener, app).await?;
    Ok(())
}
