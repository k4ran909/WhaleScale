//! WhaleScale coordinator (control plane) entrypoint.

mod acl;
mod auth;
mod config;
mod error;
mod handlers;
mod hub;
mod ipam;
mod models;
mod netmap;
mod realtime;
mod routes;
mod state;
mod stats;

use anyhow::Context;
use sqlx::postgres::PgPoolOptions;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::config::Settings;
use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let settings = Settings::from_env().context("failed to load configuration")?;
    tracing::info!(bind = %settings.bind_addr, "starting coordinator");

    // Connect to Postgres and run migrations.
    let db = PgPoolOptions::new()
        .max_connections(16)
        .connect(&settings.database_url)
        .await
        .context("failed to connect to Postgres")?;

    sqlx::migrate!("../../migrations")
        .run(&db)
        .await
        .context("failed to run migrations")?;
    tracing::info!("migrations applied");

    let state = AppState::new(db, settings.clone());
    let app = routes::router(state);

    let listener = tokio::net::TcpListener::bind(&settings.bind_addr)
        .await
        .with_context(|| format!("failed to bind {}", settings.bind_addr))?;
    tracing::info!(addr = %settings.bind_addr, "coordinator listening");

    axum::serve(listener, app).await.context("server error")?;

    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,ws_coordinator=debug"));
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}
