//! HTTP routing table.

use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::handlers;
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/version", get(version))
        // Agent control plane
        .route("/enroll", post(handlers::enroll::enroll))
        .route("/rotate", post(handlers::enroll::rotate))
        .route("/netmap", get(handlers::netmap::get_netmap))
        .route("/endpoints", post(handlers::endpoints::report_endpoints))
        .route("/stats", post(handlers::stats::report_stats))
        .route("/throughput", post(handlers::stats::report_throughput))
        .route("/ws", get(handlers::ws::ws_handler))
        // Dashboard auth
        .route("/admin/login", post(handlers::auth::login))
        .route("/admin/me", get(handlers::auth::me))
        .route(
            "/admin/tenants/:tenant_id/users",
            get(handlers::users::list_users).post(handlers::auth::create_user),
        )
        .route(
            "/admin/users/:user_id/role",
            axum::routing::patch(handlers::users::update_role),
        )
        .route(
            "/admin/users/:user_id",
            axum::routing::delete(handlers::users::delete_user),
        )
        // Admin API (consumed by the dashboard; requires an AdminSession)
        .route("/admin/tenants", get(handlers::admin::list_tenants))
        .route(
            "/admin/tenants/:tenant_id/devices",
            get(handlers::admin::list_devices),
        )
        .route(
            "/admin/tenants/:tenant_id/audit",
            get(handlers::admin::list_audit),
        )
        .route(
            "/admin/tenants/:tenant_id/latency",
            get(handlers::admin::list_latency),
        )
        .route(
            "/admin/tenants/:tenant_id/acl",
            get(handlers::admin::get_acl).put(handlers::admin::put_acl),
        )
        .route(
            "/admin/devices/:device_id",
            axum::routing::delete(handlers::admin::delete_device),
        )
        .route(
            "/admin/devices/:device_id/approve",
            post(handlers::admin::approve_device),
        )
        .route(
            "/admin/tenants/:tenant_id/authkeys",
            get(handlers::authkeys::list_auth_keys).post(handlers::authkeys::create_auth_key),
        )
        .route(
            "/admin/authkeys/:key_id/revoke",
            post(handlers::authkeys::revoke_auth_key),
        )
        // Dev-only bootstrap (removed in Phase 5)
        .route("/dev/bootstrap", post(handlers::dev::bootstrap))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state)
}

/// Liveness/readiness probe. Verifies the DB is reachable.
async fn healthz(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<Json<serde_json::Value>, crate::error::AppError> {
    sqlx::query("SELECT 1").execute(state.db()).await?;
    Ok(Json(json!({ "status": "ok" })))
}

async fn version() -> Json<serde_json::Value> {
    Json(json!({
        "name": "whalescale-coordinator",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}
