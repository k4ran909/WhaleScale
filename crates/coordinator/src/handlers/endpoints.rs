//! Endpoint reporting: agents POST their discovered local/STUN endpoints so the
//! coordinator can share them with peers for hole punching.

use axum::extract::State;
use axum::Json;
use serde_json::json;
use sqlx::types::Json as SqlxJson;

use ws_proto::EndpointUpdate;

use crate::auth::AgentSession;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

pub async fn report_endpoints(
    session: AgentSession,
    State(state): State<AppState>,
    Json(update): Json<EndpointUpdate>,
) -> AppResult<Json<serde_json::Value>> {
    // A device may only report its own endpoints.
    if update.device_id != session.device_id {
        return Err(AppError::BadRequest("device_id mismatch".into()));
    }

    sqlx::query("UPDATE devices SET endpoints = $1, last_seen = now() WHERE id = $2")
        .bind(SqlxJson(&update.endpoints))
        .bind(session.device_id)
        .execute(state.db())
        .await?;

    // Endpoints changed -> peers need a fresh map.
    crate::realtime::broadcast(&state, session.tenant_id).await;

    Ok(Json(json!({ "status": "ok" })))
}
