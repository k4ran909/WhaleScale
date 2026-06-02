//! REST access to the network map for the authenticated device.

use axum::extract::State;
use axum::Json;
use ws_proto::NetworkMap;

use crate::auth::AgentSession;
use crate::error::AppResult;
use crate::state::AppState;

pub async fn get_netmap(
    session: AgentSession,
    State(state): State<AppState>,
) -> AppResult<Json<NetworkMap>> {
    // Touch last_seen so peers see this node as online.
    sqlx::query("UPDATE devices SET last_seen = now() WHERE id = $1")
        .bind(session.device_id)
        .execute(state.db())
        .await?;

    let map = crate::netmap::build(
        state.db(),
        session.tenant_id,
        session.device_id,
        state.settings().relay_regions(),
    )
    .await?;
    Ok(Json(map))
}
