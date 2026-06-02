//! Latency reporting from agents.

use axum::extract::State;
use axum::Json;
use serde_json::json;
use ws_proto::stats::{LatencySample, ThroughputSample};

use crate::auth::AgentSession;
use crate::error::AppResult;
use crate::state::AppState;

/// An agent reports a latency sample (e.g. its STUN round-trip time).
pub async fn report_stats(
    session: AgentSession,
    State(state): State<AppState>,
    Json(sample): Json<LatencySample>,
) -> AppResult<Json<serde_json::Value>> {
    state
        .latency()
        .push(session.tenant_id, session.device_id, sample.rtt_ms);
    Ok(Json(json!({ "status": "ok" })))
}

/// An agent reports cumulative interface byte counters; the store derives a rate.
pub async fn report_throughput(
    session: AgentSession,
    State(state): State<AppState>,
    Json(sample): Json<ThroughputSample>,
) -> AppResult<Json<serde_json::Value>> {
    state.throughput().push(
        session.tenant_id,
        session.device_id,
        sample.tx_bytes,
        sample.rx_bytes,
        chrono::Utc::now(),
    );
    Ok(Json(json!({ "status": "ok" })))
}
