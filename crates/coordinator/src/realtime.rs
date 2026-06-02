//! Live network-map fanout to connected agents.

use uuid::Uuid;
use ws_proto::ServerMessage;

use crate::state::AppState;

/// Rebuild and push a fresh network map to every connected agent in `tenant`.
/// Call this after anything that changes the map (endpoint updates, new/removed
/// devices, ACL changes in Phase 5).
pub async fn broadcast(state: &AppState, tenant: Uuid) {
    let relays = state.settings().relay_regions();
    for device_id in state.hub().connected_devices(tenant) {
        match crate::netmap::build(state.db(), tenant, device_id, relays.clone()).await {
            Ok(map) => state
                .hub()
                .send_to(tenant, device_id, ServerMessage::NetworkMap(map)),
            Err(e) => tracing::error!(error = ?e, %device_id, "fanout: failed to build map"),
        }
    }
}
