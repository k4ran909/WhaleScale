//! Control-channel WebSocket between coordinator and agent.
//!
//! On connect the agent is registered with the [`Hub`](crate::hub::Hub) so the
//! coordinator can push fresh [`NetworkMap`]s live whenever the tenant's map
//! changes. The agent streams [`EndpointUpdate`]s which we persist and fan out.

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Query, State, WebSocketUpgrade};
use axum::response::{IntoResponse, Response};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use sqlx::types::Json as SqlxJson;

use ws_proto::{ClientMessage, ServerMessage};

use crate::auth::verify_token;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct WsParams {
    token: String,
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(params): Query<WsParams>,
    State(state): State<AppState>,
) -> Response {
    let claims = match verify_token(&state.settings().jwt_secret, &params.token) {
        Ok(c) => c,
        Err(_) => return axum::http::StatusCode::UNAUTHORIZED.into_response(),
    };
    ws.on_upgrade(move |socket| handle_socket(socket, state, claims.sub, claims.tenant))
}

async fn handle_socket(
    socket: WebSocket,
    state: AppState,
    device_id: uuid::Uuid,
    tenant_id: uuid::Uuid,
) {
    let (mut sender, mut receiver) = socket.split();

    // Register for live pushes; the writer task drains the hub channel.
    let mut rx = state.hub().register(tenant_id, device_id);
    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            match serde_json::to_string(&msg) {
                Ok(text) => {
                    if sender.send(Message::Text(text)).await.is_err() {
                        break;
                    }
                }
                Err(e) => tracing::error!(error = %e, "failed to serialize server message"),
            }
        }
    });

    // Push the current map immediately via the hub (so it goes through the writer).
    let relays = state.settings().relay_regions();
    match crate::netmap::build(state.db(), tenant_id, device_id, relays).await {
        Ok(map) => state
            .hub()
            .send_to(tenant_id, device_id, ServerMessage::NetworkMap(map)),
        Err(e) => tracing::error!(error = ?e, "failed to build initial network map"),
    }

    // Read loop: persist endpoint updates and fan out to peers.
    while let Some(Ok(msg)) = receiver.next().await {
        match msg {
            Message::Text(text) => match serde_json::from_str::<ClientMessage>(&text) {
                Ok(ClientMessage::Endpoints(update)) => {
                    if update.device_id != device_id {
                        continue;
                    }
                    let res = sqlx::query(
                        "UPDATE devices SET endpoints = $1, last_seen = now() WHERE id = $2",
                    )
                    .bind(SqlxJson(&update.endpoints))
                    .bind(device_id)
                    .execute(state.db())
                    .await;
                    match res {
                        Ok(_) => crate::realtime::broadcast(&state, tenant_id).await,
                        Err(e) => tracing::error!(error = %e, "failed to store endpoints"),
                    }
                }
                Ok(ClientMessage::Pong) => {}
                Err(e) => tracing::debug!(error = %e, "unparseable client message"),
            },
            Message::Close(_) => break,
            _ => {}
        }
    }

    // Cleanup.
    state.hub().unregister(tenant_id, device_id);
    writer.abort();
    tracing::debug!(%device_id, "control channel closed");
}
