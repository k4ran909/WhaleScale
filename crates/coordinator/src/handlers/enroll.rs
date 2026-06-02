//! Device enrollment: an agent presents an auth key + its WireGuard public key,
//! and receives an identity, an overlay IP, and a session token.

use axum::extract::State;
use axum::Json;
use chrono::Utc;

use ws_proto::{EnrollRequest, EnrollResponse, RotateRequest, RotateResponse};

use crate::auth::{hash_auth_key, issue_token, AgentSession};
use crate::error::{AppError, AppResult};
use crate::models::AuthKey;
use crate::{ipam, state::AppState};

pub async fn enroll(
    State(state): State<AppState>,
    Json(req): Json<EnrollRequest>,
) -> AppResult<Json<EnrollResponse>> {
    let pool = state.db();

    // 1. Validate the auth key.
    let key_hash = hash_auth_key(&req.auth_key);
    let key: AuthKey = sqlx::query_as(
        r#"SELECT id, tenant_id, reusable, used_count, expires_at, revoked, require_approval
           FROM auth_keys WHERE key_hash = $1"#,
    )
    .bind(&key_hash)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::Unauthorized)?;

    if key.revoked {
        return Err(AppError::Unauthorized);
    }
    if let Some(exp) = key.expires_at {
        if exp < Utc::now() {
            return Err(AppError::Unauthorized);
        }
    }
    if !key.reusable && key.used_count > 0 {
        return Err(AppError::Unauthorized);
    }

    // 2. Validate advertised routes (CIDRs) before storing.
    for route in &req.advertised_routes {
        route
            .parse::<ipnet::IpNet>()
            .map_err(|_| AppError::BadRequest(format!("invalid route: {route}")))?;
    }

    // 3. Allocate an overlay address.
    let overlay_ip = ipam::allocate(pool, key.tenant_id).await?;

    // 4. Insert the device. Devices from approval-required keys start pending
    //    (`approved = false`) and stay out of every network map until an admin
    //    approves them. Re-enrolling the same key keeps the existing approval.
    let approved = !key.require_approval;
    let key_expires_at = state.settings().key_expiry();
    let row: (uuid::Uuid,) = sqlx::query_as(
        r#"INSERT INTO devices (tenant_id, hostname, os, public_key, overlay_ip, advertised_routes, approved, key_expires_at, last_seen)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
           ON CONFLICT (tenant_id, public_key)
           DO UPDATE SET hostname = EXCLUDED.hostname,
                         advertised_routes = EXCLUDED.advertised_routes,
                         key_expires_at = EXCLUDED.key_expires_at,
                         last_seen = now()
           RETURNING id"#,
    )
    .bind(key.tenant_id)
    .bind(&req.hostname)
    .bind(&req.os)
    .bind(&req.public_key)
    .bind(overlay_ip)
    .bind(&req.advertised_routes)
    .bind(approved)
    .bind(key_expires_at)
    .fetch_one(pool)
    .await?;
    let device_id = row.0;

    // 4. Re-read the (possibly pre-existing) overlay IP for this device.
    let assigned_ip: sqlx::types::ipnetwork::IpNetwork =
        sqlx::query_scalar("SELECT overlay_ip FROM devices WHERE id = $1")
            .bind(device_id)
            .fetch_one(pool)
            .await?;

    // 5. Count the key usage.
    sqlx::query("UPDATE auth_keys SET used_count = used_count + 1 WHERE id = $1")
        .bind(key.id)
        .execute(pool)
        .await?;

    // 6. Audit.
    let action = if approved {
        "device.enroll"
    } else {
        "device.enroll.pending"
    };
    sqlx::query("INSERT INTO audit_log (tenant_id, action, target) VALUES ($1, $2, $3)")
        .bind(key.tenant_id)
        .bind(action)
        .bind(device_id.to_string())
        .execute(pool)
        .await?;

    let session_token = issue_token(&state.settings().jwt_secret, device_id, key.tenant_id)
        .map_err(AppError::Other)?;

    Ok(Json(EnrollResponse {
        device_id,
        tenant_id: key.tenant_id,
        overlay_ip: crate::netmap::host_net(assigned_ip),
        session_token,
        key_expires_at,
    }))
}

/// Rotate this device's WireGuard key: store the new public key, reset expiry,
/// and push fresh maps so peers learn the new key.
pub async fn rotate(
    session: AgentSession,
    State(state): State<AppState>,
    Json(req): Json<RotateRequest>,
) -> AppResult<Json<RotateResponse>> {
    let key_expires_at = state.settings().key_expiry();
    let updated = sqlx::query(
        "UPDATE devices SET public_key = $1, key_expires_at = $2, last_seen = now()
         WHERE id = $3 AND tenant_id = $4",
    )
    .bind(&req.new_public_key)
    .bind(key_expires_at)
    .bind(session.device_id)
    .bind(session.tenant_id)
    .execute(state.db())
    .await?;
    if updated.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    sqlx::query(
        "INSERT INTO audit_log (tenant_id, action, target) VALUES ($1, 'device.rotate', $2)",
    )
    .bind(session.tenant_id)
    .bind(session.device_id.to_string())
    .execute(state.db())
    .await?;

    // Peers must learn the new public key.
    crate::realtime::broadcast(&state, session.tenant_id).await;

    Ok(Json(RotateResponse { key_expires_at }))
}
