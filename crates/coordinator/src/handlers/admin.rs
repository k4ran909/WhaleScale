//! Read-mostly admin API consumed by the dashboard.
//!
//! TODO(Phase 5): require an authenticated admin/owner session and scope every
//! query to the caller's tenant via SSO. For now these are open (dev only).

use axum::extract::{Path, State};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::types::ipnetwork::IpNetwork;
use sqlx::types::Json as SqlxJson;
use sqlx::FromRow;
use uuid::Uuid;
use ws_proto::Endpoint;

use crate::auth::{AdminSession, Role};
use crate::error::{AppError, AppResult};
use crate::state::AppState;

#[derive(Debug, Serialize, FromRow)]
pub struct TenantSummary {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub device_count: i64,
}

/// List tenants the caller belongs to (org switcher). Scoped to the session's
/// own tenant — cross-tenant listing is never exposed.
pub async fn list_tenants(
    session: AdminSession,
    State(state): State<AppState>,
) -> AppResult<Json<Vec<TenantSummary>>> {
    let rows = sqlx::query_as::<_, TenantSummary>(
        r#"SELECT t.id, t.name, t.slug,
                  COUNT(d.id) AS device_count
           FROM tenants t
           LEFT JOIN devices d ON d.tenant_id = t.id
           WHERE t.id = $1
           GROUP BY t.id
           ORDER BY t.name"#,
    )
    .bind(session.tenant_id)
    .fetch_all(state.db())
    .await?;
    Ok(Json(rows))
}

#[derive(Debug, Serialize)]
pub struct DeviceSummary {
    pub id: Uuid,
    pub hostname: String,
    pub os: String,
    pub overlay_ip: String,
    pub online: bool,
    pub last_seen: Option<DateTime<Utc>>,
    /// "direct" if any STUN/local endpoint is known, else "relay" fallback.
    pub connectivity: &'static str,
    pub relay_region: Option<String>,
    pub endpoint_count: usize,
    /// False while the device is awaiting admin approval (excluded from the mesh).
    pub approved: bool,
    /// When the device's WireGuard key expires (None = never).
    pub key_expires_at: Option<DateTime<Utc>>,
}

#[derive(FromRow)]
struct DeviceRow {
    id: Uuid,
    hostname: String,
    os: String,
    overlay_ip: IpNetwork,
    endpoints: SqlxJson<Vec<Endpoint>>,
    relay_region: Option<String>,
    last_seen: Option<DateTime<Utc>>,
    approved: bool,
    key_expires_at: Option<DateTime<Utc>>,
}

/// Derive a device's live status from its last-seen time and endpoints. Pure so
/// it can be unit-tested without a database.
fn device_status(
    last_seen: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    endpoint_count: usize,
) -> (bool, &'static str) {
    let online = last_seen
        .map(|t| (now - t).num_seconds() < 60)
        .unwrap_or(false);
    let connectivity = if endpoint_count > 0 {
        "direct"
    } else {
        "relay"
    };
    (online, connectivity)
}

/// List devices for a tenant.
pub async fn list_devices(
    session: AdminSession,
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
) -> AppResult<Json<Vec<DeviceSummary>>> {
    session.require_tenant(tenant_id)?;
    let rows = sqlx::query_as::<_, DeviceRow>(
        r#"SELECT id, hostname, os, overlay_ip, endpoints, relay_region, last_seen, approved, key_expires_at
           FROM devices WHERE tenant_id = $1 ORDER BY approved, hostname"#,
    )
    .bind(tenant_id)
    .fetch_all(state.db())
    .await?;

    let now = Utc::now();
    let devices = rows
        .into_iter()
        .map(|d| {
            let endpoint_count = d.endpoints.0.len();
            let (online, connectivity) = device_status(d.last_seen, now, endpoint_count);
            DeviceSummary {
                id: d.id,
                hostname: d.hostname,
                os: d.os,
                overlay_ip: d.overlay_ip.ip().to_string(),
                online,
                last_seen: d.last_seen,
                connectivity,
                relay_region: d.relay_region,
                endpoint_count,
                approved: d.approved,
                key_expires_at: d.key_expires_at,
            }
        })
        .collect();

    Ok(Json(devices))
}

/// Approve a pending device, admitting it to the mesh. Admin+ only, tenant-scoped.
pub async fn approve_device(
    session: AdminSession,
    State(state): State<AppState>,
    Path(device_id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    session.require_role(Role::Admin)?;
    let result = sqlx::query(
        "UPDATE devices SET approved = true WHERE id = $1 AND tenant_id = $2 AND approved = false",
    )
    .bind(device_id)
    .bind(session.tenant_id)
    .execute(state.db())
    .await?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    sqlx::query(
        "INSERT INTO audit_log (tenant_id, actor_id, action, target) VALUES ($1, $2, 'device.approve', $3)",
    )
    .bind(session.tenant_id)
    .bind(session.user_id)
    .bind(device_id.to_string())
    .execute(state.db())
    .await?;

    // The device now belongs in peers' maps.
    crate::realtime::broadcast(&state, session.tenant_id).await;
    Ok(Json(serde_json::json!({ "status": "approved" })))
}

/// Remove a device (revokes it from the mesh). Admin+ only; scoped to the
/// caller's tenant so one org can't delete another's devices.
pub async fn delete_device(
    session: AdminSession,
    State(state): State<AppState>,
    Path(device_id): Path<Uuid>,
) -> AppResult<axum::http::StatusCode> {
    session.require_role(Role::Admin)?;
    let result = sqlx::query("DELETE FROM devices WHERE id = $1 AND tenant_id = $2")
        .bind(device_id)
        .bind(session.tenant_id)
        .execute(state.db())
        .await?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    crate::realtime::broadcast(&state, session.tenant_id).await;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize, FromRow)]
pub struct AuditEntry {
    pub action: String,
    pub target: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Get the tenant's active ACL policy document (empty object if none set).
pub async fn get_acl(
    session: AdminSession,
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    session.require_tenant(tenant_id)?;
    let doc: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT document FROM acl_policies WHERE tenant_id = $1 AND active LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_optional(state.db())
    .await?;
    Ok(Json(
        doc.unwrap_or_else(|| serde_json::json!({ "acls": [] })),
    ))
}

/// Validate and store a new ACL policy document for the tenant (admin+ only).
pub async fn put_acl(
    session: AdminSession,
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
    Json(doc): Json<serde_json::Value>,
) -> AppResult<Json<serde_json::Value>> {
    session.require_tenant(tenant_id)?;
    session.require_role(Role::Admin)?;
    // Reject invalid documents before persisting.
    crate::acl::Policy::parse(&doc).map_err(AppError::BadRequest)?;

    // Upsert the single active policy row, bumping its version.
    let updated = sqlx::query(
        "UPDATE acl_policies SET document = $1, version = version + 1
         WHERE tenant_id = $2 AND active",
    )
    .bind(&doc)
    .bind(tenant_id)
    .execute(state.db())
    .await?;

    if updated.rows_affected() == 0 {
        sqlx::query("INSERT INTO acl_policies (tenant_id, document, active) VALUES ($1, $2, true)")
            .bind(tenant_id)
            .bind(&doc)
            .execute(state.db())
            .await?;
    }

    sqlx::query("INSERT INTO audit_log (tenant_id, action) VALUES ($1, 'acl.update')")
        .bind(tenant_id)
        .execute(state.db())
        .await?;

    // Reachability may have changed; refresh connected agents.
    crate::realtime::broadcast(&state, tenant_id).await;

    Ok(Json(serde_json::json!({ "status": "ok" })))
}

#[derive(Debug, Serialize)]
pub struct LatencyEntry {
    pub device_id: Uuid,
    pub hostname: Option<String>,
    pub last_ms: Option<u32>,
    pub avg_ms: Option<f64>,
    pub p95_ms: Option<u32>,
    pub samples: Vec<u32>,
    pub tx_bps: f64,
    pub rx_bps: f64,
}

/// Per-device latency + throughput stats for the tenant (from in-memory stores).
pub async fn list_latency(
    session: AdminSession,
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
) -> AppResult<Json<Vec<LatencyEntry>>> {
    session.require_tenant(tenant_id)?;

    // Map device_id -> hostname for nicer labels.
    let names: std::collections::HashMap<Uuid, String> = sqlx::query_as::<_, (Uuid, String)>(
        "SELECT id, hostname FROM devices WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_all(state.db())
    .await?
    .into_iter()
    .collect();

    // device_id -> (tx_bps, rx_bps)
    let rates: std::collections::HashMap<Uuid, (f64, f64)> = state
        .throughput()
        .snapshot(tenant_id)
        .into_iter()
        .map(|t| (t.device_id, (t.tx_bps, t.rx_bps)))
        .collect();

    let entries = state
        .latency()
        .snapshot(tenant_id)
        .into_iter()
        .map(|s| {
            let (tx_bps, rx_bps) = rates.get(&s.device_id).copied().unwrap_or((0.0, 0.0));
            LatencyEntry {
                hostname: names.get(&s.device_id).cloned(),
                device_id: s.device_id,
                last_ms: s.last,
                avg_ms: s.avg,
                p95_ms: s.p95,
                samples: s.samples,
                tx_bps,
                rx_bps,
            }
        })
        .collect();

    Ok(Json(entries))
}

/// Recent audit log for a tenant.
pub async fn list_audit(
    session: AdminSession,
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
) -> AppResult<Json<Vec<AuditEntry>>> {
    session.require_tenant(tenant_id)?;
    let rows = sqlx::query_as::<_, AuditEntry>(
        r#"SELECT action, target, created_at FROM audit_log
           WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 100"#,
    )
    .bind(tenant_id)
    .fetch_all(state.db())
    .await?;
    Ok(Json(rows))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn online_within_60s_and_direct_with_endpoints() {
        let now = Utc::now();
        let (online, conn) = device_status(Some(now), now, 2);
        assert!(online);
        assert_eq!(conn, "direct");
    }

    #[test]
    fn offline_when_stale_and_relayed_without_endpoints() {
        let now = Utc::now();
        let stale = now - chrono::Duration::seconds(120);
        let (online, conn) = device_status(Some(stale), now, 0);
        assert!(!online);
        assert_eq!(conn, "relay");
    }

    #[test]
    fn never_seen_is_offline() {
        let now = Utc::now();
        let (online, _) = device_status(None, now, 0);
        assert!(!online);
    }
}
