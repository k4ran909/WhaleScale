//! Admin auth-key management: generate, list, and revoke the pre-auth keys used
//! for headless device enrollment.
//!
//! The raw key is shown exactly once (at creation). Only its SHA-256 hash is
//! stored for verification, plus a short non-secret prefix so the dashboard can
//! identify keys in listings. This replaces the dev-only `/dev/bootstrap` path
//! for real onboarding from the UI.

use axum::extract::{Path, State};
use axum::Json;
use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::auth::{hash_auth_key, AdminSession, Role};
use crate::error::{AppError, AppResult};
use crate::state::AppState;

/// A freshly generated key: the raw secret (shown once), its storage hash, and a
/// short non-secret prefix used for later identification in listings.
pub struct GeneratedKey {
    pub raw: String,
    pub hash: String,
    pub prefix: String,
}

/// Build an `ws-`-prefixed auth key from 24 random bytes. Pure (RNG injected by
/// the caller) so it can be unit-tested: the prefix is always a prefix of the
/// raw key, and the hash matches [`hash_auth_key`].
pub fn generate_key(bytes: [u8; 24]) -> GeneratedKey {
    let raw = format!("ws-{}", hex::encode(bytes));
    let hash = hash_auth_key(&raw);
    // "ws-" + first 8 hex chars: enough to recognize, reveals nothing useful.
    let prefix = raw.chars().take(11).collect();
    GeneratedKey { raw, hash, prefix }
}

#[derive(Debug, Deserialize)]
pub struct CreateAuthKey {
    #[serde(default)]
    pub reusable: bool,
    #[serde(default)]
    pub ephemeral: bool,
    #[serde(default)]
    pub require_approval: bool,
    /// Optional lifetime in days; omitted or non-positive = never expires.
    pub expires_in_days: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct CreatedAuthKey {
    pub id: Uuid,
    /// The raw key — returned ONCE and never retrievable again.
    pub auth_key: String,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Generate a new pre-auth key for a tenant (admin+). Returns the raw key once.
pub async fn create_auth_key(
    session: AdminSession,
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
    Json(req): Json<CreateAuthKey>,
) -> AppResult<Json<CreatedAuthKey>> {
    session.require_tenant(tenant_id)?;
    session.require_role(Role::Admin)?;

    let key = generate_key(rand::thread_rng().gen());
    let expires_at = req
        .expires_in_days
        .filter(|d| *d > 0)
        .map(|d| Utc::now() + Duration::days(d));

    let id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO auth_keys
               (tenant_id, key_hash, key_prefix, reusable, ephemeral, require_approval, expires_at, created_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(&key.hash)
    .bind(&key.prefix)
    .bind(req.reusable)
    .bind(req.ephemeral)
    .bind(req.require_approval)
    .bind(expires_at)
    .bind(session.user_id)
    .fetch_one(state.db())
    .await?;

    sqlx::query(
        "INSERT INTO audit_log (tenant_id, actor_id, action, target) VALUES ($1, $2, 'authkey.create', $3)",
    )
    .bind(tenant_id)
    .bind(session.user_id)
    .bind(id.to_string())
    .execute(state.db())
    .await?;

    Ok(Json(CreatedAuthKey {
        id,
        auth_key: key.raw,
        expires_at,
    }))
}

#[derive(Debug, Serialize, FromRow)]
pub struct AuthKeySummary {
    pub id: Uuid,
    pub key_prefix: Option<String>,
    pub reusable: bool,
    pub ephemeral: bool,
    pub require_approval: bool,
    pub used_count: i32,
    pub revoked: bool,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// List a tenant's auth keys (metadata only — never the secret).
pub async fn list_auth_keys(
    session: AdminSession,
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
) -> AppResult<Json<Vec<AuthKeySummary>>> {
    session.require_tenant(tenant_id)?;
    let rows = sqlx::query_as::<_, AuthKeySummary>(
        r#"SELECT id, key_prefix, reusable, ephemeral, require_approval,
                  used_count, revoked, expires_at, created_at
           FROM auth_keys WHERE tenant_id = $1 ORDER BY created_at DESC"#,
    )
    .bind(tenant_id)
    .fetch_all(state.db())
    .await?;
    Ok(Json(rows))
}

/// Revoke an auth key so it can no longer enroll new devices (admin+). Existing
/// devices already enrolled with it are unaffected.
pub async fn revoke_auth_key(
    session: AdminSession,
    State(state): State<AppState>,
    Path(key_id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    session.require_role(Role::Admin)?;
    let result = sqlx::query(
        "UPDATE auth_keys SET revoked = true WHERE id = $1 AND tenant_id = $2 AND NOT revoked",
    )
    .bind(key_id)
    .bind(session.tenant_id)
    .execute(state.db())
    .await?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    sqlx::query(
        "INSERT INTO audit_log (tenant_id, actor_id, action, target) VALUES ($1, $2, 'authkey.revoke', $3)",
    )
    .bind(session.tenant_id)
    .bind(session.user_id)
    .bind(key_id.to_string())
    .execute(state.db())
    .await?;

    Ok(Json(serde_json::json!({ "status": "revoked" })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_key_is_consistent() {
        let k = generate_key([0xab; 24]);
        assert!(k.raw.starts_with("ws-"));
        assert!(k.raw.starts_with(&k.prefix));
        assert_eq!(k.prefix.len(), 11); // "ws-" + 8 hex chars
        assert_eq!(k.hash, hash_auth_key(&k.raw));
        // The stored hash is never the raw secret.
        assert_ne!(k.hash, k.raw);
    }

    #[test]
    fn distinct_inputs_produce_distinct_keys() {
        let a = generate_key([1u8; 24]);
        let b = generate_key([2u8; 24]);
        assert_ne!(a.raw, b.raw);
        assert_ne!(a.hash, b.hash);
        assert_ne!(a.prefix, b.prefix);
    }
}
