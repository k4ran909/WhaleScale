//! Dev-only bootstrap helpers. Replaced by the real admin API + SSO in Phase 5.
//! **Do not expose in production** (no auth).

use axum::extract::State;
use axum::Json;
use rand::Rng;
use serde_json::json;

use crate::auth::{hash_auth_key, hash_password};
use crate::error::{AppError, AppResult};
use crate::state::AppState;

/// Create (or reuse) a dev tenant, an owner login, and a reusable auth key.
/// Returns the credentials once — log in with the email/password and feed the
/// auth key to an agent's enrollment.
pub async fn bootstrap(State(state): State<AppState>) -> AppResult<Json<serde_json::Value>> {
    let pool = state.db();

    let tenant_id: uuid::Uuid = sqlx::query_scalar(
        r#"INSERT INTO tenants (name, slug, dns_suffix)
           VALUES ('Dev Org', 'dev', 'dev.whale.net')
           ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name
           RETURNING id"#,
    )
    .fetch_one(pool)
    .await?;

    // Owner login (idempotent): owner@dev / whalescale.
    let owner_email = "owner@dev";
    let owner_password = "whalescale";
    let pw_hash = hash_password(owner_password).map_err(AppError::Other)?;
    sqlx::query(
        r#"INSERT INTO users (tenant_id, email, role, password_hash)
           VALUES ($1, $2, 'owner', $3)
           ON CONFLICT (tenant_id, email)
           DO UPDATE SET password_hash = EXCLUDED.password_hash, role = 'owner'"#,
    )
    .bind(tenant_id)
    .bind(owner_email)
    .bind(&pw_hash)
    .execute(pool)
    .await?;

    // Generate a random raw key; store only its hash.
    let raw_key: String = {
        let bytes: [u8; 24] = rand::thread_rng().gen();
        format!("ws-{}", hex::encode(bytes))
    };
    let key_hash = hash_auth_key(&raw_key);

    sqlx::query(
        r#"INSERT INTO auth_keys (tenant_id, key_hash, reusable)
           VALUES ($1, $2, true)"#,
    )
    .bind(tenant_id)
    .bind(&key_hash)
    .execute(pool)
    .await
    .map_err(AppError::Database)?;

    Ok(Json(json!({
        "tenant_id": tenant_id,
        "auth_key": raw_key,
        "login": { "email": owner_email, "password": owner_password },
        "note": "dev-only; log in with the email/password, feed auth_key to an agent"
    })))
}
