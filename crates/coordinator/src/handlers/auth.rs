//! Dashboard authentication: credential login, current-user, and user creation.
//!
//! This is real local auth (Argon2 password hashing + signed JWT sessions).
//! OIDC/SSO can be added as an additional login path that mints the same
//! [`AdminClaims`](crate::auth::AdminClaims) after an external identity check.

use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::auth::{hash_password, issue_admin_token, verify_password, AdminSession, Role};
use crate::error::{AppError, AppResult};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub email: String,
    pub role: Role,
}

#[derive(sqlx::FromRow)]
struct UserAuthRow {
    id: Uuid,
    tenant_id: Uuid,
    role: String,
    password_hash: Option<String>,
}

/// Exchange email + password for a session token.
pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> AppResult<Json<LoginResponse>> {
    let user: Option<UserAuthRow> = sqlx::query_as(
        r#"SELECT id, tenant_id, role, password_hash
           FROM users
           WHERE email = $1 AND password_hash IS NOT NULL
           LIMIT 1"#,
    )
    .bind(&req.email)
    .fetch_optional(state.db())
    .await?;

    // Always run verification work shape-wise; reject uniformly on any failure.
    let user = user.ok_or(AppError::Unauthorized)?;
    let hash = user
        .password_hash
        .as_deref()
        .ok_or(AppError::Unauthorized)?;
    if !verify_password(&req.password, hash) {
        return Err(AppError::Unauthorized);
    }

    let role = Role::from_db(&user.role);
    let token = issue_admin_token(&state.settings().jwt_secret, user.id, user.tenant_id, role)
        .map_err(AppError::Other)?;

    Ok(Json(LoginResponse {
        token,
        user_id: user.id,
        tenant_id: user.tenant_id,
        email: req.email,
        role,
    }))
}

/// Return the authenticated user's profile.
pub async fn me(session: AdminSession) -> AppResult<Json<serde_json::Value>> {
    Ok(Json(json!({
        "user_id": session.user_id,
        "tenant_id": session.tenant_id,
        "role": session.role,
    })))
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub role: Option<Role>,
}

/// Create a user in the session's tenant (admin/owner only).
pub async fn create_user(
    session: AdminSession,
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
    Json(req): Json<CreateUserRequest>,
) -> AppResult<Json<serde_json::Value>> {
    session.require_tenant(tenant_id)?;
    session.require_role(Role::Admin)?;

    let role = match req.role.unwrap_or(Role::Member) {
        // Only an owner may mint another owner.
        Role::Owner if session.role != Role::Owner => return Err(AppError::Unauthorized),
        r => r,
    };
    let role_str = serde_json::to_value(role)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "member".to_string());

    let hash = hash_password(&req.password).map_err(AppError::Other)?;
    let id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO users (tenant_id, email, role, password_hash)
           VALUES ($1, $2, $3, $4) RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(&req.email)
    .bind(&role_str)
    .bind(&hash)
    .fetch_one(state.db())
    .await?;

    sqlx::query("INSERT INTO audit_log (tenant_id, actor_id, action, target) VALUES ($1, $2, 'user.create', $3)")
        .bind(tenant_id)
        .bind(session.user_id)
        .bind(id.to_string())
        .execute(state.db())
        .await?;

    Ok(Json(json!({ "id": id })))
}
