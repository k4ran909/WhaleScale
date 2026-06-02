//! Team / user management for the dashboard: list members, change roles, and
//! remove users. Creation lives in [`auth::create_user`](super::auth::create_user);
//! this module covers the rest of the lifecycle.
//!
//! Every operation is tenant-scoped and role-gated. The authorization decisions
//! are pure functions ([`can_change_role`], [`can_delete_user`]) so the RBAC
//! rules can be unit-tested without a database, and the last owner of an org can
//! never be demoted or removed (which would lock everyone out).

use axum::extract::{Path, State};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::auth::{AdminSession, Role};
use crate::error::{AppError, AppResult};
use crate::state::AppState;

#[derive(Debug, Serialize, FromRow)]
pub struct UserSummary {
    pub id: Uuid,
    pub email: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

/// List the members of a tenant (any signed-in member of that tenant).
pub async fn list_users(
    session: AdminSession,
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
) -> AppResult<Json<Vec<UserSummary>>> {
    session.require_tenant(tenant_id)?;
    let rows = sqlx::query_as::<_, UserSummary>(
        r#"SELECT id, email, role, created_at
           FROM users WHERE tenant_id = $1 ORDER BY created_at"#,
    )
    .bind(tenant_id)
    .fetch_all(state.db())
    .await?;
    Ok(Json(rows))
}

/// Whether `actor` may change a user from role `current` to `new`. Pure/testable.
/// Admin+ is required; only an Owner may modify an existing Owner or grant Owner.
pub fn can_change_role(actor: Role, current: Role, new: Role) -> bool {
    if !actor.at_least(Role::Admin) {
        return false;
    }
    // Modifying an existing owner requires owner.
    if current == Role::Owner && actor != Role::Owner {
        return false;
    }
    // Granting the owner role requires owner.
    if new == Role::Owner && actor != Role::Owner {
        return false;
    }
    true
}

/// Whether `actor` may delete a user holding `target` role. Pure/testable.
/// Admin+ is required; only an Owner may remove another Owner.
pub fn can_delete_user(actor: Role, target: Role) -> bool {
    actor.at_least(Role::Admin) && (target != Role::Owner || actor == Role::Owner)
}

#[derive(Debug, Deserialize)]
pub struct UpdateRoleRequest {
    pub role: Role,
}

/// Change a user's role (tenant-scoped, role-gated, last-owner-protected).
pub async fn update_role(
    session: AdminSession,
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
    Json(req): Json<UpdateRoleRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let current = fetch_user_role(&state, session.tenant_id, user_id).await?;
    if !can_change_role(session.role, current, req.role) {
        return Err(AppError::Unauthorized);
    }
    // Never demote the last remaining owner.
    if current == Role::Owner && req.role != Role::Owner {
        ensure_not_last_owner(&state, session.tenant_id).await?;
    }

    let new_str = role_str(req.role);
    let updated = sqlx::query("UPDATE users SET role = $1 WHERE id = $2 AND tenant_id = $3")
        .bind(&new_str)
        .bind(user_id)
        .bind(session.tenant_id)
        .execute(state.db())
        .await?;
    if updated.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    audit(&state, session.tenant_id, session.user_id, "user.role", user_id).await?;
    Ok(Json(serde_json::json!({ "status": "ok", "role": new_str })))
}

/// Remove a user from the tenant (tenant-scoped, role-gated, last-owner-protected).
pub async fn delete_user(
    session: AdminSession,
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> AppResult<axum::http::StatusCode> {
    let current = fetch_user_role(&state, session.tenant_id, user_id).await?;
    if !can_delete_user(session.role, current) {
        return Err(AppError::Unauthorized);
    }
    if current == Role::Owner {
        ensure_not_last_owner(&state, session.tenant_id).await?;
    }
    let deleted = sqlx::query("DELETE FROM users WHERE id = $1 AND tenant_id = $2")
        .bind(user_id)
        .bind(session.tenant_id)
        .execute(state.db())
        .await?;
    if deleted.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    audit(&state, session.tenant_id, session.user_id, "user.delete", user_id).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

async fn fetch_user_role(state: &AppState, tenant_id: Uuid, user_id: Uuid) -> AppResult<Role> {
    let role: Option<String> =
        sqlx::query_scalar("SELECT role FROM users WHERE id = $1 AND tenant_id = $2")
            .bind(user_id)
            .bind(tenant_id)
            .fetch_optional(state.db())
            .await?;
    role.map(|r| Role::from_db(&r)).ok_or(AppError::NotFound)
}

async fn ensure_not_last_owner(state: &AppState, tenant_id: Uuid) -> AppResult<()> {
    let owners: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND role = 'owner'")
            .bind(tenant_id)
            .fetch_one(state.db())
            .await?;
    if owners <= 1 {
        return Err(AppError::BadRequest(
            "cannot remove the last owner of the organization".into(),
        ));
    }
    Ok(())
}

fn role_str(role: Role) -> String {
    match role {
        Role::Owner => "owner",
        Role::Admin => "admin",
        Role::Member => "member",
    }
    .to_string()
}

async fn audit(
    state: &AppState,
    tenant_id: Uuid,
    actor_id: Uuid,
    action: &str,
    target: Uuid,
) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO audit_log (tenant_id, actor_id, action, target) VALUES ($1, $2, $3, $4)",
    )
    .bind(tenant_id)
    .bind(actor_id)
    .bind(action)
    .bind(target.to_string())
    .execute(state.db())
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_owner_touches_an_owner() {
        assert!(can_change_role(Role::Owner, Role::Owner, Role::Admin));
        assert!(!can_change_role(Role::Admin, Role::Owner, Role::Admin));
    }

    #[test]
    fn only_owner_grants_owner() {
        assert!(can_change_role(Role::Owner, Role::Member, Role::Owner));
        assert!(!can_change_role(Role::Admin, Role::Member, Role::Owner));
    }

    #[test]
    fn admin_manages_members_and_admins() {
        assert!(can_change_role(Role::Admin, Role::Member, Role::Admin));
        assert!(can_change_role(Role::Admin, Role::Admin, Role::Member));
    }

    #[test]
    fn members_cannot_manage() {
        assert!(!can_change_role(Role::Member, Role::Member, Role::Admin));
        assert!(!can_delete_user(Role::Member, Role::Member));
    }

    #[test]
    fn delete_rules() {
        assert!(can_delete_user(Role::Owner, Role::Owner));
        assert!(can_delete_user(Role::Admin, Role::Member));
        assert!(!can_delete_user(Role::Admin, Role::Owner));
    }
}
