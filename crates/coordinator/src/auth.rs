//! JWT session tokens for agents and an axum extractor that validates them.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::AppError;
use crate::state::AppState;

/// Claims embedded in an agent's session JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Device id (subject).
    pub sub: Uuid,
    /// Tenant the device belongs to.
    pub tenant: Uuid,
    /// Expiry (unix seconds).
    pub exp: i64,
}

/// Issue a signed session token for a freshly enrolled device.
pub fn issue_token(secret: &str, device_id: Uuid, tenant_id: Uuid) -> anyhow::Result<String> {
    let claims = Claims {
        sub: device_id,
        tenant: tenant_id,
        // Long-lived; rotation/expiry policy is a Phase 5 concern.
        exp: (Utc::now() + Duration::days(365)).timestamp(),
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?;
    Ok(token)
}

fn decode_token(secret: &str, token: &str) -> Result<Claims, AppError> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .map_err(|_| AppError::Unauthorized)
}

/// Verify a raw bearer token (used by the WebSocket upgrade, which carries the
/// token as a query parameter rather than an `Authorization` header).
pub fn verify_token(secret: &str, token: &str) -> Result<Claims, AppError> {
    decode_token(secret, token)
}

/// Hash a raw auth key for storage/comparison (we never store the raw key).
pub fn hash_auth_key(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    hex::encode(hasher.finalize())
}

/// Authenticated agent identity, extracted from the `Authorization: Bearer` header.
#[derive(Debug, Clone)]
pub struct AgentSession {
    pub device_id: Uuid,
    pub tenant_id: Uuid,
}

#[axum::async_trait]
impl FromRequestParts<AppState> for AgentSession {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token(parts).ok_or(AppError::Unauthorized)?;
        let claims = decode_token(&state.settings().jwt_secret, token)?;
        Ok(AgentSession {
            device_id: claims.sub,
            tenant_id: claims.tenant,
        })
    }
}

fn bearer_token(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

// ---------------------------------------------------------------------------
// Admin / dashboard authentication (RBAC)
// ---------------------------------------------------------------------------

/// Role-based access levels for dashboard users.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Owner,
    Admin,
    Member,
}

impl Role {
    fn rank(self) -> u8 {
        match self {
            Role::Owner => 3,
            Role::Admin => 2,
            Role::Member => 1,
        }
    }

    /// True if `self` has at least the privileges of `other`.
    pub fn at_least(self, other: Role) -> bool {
        self.rank() >= other.rank()
    }

    pub fn from_db(s: &str) -> Role {
        match s {
            "owner" => Role::Owner,
            "admin" => Role::Admin,
            _ => Role::Member,
        }
    }
}

/// Claims in a dashboard user's session JWT. `kind` distinguishes these from
/// agent tokens so the two can't be swapped.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminClaims {
    pub sub: Uuid,
    pub tenant: Uuid,
    pub role: Role,
    pub kind: String,
    pub exp: i64,
}

pub fn issue_admin_token(
    secret: &str,
    user_id: Uuid,
    tenant_id: Uuid,
    role: Role,
) -> anyhow::Result<String> {
    let claims = AdminClaims {
        sub: user_id,
        tenant: tenant_id,
        role,
        kind: "admin".to_string(),
        exp: (Utc::now() + Duration::hours(12)).timestamp(),
    };
    Ok(encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?)
}

/// Authenticated dashboard user.
#[derive(Debug, Clone)]
pub struct AdminSession {
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub role: Role,
}

impl AdminSession {
    /// Ensure the session is scoped to `tenant_id` (tenant isolation).
    pub fn require_tenant(&self, tenant_id: Uuid) -> Result<(), AppError> {
        if self.tenant_id == tenant_id {
            Ok(())
        } else {
            Err(AppError::Unauthorized)
        }
    }

    /// Ensure the user holds at least `role`.
    pub fn require_role(&self, role: Role) -> Result<(), AppError> {
        if self.role.at_least(role) {
            Ok(())
        } else {
            Err(AppError::Unauthorized)
        }
    }
}

#[axum::async_trait]
impl FromRequestParts<AppState> for AdminSession {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token(parts).ok_or(AppError::Unauthorized)?;
        let claims = decode::<AdminClaims>(
            token,
            &DecodingKey::from_secret(state.settings().jwt_secret.as_bytes()),
            &Validation::default(),
        )
        .map(|d| d.claims)
        .map_err(|_| AppError::Unauthorized)?;

        if claims.kind != "admin" {
            return Err(AppError::Unauthorized);
        }
        Ok(AdminSession {
            user_id: claims.sub,
            tenant_id: claims.tenant,
            role: claims.role,
        })
    }
}

/// Hash a password with Argon2id (random salt embedded in the output string).
pub fn hash_password(password: &str) -> anyhow::Result<String> {
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    use argon2::Argon2;
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("password hash failed: {e}"))
}

/// Verify a password against a stored Argon2 hash.
pub fn verify_password(password: &str, hash: &str) -> bool {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    use argon2::Argon2;
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_roundtrip() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &hash));
        assert!(!verify_password("wrong password", &hash));
    }

    #[test]
    fn role_ordering() {
        assert!(Role::Owner.at_least(Role::Admin));
        assert!(Role::Admin.at_least(Role::Member));
        assert!(!Role::Member.at_least(Role::Admin));
    }

    #[test]
    fn admin_token_roundtrip() {
        let uid = Uuid::new_v4();
        let tid = Uuid::new_v4();
        let token = issue_admin_token("secret", uid, tid, Role::Admin).unwrap();
        let claims = decode::<AdminClaims>(
            &token,
            &DecodingKey::from_secret(b"secret"),
            &Validation::default(),
        )
        .unwrap()
        .claims;
        assert_eq!(claims.sub, uid);
        assert_eq!(claims.role, Role::Admin);
        assert_eq!(claims.kind, "admin");
    }
}
