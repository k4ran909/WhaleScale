//! Database row models (sqlx `FromRow`).

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow)]
pub struct AuthKey {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub reusable: bool,
    pub used_count: i32,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked: bool,
    pub require_approval: bool,
}

#[derive(Debug, Clone, FromRow)]
pub struct Tenant {
    pub dns_suffix: Option<String>,
}
