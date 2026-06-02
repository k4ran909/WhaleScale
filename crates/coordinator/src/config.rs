//! Coordinator runtime configuration, loaded from environment variables.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Settings {
    /// Address the HTTP/WebSocket server binds to, e.g. "0.0.0.0:8080".
    #[serde(default = "default_bind")]
    pub bind_addr: String,

    /// Postgres connection string.
    pub database_url: String,

    /// Redis connection string (reserved for cross-instance network-map fanout,
    /// Phase 2.5 — not yet consumed).
    #[serde(default = "default_redis")]
    #[allow(dead_code)]
    pub redis_url: String,

    /// Secret used to sign agent/session JWTs.
    pub jwt_secret: String,

    /// Optional relay endpoint advertised to agents, as `host:port`.
    /// When unset, no relay fallback is offered (Phase 2 behavior).
    pub relay_addr: Option<String>,

    #[serde(default = "default_relay_id")]
    pub relay_region_id: String,

    #[serde(default = "default_relay_name")]
    pub relay_region_name: String,

    /// Device WireGuard key lifetime in days. Unset = keys never expire.
    pub device_key_ttl_days: Option<i64>,
}

fn default_relay_id() -> String {
    "default".to_string()
}

fn default_relay_name() -> String {
    "Default Relay".to_string()
}

fn default_bind() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_redis() -> String {
    "redis://127.0.0.1:6379".to_string()
}

impl Settings {
    /// Load configuration from process environment (and a local `.env` if present).
    pub fn from_env() -> anyhow::Result<Self> {
        // Load .env if present; ignore if missing.
        let _ = dotenvy::dotenv();

        let settings = config::Config::builder()
            .add_source(config::Environment::default())
            .build()?
            .try_deserialize::<Settings>()?;

        Ok(settings)
    }

    /// Compute a device key expiry from the configured TTL (None = never).
    pub fn key_expiry(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.device_key_ttl_days
            .map(|days| chrono::Utc::now() + chrono::Duration::days(days))
    }

    /// Relay regions advertised in network maps (currently zero or one).
    pub fn relay_regions(&self) -> Vec<ws_proto::RelayRegion> {
        match self.relay_addr.as_ref().and_then(|a| a.parse().ok()) {
            Some(addr) => vec![ws_proto::RelayRegion {
                id: self.relay_region_id.clone(),
                name: self.relay_region_name.clone(),
                addr,
            }],
            None => Vec::new(),
        }
    }
}
