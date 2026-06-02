//! Shared application state passed to every handler.

use std::sync::Arc;

use sqlx::PgPool;

use crate::config::Settings;
use crate::hub::Hub;
use crate::stats::{LatencyStore, ThroughputStore};

#[derive(Clone)]
pub struct AppState {
    pub inner: Arc<Inner>,
}

pub struct Inner {
    pub db: PgPool,
    pub settings: Settings,
    pub hub: Hub,
    pub latency: LatencyStore,
    pub throughput: ThroughputStore,
}

impl AppState {
    pub fn new(db: PgPool, settings: Settings) -> Self {
        Self {
            inner: Arc::new(Inner {
                db,
                settings,
                hub: Hub::default(),
                latency: LatencyStore::default(),
                throughput: ThroughputStore::default(),
            }),
        }
    }

    pub fn db(&self) -> &PgPool {
        &self.inner.db
    }

    pub fn settings(&self) -> &Settings {
        &self.inner.settings
    }

    pub fn hub(&self) -> &Hub {
        &self.inner.hub
    }

    pub fn latency(&self) -> &LatencyStore {
        &self.inner.latency
    }

    pub fn throughput(&self) -> &ThroughputStore {
        &self.inner.throughput
    }
}
