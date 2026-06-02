//! In-memory latency + throughput stats per device (ephemeral; not persisted).

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use uuid::Uuid;
use ws_proto::stats::{bytes_per_sec, LatencyWindow};

const WINDOW: usize = 60; // keep the last ~60 samples per device

#[derive(Default)]
pub struct LatencyStore {
    // device_id -> (tenant_id, rolling window)
    inner: Mutex<HashMap<Uuid, (Uuid, LatencyWindow)>>,
}

/// A device's current latency aggregates, returned to the dashboard.
pub struct LatencySnapshot {
    pub device_id: Uuid,
    pub last: Option<u32>,
    pub avg: Option<f64>,
    pub p95: Option<u32>,
    pub samples: Vec<u32>,
}

impl LatencyStore {
    /// Record a sample for a device.
    pub fn push(&self, tenant_id: Uuid, device_id: Uuid, rtt_ms: u32) {
        let mut guard = self.inner.lock().unwrap();
        let entry = guard
            .entry(device_id)
            .or_insert_with(|| (tenant_id, LatencyWindow::new(WINDOW)));
        entry.0 = tenant_id;
        entry.1.push(rtt_ms);
    }

    /// Snapshot all devices in a tenant.
    pub fn snapshot(&self, tenant_id: Uuid) -> Vec<LatencySnapshot> {
        let guard = self.inner.lock().unwrap();
        guard
            .iter()
            .filter(|(_, (t, _))| *t == tenant_id)
            .map(|(device_id, (_, w))| LatencySnapshot {
                device_id: *device_id,
                last: w.last(),
                avg: w.avg(),
                p95: w.p95(),
                samples: w.samples(),
            })
            .collect()
    }
}

/// Computed throughput rate for a device.
pub struct ThroughputSnapshot {
    pub device_id: Uuid,
    pub tx_bps: f64,
    pub rx_bps: f64,
}

/// Last cumulative counters + the rate derived from the previous reading.
struct ThroughputEntry {
    tenant_id: Uuid,
    last: Option<(u64, u64, DateTime<Utc>)>, // (tx, rx, when)
    tx_bps: f64,
    rx_bps: f64,
}

#[derive(Default)]
pub struct ThroughputStore {
    inner: Mutex<HashMap<Uuid, ThroughputEntry>>,
}

impl ThroughputStore {
    /// Record cumulative `(tx, rx)` counters, deriving the rate vs. the previous
    /// reading.
    pub fn push(&self, tenant_id: Uuid, device_id: Uuid, tx: u64, rx: u64, now: DateTime<Utc>) {
        let mut guard = self.inner.lock().unwrap();
        let entry = guard.entry(device_id).or_insert_with(|| ThroughputEntry {
            tenant_id,
            last: None,
            tx_bps: 0.0,
            rx_bps: 0.0,
        });
        entry.tenant_id = tenant_id;
        if let Some((ptx, prx, pwhen)) = entry.last {
            let secs = (now - pwhen).num_milliseconds() as f64 / 1000.0;
            entry.tx_bps = bytes_per_sec(ptx, tx, secs);
            entry.rx_bps = bytes_per_sec(prx, rx, secs);
        }
        entry.last = Some((tx, rx, now));
    }

    pub fn snapshot(&self, tenant_id: Uuid) -> Vec<ThroughputSnapshot> {
        let guard = self.inner.lock().unwrap();
        guard
            .iter()
            .filter(|(_, e)| e.tenant_id == tenant_id)
            .map(|(device_id, e)| ThroughputSnapshot {
                device_id: *device_id,
                tx_bps: e.tx_bps,
                rx_bps: e.rx_bps,
            })
            .collect()
    }
}
