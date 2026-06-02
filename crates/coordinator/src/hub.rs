//! In-process registry of connected agents and live network-map fanout.
//!
//! Phase 2: single-instance fanout. When a device's endpoints change we rebuild
//! and push a fresh map to every *connected* agent in the same tenant. Phase 2.5
//! adds Redis pub/sub so this fans out across coordinator instances too.

use std::collections::HashMap;
use std::sync::Mutex;

use tokio::sync::mpsc;
use uuid::Uuid;
use ws_proto::ServerMessage;

/// Sender side of a connected agent's outbound message queue.
type Tx = mpsc::UnboundedSender<ServerMessage>;

#[derive(Default)]
pub struct Hub {
    // tenant_id -> (device_id -> outbound sender)
    inner: Mutex<HashMap<Uuid, HashMap<Uuid, Tx>>>,
}

impl Hub {
    /// Register a connected agent; returns the receiver its socket writer drains.
    pub fn register(&self, tenant: Uuid, device: Uuid) -> mpsc::UnboundedReceiver<ServerMessage> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.inner
            .lock()
            .unwrap()
            .entry(tenant)
            .or_default()
            .insert(device, tx);
        rx
    }

    /// Remove a disconnected agent.
    pub fn unregister(&self, tenant: Uuid, device: Uuid) {
        let mut guard = self.inner.lock().unwrap();
        if let Some(devices) = guard.get_mut(&tenant) {
            devices.remove(&device);
            if devices.is_empty() {
                guard.remove(&tenant);
            }
        }
    }

    /// Device ids currently connected for a tenant.
    pub fn connected_devices(&self, tenant: Uuid) -> Vec<Uuid> {
        self.inner
            .lock()
            .unwrap()
            .get(&tenant)
            .map(|d| d.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Push a message to one connected device (no-op if not connected).
    pub fn send_to(&self, tenant: Uuid, device: Uuid, msg: ServerMessage) {
        if let Some(devices) = self.inner.lock().unwrap().get(&tenant) {
            if let Some(tx) = devices.get(&device) {
                let _ = tx.send(msg);
            }
        }
    }
}
