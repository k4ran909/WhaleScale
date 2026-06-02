//! Shared node-agent logic used by every platform client (Phase 1+).
//!
//! Responsibilities (built out across phases):
//!  - generate the WireGuard keypair and enroll with the coordinator       (Phase 1)
//!  - fetch and apply the network map, rendering a WireGuard config         (Phase 1)
//!  - run STUN endpoint discovery and attempt hole punching                 (Phase 2)
//!  - select a relay fallback                                               (Phase 3)
//!
//! Platform crates (`agent-cli`, iOS, Android) supply a [`TunnelBackend`]
//! that applies the rendered configuration to a real WireGuard interface.

pub mod backend;
pub mod client;
pub mod conn;
pub mod discovery;
pub mod filter;
pub mod keys;
pub mod magicdns;
pub mod relay_client;
pub mod wgconfig;
pub mod wireguard;

use anyhow::Context;
use ws_proto::{EnrollRequest, NetworkMap};

pub use backend::{LogBackend, TunnelBackend, WgQuickBackend};
pub use client::CoordinatorClient;
pub use keys::WgKeypair;

/// Local persistent identity for an enrolled agent.
#[derive(Debug, Clone)]
pub struct AgentIdentity {
    pub device_id: uuid::Uuid,
    pub session_token: String,
    pub keypair: WgKeypair,
    pub key_expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// The agent runtime: holds identity, talks to the coordinator, applies maps.
pub struct Agent<B: TunnelBackend> {
    client: CoordinatorClient,
    backend: B,
    identity: Option<AgentIdentity>,
    listen_port: u16,
    current_map_version: u64,
    last_map: Option<NetworkMap>,
    advertised_routes: Vec<String>,
    inbound_filter: filter::CompiledFilter,
}

impl<B: TunnelBackend> Agent<B> {
    pub fn new(coordinator_url: impl Into<String>, backend: B) -> Self {
        Self {
            client: CoordinatorClient::new(coordinator_url),
            backend,
            identity: None,
            listen_port: 51820,
            current_map_version: 0,
            last_map: None,
            advertised_routes: Vec::new(),
            inbound_filter: filter::CompiledFilter::default(),
        }
    }

    /// Advertise subnet routes (or `0.0.0.0/0` for an exit node). Call before
    /// [`enroll`](Self::enroll).
    pub fn advertise_routes(&mut self, routes: Vec<String>) -> &mut Self {
        self.advertised_routes = routes;
        self
    }

    /// The most recently applied network map (for MagicDNS, status, etc.).
    pub fn current_map(&self) -> Option<&NetworkMap> {
        self.last_map.as_ref()
    }

    /// Whether an inbound (already-decrypted) IPv4 packet is permitted by the
    /// current ACL packet filter. The platform TUN loop calls this before
    /// writing a decrypted packet to the tunnel device. Unparseable packets and
    /// an empty/absent filter are allowed (fail-open is the no-policy default).
    pub fn inbound_allowed(&self, packet: &[u8]) -> bool {
        match filter::parse_ipv4(packet) {
            Some(meta) => self.inbound_filter.allows(&meta),
            None => true,
        }
    }

    /// Generate a keypair and enroll with the coordinator using `auth_key`.
    pub async fn enroll(
        &mut self,
        auth_key: &str,
        hostname: &str,
        os: &str,
    ) -> anyhow::Result<&AgentIdentity> {
        let keypair = WgKeypair::generate();
        let resp = self
            .client
            .enroll(&EnrollRequest {
                auth_key: auth_key.to_string(),
                public_key: keypair.public_key.clone(),
                hostname: hostname.to_string(),
                os: os.to_string(),
                advertised_routes: self.advertised_routes.clone(),
            })
            .await
            .context("enrollment failed")?;

        tracing::info!(device_id = %resp.device_id, overlay_ip = %resp.overlay_ip, "enrolled");
        self.identity = Some(AgentIdentity {
            device_id: resp.device_id,
            session_token: resp.session_token,
            keypair,
            key_expires_at: resp.key_expires_at,
        });
        Ok(self.identity.as_ref().expect("just set"))
    }

    /// Rotate the WireGuard key if it expires within `window`. Generates a new
    /// keypair, registers it, and forces the next [`sync`](Self::sync) to
    /// reconfigure the interface with it. Returns true if a rotation happened.
    pub async fn maybe_rotate(&mut self, window: chrono::Duration) -> anyhow::Result<bool> {
        let (token, expires_at) = {
            let id = self.identity.as_ref().context("agent is not enrolled")?;
            (id.session_token.clone(), id.key_expires_at)
        };
        if !ws_proto::expiry::expires_within(expires_at, chrono::Utc::now(), window) {
            return Ok(false);
        }

        tracing::info!("WireGuard key expiring soon; rotating");
        let new_keypair = WgKeypair::generate();
        let resp = self
            .client
            .rotate(
                &token,
                &ws_proto::RotateRequest {
                    new_public_key: new_keypair.public_key.clone(),
                },
            )
            .await
            .context("key rotation failed")?;

        if let Some(id) = self.identity.as_mut() {
            id.keypair = new_keypair;
            id.key_expires_at = resp.key_expires_at;
        }
        // Force the next sync to re-render the config with the new key.
        self.current_map_version = 0;
        Ok(true)
    }

    /// Run STUN/local endpoint discovery and report the result to the
    /// coordinator so peers can attempt direct connections (hole punching).
    pub async fn discover_and_report(
        &self,
        stun_server: std::net::SocketAddr,
    ) -> anyhow::Result<Vec<ws_proto::Endpoint>> {
        let identity = self.identity.as_ref().context("agent is not enrolled")?;
        let discovery = discovery::discover_endpoints(stun_server, self.listen_port).await?;
        self.client
            .report_endpoints(
                &identity.session_token,
                &ws_proto::EndpointUpdate {
                    device_id: identity.device_id,
                    endpoints: discovery.endpoints.clone(),
                },
            )
            .await?;

        // Report the measured STUN round-trip time for the latency dashboard.
        if let Some(rtt_ms) = discovery.stun_rtt_ms {
            if let Err(e) = self
                .client
                .report_stats(
                    &identity.session_token,
                    &ws_proto::stats::LatencySample { rtt_ms },
                )
                .await
            {
                tracing::warn!(error = %e, "failed to report latency");
            }
        }

        tracing::info!(count = discovery.endpoints.len(), rtt_ms = ?discovery.stun_rtt_ms, "reported endpoints");
        Ok(discovery.endpoints)
    }

    /// Report interface throughput counters (if the backend exposes them) so
    /// the coordinator can chart per-device rates.
    pub async fn report_throughput(&mut self) -> anyhow::Result<()> {
        let token = match self.identity.as_ref() {
            Some(id) => id.session_token.clone(),
            None => return Ok(()),
        };
        let Some((rx_bytes, tx_bytes)) = self.backend.transfer() else {
            return Ok(());
        };
        self.client
            .report_throughput(
                &token,
                &ws_proto::stats::ThroughputSample { tx_bytes, rx_bytes },
            )
            .await
    }

    /// Fetch the latest map and, if newer, render + apply the WireGuard config.
    pub async fn sync(&mut self) -> anyhow::Result<bool> {
        let identity = self.identity.as_ref().context("agent is not enrolled")?;

        let map = self.client.netmap(&identity.session_token).await?;
        self.apply_map(&map)
    }

    /// Apply a network map if it is newer than what we already hold.
    pub fn apply_map(&mut self, map: &NetworkMap) -> anyhow::Result<bool> {
        if map.version <= self.current_map_version {
            return Ok(false);
        }
        let identity = self.identity.as_ref().context("agent is not enrolled")?;
        let quick = wgconfig::render_quick(map, &identity.keypair.private_key, self.listen_port);
        let sync = wgconfig::render_setconf(map, &identity.keypair.private_key, self.listen_port);
        self.backend.apply(&quick, &sync)?;
        self.current_map_version = map.version;
        self.inbound_filter = filter::CompiledFilter::compile(&map.packet_filter);
        self.last_map = Some(map.clone());
        tracing::info!(
            version = map.version,
            peers = map.peers.len(),
            "applied network map"
        );
        Ok(true)
    }

    pub fn map_version(&self) -> u64 {
        self.current_map_version
    }
}
