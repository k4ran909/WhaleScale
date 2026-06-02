//! WhaleScale desktop/server agent CLI (Linux/Windows/macOS).
//!
//! Generates a keypair, enrolls, discovers endpoints via STUN, fetches the
//! network map, and applies a WireGuard configuration — then keeps syncing on
//! an interval (a long-running daemon).
//!
//! Env:
//!   COORDINATOR_URL   default http://localhost:8080
//!   WS_AUTH_KEY       required (from POST /dev/bootstrap)
//!   STUN_SERVER       host:port to discover endpoints (optional)
//!   WS_BACKEND        "wgquick" for a real interface, else "log" (default)
//!   WS_IFACE          interface name for wgquick backend (default whale0)
//!   WS_SYNC_INTERVAL  seconds between syncs (default 15)
//!   WS_DNS_BIND       addr to serve MagicDNS on, e.g. 127.0.0.1:5353 (optional)

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;
use ws_agent_core::magicdns::{self, Resolver};
use ws_agent_core::{Agent, LogBackend, TunnelBackend, WgQuickBackend};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let coordinator_url =
        std::env::var("COORDINATOR_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());
    let auth_key = std::env::var("WS_AUTH_KEY")
        .map_err(|_| anyhow::anyhow!("set WS_AUTH_KEY (get one from POST /dev/bootstrap)"))?;
    let hostname = std::env::var("WS_HOSTNAME")
        .ok()
        .or_else(hostname_from_os)
        .unwrap_or_else(|| "whalescale-node".to_string());
    let stun_server = std::env::var("STUN_SERVER").ok();
    let interval = std::env::var("WS_SYNC_INTERVAL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(15u64);

    let backend = select_backend();
    let mut agent = Agent::new(coordinator_url, backend);

    // Subnet routes / exit node, e.g. WS_ADVERTISE_ROUTES=192.168.1.0/24
    // or WS_ADVERTISE_ROUTES=0.0.0.0/0 to be an exit node.
    if let Ok(routes) = std::env::var("WS_ADVERTISE_ROUTES") {
        let routes: Vec<String> = routes
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !routes.is_empty() {
            tracing::info!(?routes, "advertising routes");
            agent.advertise_routes(routes);
        }
    }

    agent
        .enroll(&auth_key, &hostname, std::env::consts::OS)
        .await?;

    // Optional MagicDNS server; the resolver is refreshed after each sync.
    let dns_resolver = Arc::new(Mutex::new(Resolver::default()));
    if let Ok(dns_bind) = std::env::var("WS_DNS_BIND") {
        match UdpSocket::bind(&dns_bind).await {
            Ok(sock) => {
                tracing::info!(%dns_bind, "MagicDNS serving");
                tokio::spawn(magicdns::serve(sock, dns_resolver.clone()));
            }
            Err(e) => tracing::warn!(error = %e, "failed to bind MagicDNS socket"),
        }
    }

    // Daemon loop: discover endpoints, sync the map, sleep, repeat.
    let mut tick = tokio::time::interval(Duration::from_secs(interval));
    loop {
        tick.tick().await;

        // Rotate the WireGuard key if it expires within a day.
        if let Err(e) = agent.maybe_rotate(chrono::Duration::days(1)).await {
            tracing::warn!(error = %e, "key rotation check failed");
        }

        if let Some(stun) = &stun_server {
            match stun.parse() {
                Ok(addr) => {
                    if let Err(e) = agent.discover_and_report(addr).await {
                        tracing::warn!(error = %e, "endpoint discovery failed");
                    }
                }
                Err(e) => tracing::warn!(error = %e, "invalid STUN_SERVER address"),
            }
        }

        match agent.sync().await {
            Ok(applied) => {
                if applied {
                    tracing::info!(version = agent.map_version(), "applied updated network map");
                    // Refresh MagicDNS records from the new map.
                    if let Some(map) = agent.current_map() {
                        *dns_resolver.lock().unwrap() = Resolver::from_netmap(map);
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, "sync failed; will retry"),
        }

        // Report interface throughput (no-op unless the backend exposes counters).
        if let Err(e) = agent.report_throughput().await {
            tracing::warn!(error = %e, "throughput report failed");
        }
    }
}

fn select_backend() -> Box<dyn TunnelBackend> {
    match std::env::var("WS_BACKEND").as_deref() {
        Ok("wgquick") => {
            let iface = std::env::var("WS_IFACE").unwrap_or_else(|_| "whale0".to_string());
            tracing::info!(%iface, "using wg-quick backend");
            Box::new(WgQuickBackend::new(iface))
        }
        _ => {
            tracing::info!("using log backend (set WS_BACKEND=wgquick for a real interface)");
            Box::new(LogBackend)
        }
    }
}

fn hostname_from_os() -> Option<String> {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
}
