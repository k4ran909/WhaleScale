//! Builds the per-node [`NetworkMap`] from the database.
//!
//! Peers are filtered by the tenant's ACL policy (Phase 5): a peer is visible to
//! a node only if a rule permits traffic in either direction. When no policy is
//! configured the default is allow-all (preserving pre-ACL behavior).

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use sqlx::types::ipnetwork::IpNetwork;
use sqlx::types::Json as SqlxJson;
use sqlx::FromRow;
use uuid::Uuid;
use ws_proto::{Endpoint, NetworkMap, PeerNode, RelayRegion, SelfNode};

use crate::acl::{Policy, Principal};
use crate::error::{AppError, AppResult};
use crate::models::Tenant;

/// Convert a stored `IpNetwork` (a host address) into a proto `IpNet`.
pub fn host_net(net: IpNetwork) -> IpNet {
    let ip = net.ip();
    let prefix = match ip {
        std::net::IpAddr::V4(_) => 32,
        std::net::IpAddr::V6(_) => 128,
    };
    IpNet::new(ip, prefix).expect("valid host prefix")
}

#[derive(FromRow)]
struct NetRow {
    id: Uuid,
    hostname: String,
    public_key: String,
    overlay_ip: IpNetwork,
    endpoints: SqlxJson<Vec<Endpoint>>,
    relay_region: Option<String>,
    last_seen: Option<DateTime<Utc>>,
    tags: Vec<String>,
    owner_email: Option<String>,
    advertised_routes: Vec<String>,
    key_expires_at: Option<DateTime<Utc>>,
}

/// A peer's AllowedIPs = its own overlay address plus any subnets it routes
/// (subnet router / exit node). Invalid CIDRs are skipped.
pub fn merge_allowed_ips(overlay: IpNetwork, routes: &[String]) -> Vec<IpNet> {
    let mut ips = vec![host_net(overlay)];
    for route in routes {
        if let Ok(net) = route.parse::<IpNet>() {
            if !ips.contains(&net) {
                ips.push(net);
            }
        }
    }
    ips
}

impl NetRow {
    fn principal(&self) -> Principal {
        Principal {
            user: self.owner_email.clone(),
            tags: self.tags.clone(),
        }
    }
}

/// Build the network map delivered to `device_id`. `relays` are the relay
/// regions to advertise (from coordinator config).
pub async fn build(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    device_id: Uuid,
    relays: Vec<RelayRegion>,
) -> AppResult<NetworkMap> {
    let tenant: Tenant = sqlx::query_as("SELECT dns_suffix FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;

    let mut devices: Vec<NetRow> = sqlx::query_as(
        r#"SELECT d.id, d.hostname, d.public_key, d.overlay_ip, d.endpoints,
                  d.relay_region, d.last_seen, d.tags, u.email AS owner_email,
                  d.advertised_routes, d.key_expires_at
           FROM devices d
           LEFT JOIN users u ON u.id = d.owner_id
           WHERE d.tenant_id = $1 AND d.approved = true"#,
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;

    // Exclude devices whose key has expired (quarantined until they rotate).
    let now = Utc::now();
    devices.retain(|d| ws_proto::expiry::is_active(d.key_expires_at, now));

    let self_device = devices
        .iter()
        .find(|d| d.id == device_id)
        .ok_or(AppError::NotFound)?;
    let self_principal = self_device.principal();

    // Load the active ACL policy (None => allow-all).
    let policy = load_policy(pool, tenant_id).await;

    let peers: Vec<PeerNode> = devices
        .iter()
        .filter(|d| d.id != device_id)
        .filter(|d| match &policy {
            None => true,
            // Visible if traffic is permitted in either direction.
            Some(p) => {
                let peer = d.principal();
                p.allows(&self_principal, &peer) || p.allows(&peer, &self_principal)
            }
        })
        .map(|d| PeerNode {
            device_id: d.id,
            hostname: d.hostname.clone(),
            public_key: d.public_key.clone(),
            allowed_ips: merge_allowed_ips(d.overlay_ip, &d.advertised_routes),
            endpoints: d.endpoints.0.clone(),
            relay_region: d.relay_region.clone(),
            online: d
                .last_seen
                .map(|t| (Utc::now() - t).num_seconds() < 60)
                .unwrap_or(false),
            last_seen: d.last_seen,
        })
        .collect();

    // Inbound packet filter for this node (port-level ACL enforcement).
    // Empty when no policy is configured (allow-all).
    let packet_filter = match &policy {
        Some(p) => {
            let peer_principals: Vec<(crate::acl::Principal, IpNet)> = devices
                .iter()
                .filter(|d| d.id != device_id)
                .map(|d| (d.principal(), host_net(d.overlay_ip)))
                .collect();
            p.inbound_filter(&self_principal, &peer_principals)
        }
        None => vec![],
    };

    Ok(NetworkMap {
        version: Utc::now().timestamp_millis() as u64,
        self_node: SelfNode {
            device_id: self_device.id,
            overlay_ip: host_net(self_device.overlay_ip),
            hostname: self_device.hostname.clone(),
        },
        peers,
        relays,
        dns_suffix: tenant.dns_suffix,
        packet_filter,
    })
}

/// Load and parse the tenant's active ACL policy. A missing row means allow-all
/// (returns `None`); a present-but-unparseable document also falls back to
/// allow-all (logged) to avoid locking an admin out of their own network.
async fn load_policy(pool: &sqlx::PgPool, tenant_id: Uuid) -> Option<Policy> {
    let doc: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT document FROM acl_policies WHERE tenant_id = $1 AND active LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    let doc = doc?;
    // An empty object means "no rules configured yet" -> allow-all.
    doc.get("acls")?;
    match Policy::parse(&doc) {
        Ok(p) => Some(p),
        Err(e) => {
            tracing::error!(%tenant_id, error = %e, "invalid ACL policy; defaulting to allow-all");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> IpNetwork {
        s.parse().unwrap()
    }

    #[test]
    fn allowed_ips_includes_overlay_and_routes() {
        let ips = merge_allowed_ips(
            net("100.64.0.5/32"),
            &["192.168.1.0/24".into(), "10.0.0.0/8".into()],
        );
        assert_eq!(ips[0], "100.64.0.5/32".parse::<IpNet>().unwrap());
        assert!(ips.contains(&"192.168.1.0/24".parse().unwrap()));
        assert!(ips.contains(&"10.0.0.0/8".parse().unwrap()));
    }

    #[test]
    fn exit_node_advertises_default_route() {
        let ips = merge_allowed_ips(net("100.64.0.9/32"), &["0.0.0.0/0".into()]);
        assert!(ips.contains(&"0.0.0.0/0".parse().unwrap()));
    }

    #[test]
    fn invalid_routes_are_skipped() {
        let ips = merge_allowed_ips(net("100.64.0.1/32"), &["not-a-cidr".into()]);
        assert_eq!(ips.len(), 1); // only the overlay address
    }
}
