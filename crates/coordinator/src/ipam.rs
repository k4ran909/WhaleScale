//! Overlay IP address management.
//!
//! Each tenant owns the full `100.64.0.0/10` CGNAT range; uniqueness is
//! enforced per-tenant. Phase 1 uses a simple "lowest free address" strategy.

use std::collections::HashSet;
use std::net::Ipv4Addr;

use sqlx::types::ipnetwork::IpNetwork;
use uuid::Uuid;

use crate::error::{AppError, AppResult};

/// First assignable address: 100.64.0.1 (`.0` reserved as network/anchor).
const BASE: u32 = 0x6440_0001; // 100.64.0.1
/// Last address inside 100.64.0.0/10: 100.127.255.254.
const LAST: u32 = 0x647F_FFFE; // 100.127.255.254

/// The lowest free overlay address given the set of in-use addresses (as `u32`).
/// Pure so the allocation policy can be unit-tested without a database.
fn next_free_v4(used: &HashSet<u32>) -> Option<Ipv4Addr> {
    (BASE..=LAST)
        .find(|candidate| !used.contains(candidate))
        .map(Ipv4Addr::from)
}

/// Allocate the lowest free overlay address for `tenant_id`, as a host network.
pub async fn allocate(pool: &sqlx::PgPool, tenant_id: Uuid) -> AppResult<IpNetwork> {
    let used: Vec<IpNetwork> =
        sqlx::query_scalar::<_, IpNetwork>("SELECT overlay_ip FROM devices WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_all(pool)
            .await?;

    let used: HashSet<u32> = used
        .into_iter()
        .filter_map(|net| match net.ip() {
            std::net::IpAddr::V4(v4) => Some(u32::from(v4)),
            std::net::IpAddr::V6(_) => None,
        })
        .collect();

    let v4 = next_free_v4(&used).ok_or_else(|| {
        AppError::Other(anyhow::anyhow!("overlay address pool exhausted for tenant"))
    })?;
    Ok(IpNetwork::new(std::net::IpAddr::V4(v4), 32).expect("valid /32"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_constants_map_to_cgnat() {
        assert_eq!(Ipv4Addr::from(BASE), Ipv4Addr::new(100, 64, 0, 1));
        assert_eq!(Ipv4Addr::from(LAST), Ipv4Addr::new(100, 127, 255, 254));
    }

    #[test]
    fn first_allocation_is_base() {
        let used = HashSet::new();
        assert_eq!(next_free_v4(&used), Some(Ipv4Addr::new(100, 64, 0, 1)));
    }

    #[test]
    fn fills_the_lowest_gap() {
        // .1 and .3 taken -> .2 is the lowest free.
        let used: HashSet<u32> = [
            u32::from(Ipv4Addr::new(100, 64, 0, 1)),
            u32::from(Ipv4Addr::new(100, 64, 0, 3)),
        ]
        .into_iter()
        .collect();
        assert_eq!(next_free_v4(&used), Some(Ipv4Addr::new(100, 64, 0, 2)));
    }

    #[test]
    fn skips_contiguous_run() {
        // .1 and .2 taken -> .3 next.
        let used: HashSet<u32> = [
            u32::from(Ipv4Addr::new(100, 64, 0, 1)),
            u32::from(Ipv4Addr::new(100, 64, 0, 2)),
        ]
        .into_iter()
        .collect();
        assert_eq!(next_free_v4(&used), Some(Ipv4Addr::new(100, 64, 0, 3)));
    }
}
