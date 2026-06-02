//! Tailscale-style ACL policy engine.
//!
//! A policy document (HuJSON/JSON) defines `groups`, and a list of `acls` rules
//! with `action: accept`, `src`, and `dst`. Each device is reduced to a
//! [`Principal`] (its owner's email + tags); [`Policy::allows`] decides whether
//! a source principal may reach a destination principal. The network-map builder
//! uses this to filter which peers each node can see.
//!
//! Selector forms (in `src` and the host part of `dst`):
//!   - `*`              — any
//!   - `group:NAME`     — any member of the group
//!   - `tag:NAME`       — any device carrying that tag
//!   - `alice@acme.com` — a specific user (device owner)
//!
//! `dst` entries are `HOST:PORTS` (e.g. `tag:server:22,443`). Ports are parsed
//! and retained for future packet-filter generation but do not affect peer
//! visibility (WireGuard is all-ports at the IP layer).

use std::collections::HashMap;

use ipnet::IpNet;
use serde::Deserialize;
use ws_proto::{FilterRule, Ports};

/// What a device "is" for ACL matching.
#[derive(Debug, Clone, Default)]
pub struct Principal {
    /// Owner's email, if the device has an owner.
    pub user: Option<String>,
    /// Tags carried by the device, in `tag:NAME` form.
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawRule {
    #[serde(default = "default_action")]
    action: String,
    #[serde(default)]
    src: Vec<String>,
    #[serde(default)]
    dst: Vec<String>,
}

fn default_action() -> String {
    "accept".to_string()
}

#[derive(Debug, Clone, Deserialize)]
struct RawPolicy {
    #[serde(default)]
    groups: HashMap<String, Vec<String>>,
    #[serde(default)]
    acls: Vec<RawRule>,
}

/// A parsed, validated policy.
#[derive(Debug, Clone)]
pub struct Policy {
    groups: HashMap<String, Vec<String>>,
    rules: Vec<Rule>,
}

#[derive(Debug, Clone)]
struct Rule {
    src: Vec<String>,
    dst: Vec<DstSel>,
}

/// A destination selector: a host pattern plus the ports it covers.
#[derive(Debug, Clone)]
struct DstSel {
    host: String,
    ports: Ports,
}

impl Policy {
    /// Parse and validate a policy document. Returns an error describing the
    /// first problem found (used by the admin API to reject bad edits).
    pub fn parse(doc: &serde_json::Value) -> Result<Policy, String> {
        let raw: RawPolicy =
            serde_json::from_value(doc.clone()).map_err(|e| format!("invalid policy: {e}"))?;

        let mut rules = Vec::new();
        for (i, r) in raw.acls.iter().enumerate() {
            if r.action != "accept" {
                return Err(format!(
                    "acls[{i}]: unsupported action {:?} (only \"accept\")",
                    r.action
                ));
            }
            if r.src.is_empty() || r.dst.is_empty() {
                return Err(format!("acls[{i}]: src and dst must be non-empty"));
            }
            let dst = r
                .dst
                .iter()
                .map(|d| DstSel {
                    host: host_of(d).to_string(),
                    ports: port_of(d),
                })
                .collect();
            rules.push(Rule {
                src: r.src.clone(),
                dst,
            });
        }

        Ok(Policy {
            groups: raw.groups,
            rules,
        })
    }

    /// Does any accept rule permit `src` to reach `dst`?
    pub fn allows(&self, src: &Principal, dst: &Principal) -> bool {
        self.rules.iter().any(|rule| {
            rule.src.iter().any(|s| self.matches(s, src))
                && rule.dst.iter().any(|d| self.matches(&d.host, dst))
        })
    }

    /// Compute the inbound packet filter for destination node `dst`: for every
    /// rule whose `dst` matches it, the source principals (resolved to their
    /// overlay IPs from `peers`) are allowed on the rule's ports.
    pub fn inbound_filter(
        &self,
        dst: &Principal,
        peers: &[(Principal, IpNet)],
    ) -> Vec<FilterRule> {
        let mut out = Vec::new();
        for rule in &self.rules {
            if !rule.dst.iter().any(|d| self.matches(&d.host, dst)) {
                continue;
            }
            let src_ips: Vec<IpNet> = peers
                .iter()
                .filter(|(p, _)| rule.src.iter().any(|s| self.matches(s, p)))
                .map(|(_, ip)| *ip)
                .collect();
            if src_ips.is_empty() {
                continue;
            }
            for d in &rule.dst {
                if self.matches(&d.host, dst) {
                    out.push(FilterRule {
                        src_ips: src_ips.clone(),
                        ports: d.ports.clone(),
                    });
                }
            }
        }
        out
    }

    /// Does `selector` match `p`?
    fn matches(&self, selector: &str, p: &Principal) -> bool {
        if selector == "*" {
            return true;
        }
        if let Some(group) = selector.strip_prefix("group:") {
            if let (Some(user), Some(members)) =
                (&p.user, self.groups.get(&format!("group:{group}")))
            {
                return members.iter().any(|m| m == user);
            }
            // Group lookups may also be keyed without the prefix.
            if let (Some(user), Some(members)) = (&p.user, self.groups.get(group)) {
                return members.iter().any(|m| m == user);
            }
            return false;
        }
        if selector.starts_with("tag:") {
            return p.tags.iter().any(|t| t == selector);
        }
        // Otherwise treat as a user email.
        p.user.as_deref() == Some(selector)
    }
}

/// Strip the `:PORTS` suffix from a `dst` entry, returning the host selector.
/// Handles `*`, `*:*`, `tag:server:22`, `group:eng:*`.
fn host_of(dst: &str) -> &str {
    match dst.rsplit_once(':') {
        // If the part after the last ':' looks like ports/`*`, drop it.
        Some((host, ports)) if is_ports(ports) => host,
        _ => dst,
    }
}

fn is_ports(s: &str) -> bool {
    s == "*" || (!s.is_empty() && s.split(',').all(|p| p.parse::<u16>().is_ok()))
}

/// Parse the ports portion of a `dst` entry (e.g. `22,443` or `*`).
fn port_of(dst: &str) -> Ports {
    match dst.rsplit_once(':') {
        Some((_, ports)) if is_ports(ports) => {
            if ports == "*" {
                Ports::All
            } else {
                Ports::List(ports.split(',').filter_map(|p| p.parse().ok()).collect())
            }
        }
        _ => Ports::All,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn principal(user: Option<&str>, tags: &[&str]) -> Principal {
        Principal {
            user: user.map(|u| u.to_string()),
            tags: tags.iter().map(|t| t.to_string()).collect(),
        }
    }

    #[test]
    fn wildcard_allows_everything() {
        let p = Policy::parse(
            &json!({ "acls": [{ "action": "accept", "src": ["*"], "dst": ["*:*"] }] }),
        )
        .unwrap();
        assert!(p.allows(
            &principal(Some("a@x.com"), &[]),
            &principal(None, &["tag:server"])
        ));
    }

    #[test]
    fn group_to_tag_rule() {
        let doc = json!({
            "groups": { "group:eng": ["alice@x.com", "bob@x.com"] },
            "acls": [
                { "action": "accept", "src": ["group:eng"], "dst": ["tag:server:22,443"] }
            ]
        });
        let p = Policy::parse(&doc).unwrap();
        let alice = principal(Some("alice@x.com"), &[]);
        let carol = principal(Some("carol@x.com"), &[]);
        let server = principal(None, &["tag:server"]);
        let laptop = principal(Some("dave@x.com"), &[]);

        assert!(p.allows(&alice, &server), "eng member -> tagged server");
        assert!(!p.allows(&carol, &server), "non-member denied");
        assert!(!p.allows(&alice, &laptop), "no rule to untagged laptop");
    }

    #[test]
    fn empty_acls_denies_all() {
        let p = Policy::parse(&json!({ "acls": [] })).unwrap();
        assert!(!p.allows(
            &principal(Some("a@x.com"), &[]),
            &principal(Some("b@x.com"), &[])
        ));
    }

    #[test]
    fn rejects_non_accept_action() {
        let err =
            Policy::parse(&json!({ "acls": [{ "action": "drop", "src": ["*"], "dst": ["*:*"] }] }))
                .unwrap_err();
        assert!(err.contains("unsupported action"));
    }

    #[test]
    fn host_parsing_strips_ports() {
        assert_eq!(host_of("tag:server:22,443"), "tag:server");
        assert_eq!(host_of("*:*"), "*");
        assert_eq!(host_of("group:eng:*"), "group:eng");
        assert_eq!(host_of("alice@x.com"), "alice@x.com");
    }

    #[test]
    fn port_parsing() {
        assert_eq!(port_of("tag:server:22,443"), Ports::List(vec![22, 443]));
        assert_eq!(port_of("*:*"), Ports::All);
        assert_eq!(port_of("alice@x.com"), Ports::All); // no ports -> all
    }

    #[test]
    fn inbound_filter_resolves_sources_and_ports() {
        let doc = json!({
            "groups": { "group:eng": ["alice@x.com"] },
            "acls": [
                { "action": "accept", "src": ["group:eng"], "dst": ["tag:server:22,443"] }
            ]
        });
        let p = Policy::parse(&doc).unwrap();

        let alice = (principal(Some("alice@x.com"), &[]), "100.64.0.10/32".parse().unwrap());
        let carol = (principal(Some("carol@x.com"), &[]), "100.64.0.11/32".parse().unwrap());
        let server = principal(None, &["tag:server"]);
        let laptop = principal(Some("dave@x.com"), &[]);

        // The server's inbound filter: only Alice's IP, on ports 22/443.
        let filter = p.inbound_filter(&server, &[alice.clone(), carol.clone()]);
        assert_eq!(filter.len(), 1);
        assert_eq!(filter[0].src_ips, vec!["100.64.0.10/32".parse().unwrap()]);
        assert_eq!(filter[0].ports, Ports::List(vec![22, 443]));

        // A node that isn't a destination of any rule gets no inbound rules.
        assert!(p.inbound_filter(&laptop, &[alice, carol]).is_empty());
    }
}
