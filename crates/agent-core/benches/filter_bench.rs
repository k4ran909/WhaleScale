//! Per-packet ACL filter: naive linear scan vs. compiled O(1) lookup.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ws_agent_core::filter::{allows_inbound, parse_ipv4, CompiledFilter, PacketMeta};
use ws_proto::{FilterRule, Ports};

/// A realistic filter: `rules` rules, each permitting `ips_per_rule` peer /32s
/// on a couple of ports.
fn make_filter(rules: usize, ips_per_rule: usize) -> Vec<FilterRule> {
    (0..rules)
        .map(|r| {
            let src_ips = (0..ips_per_rule)
                .map(|i| {
                    let n = (r * ips_per_rule + i) as u32;
                    format!("100.{}.{}.{}/32", (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff)
                        .parse()
                        .unwrap()
                })
                .collect();
            FilterRule {
                src_ips,
                ports: Ports::List(vec![22, 443]),
            }
        })
        .collect()
}

fn ipv4(src: [u8; 4], dst_port: u16) -> Vec<u8> {
    let mut p = vec![0u8; 24];
    p[0] = 0x45;
    p[3] = 24;
    p[9] = 6; // TCP
    p[12..16].copy_from_slice(&src);
    p[22..24].copy_from_slice(&dst_port.to_be_bytes());
    p
}

fn bench(c: &mut Criterion) {
    let filter = make_filter(50, 20); // 1000 source IPs across 50 rules
    let compiled = CompiledFilter::compile(&filter);

    // Worst case for the naive scan: a source not present anywhere, so it must
    // examine every rule and every IP before deciding "deny".
    let meta: PacketMeta = parse_ipv4(&ipv4([198, 51, 100, 7], 22)).unwrap();

    let mut group = c.benchmark_group("packet_filter_1000_ips");
    group.bench_function("naive_linear_scan", |b| {
        b.iter(|| allows_inbound(black_box(&filter), black_box(&meta)))
    });
    group.bench_function("compiled_lookup", |b| {
        b.iter(|| compiled.allows(black_box(&meta)))
    });
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
