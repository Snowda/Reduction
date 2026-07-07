// Benchmark harness code is exempt from the production lint gate the same way #[cfg(test)]
// modules are (the gate lints only --lib --bins). unwrap/expect on synthetic fixtures is fine here.
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use std::net::IpAddr;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use reduction::ratelimit::RateLimit;

fn bench_check_cache_hit(c: &mut Criterion) {
    let limiter: RateLimit = RateLimit::new(u32::MAX).unwrap();
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    // Prime the cache
    limiter.check(ip).unwrap();

    c.bench_function("ratelimit_cache_hit", |b| {
        b.iter(|| limiter.check(ip));
    });
}

fn bench_check_single_ip(c: &mut Criterion) {
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    c.bench_function("ratelimit_single_ip_cold", |b| {
        b.iter(|| {
            let fresh: RateLimit = RateLimit::new(u32::MAX).unwrap();
            fresh.check(ip)
        });
    });
}

fn bench_check_many_ips(c: &mut Criterion) {
    let mut group = c.benchmark_group("ratelimit_many_ips");

    for ip_count in [10, 100, 1000] {
        let limiter: RateLimit = RateLimit::new(u32::MAX).unwrap();
        let ips: Vec<IpAddr> = (0..ip_count)
            .map(|i: u32| {
                let a: u8 = ((i >> 16) & 0xFF) as u8;
                let b: u8 = ((i >> 8) & 0xFF) as u8;
                let c: u8 = (i & 0xFF) as u8;
                format!("10.{a}.{b}.{c}").parse().unwrap()
            })
            .collect();

        // Prime all IPs
        for ip in &ips {
            limiter.check(*ip).unwrap();
        }

        group.bench_with_input(
            BenchmarkId::from_parameter(ip_count),
            &ip_count,
            |b, _| {
                let mut idx: usize = 0;
                b.iter(|| {
                    let ip: IpAddr = ips[idx % ips.len()];
                    idx += 1;
                    limiter.check(ip)
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_check_cache_hit, bench_check_single_ip, bench_check_many_ips);
criterion_main!(benches);
