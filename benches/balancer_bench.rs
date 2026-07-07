// Benchmark harness code is exempt from the production lint gate the same way #[cfg(test)]
// modules are (the gate lints only --lib --bins). unwrap/expect on synthetic fixtures is fine here.
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use std::net::IpAddr;

use arrayvec::ArrayString;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use reduction::balancer::BackendPool;
use reduction::config::{BackendConfig, TransportKind};
use reduction::health::{Availability, BackendHealth, HealthBroadcast, HealthState};

fn make_backends(count: usize) -> Vec<BackendConfig> {
    return (0..count)
        .map(|i| BackendConfig::new(
            &format!("backend-{i}"),
            format!("10.0.{}.{}:8080", i / 256, i % 256).parse().unwrap(),
            1.0,
            TransportKind::Tcp,
        ).unwrap())
        .collect();
}

fn make_health_all_healthy(count: usize) -> HealthState {
    let mut state: HealthState = HealthState::new();
    let entries: Vec<BackendHealth> = (0..count)
        .map(|i| BackendHealth {
            backend_id: ArrayString::from(&format!("backend-{i}")).unwrap(),
            load: 0.2,
            latency_ms: 30,
            availability: Availability::Online,
        })
        .collect();
    state.update(HealthBroadcast { entries });
    return state;
}

fn make_health_mixed(count: usize) -> HealthState {
    let mut state: HealthState = HealthState::new();
    let entries: Vec<BackendHealth> = (0..count)
        .map(|i| BackendHealth {
            backend_id: ArrayString::from(&format!("backend-{i}")).unwrap(),
            load: if i % 3 == 0 { 0.95 } else { 0.1 },
            latency_ms: if i % 5 == 0 { 800 } else { 30 },
            availability: if i % 7 != 0 { Availability::Online } else { Availability::Offline },
        })
        .collect();
    state.update(HealthBroadcast { entries });
    return state;
}

fn bench_select(c: &mut Criterion) {
    let mut group = c.benchmark_group("balancer_select");
    let ip: IpAddr = "192.168.1.42".parse().unwrap();

    for backend_count in [2, 16, 64] {
        let pool: BackendPool = BackendPool::new(make_backends(backend_count), 0.05).unwrap();

        let health_empty: HealthState = HealthState::new();
        group.bench_with_input(
            BenchmarkId::new("no_health", backend_count),
            &backend_count,
            |b, _| {
                b.iter(|| pool.select(ip, &health_empty));
            },
        );

        let health_all: HealthState = make_health_all_healthy(backend_count);
        group.bench_with_input(
            BenchmarkId::new("all_healthy", backend_count),
            &backend_count,
            |b, _| {
                b.iter(|| pool.select(ip, &health_all));
            },
        );

        let health_mixed: HealthState = make_health_mixed(backend_count);
        group.bench_with_input(
            BenchmarkId::new("mixed_health", backend_count),
            &backend_count,
            |b, _| {
                b.iter(|| pool.select(ip, &health_mixed));
            },
        );
    }

    group.finish();
}

fn bench_select_varied_ips(c: &mut Criterion) {
    let pool: BackendPool = BackendPool::new(make_backends(16), 0.05).unwrap();
    let health: HealthState = make_health_all_healthy(16);

    let ips: Vec<IpAddr> = (0..256u16)
        .map(|i| format!("10.0.{}.{}", i / 256, i % 256).parse().unwrap())
        .collect();

    c.bench_function("balancer_select_varied_ips_16", |b| {
        let mut idx: usize = 0;
        b.iter(|| {
            let ip: IpAddr = ips[idx % ips.len()];
            idx += 1;
            pool.select(ip, &health)
        });
    });
}

fn bench_pool_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("balancer_construction");

    for count in [2, 16, 64] {
        let backends: Vec<BackendConfig> = make_backends(count);
        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &backends,
            |b, backends| {
                b.iter(|| BackendPool::new(backends.clone(), 0.05));
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_select, bench_select_varied_ips, bench_pool_construction);
criterion_main!(benches);
