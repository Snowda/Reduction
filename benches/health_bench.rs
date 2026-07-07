// Benchmark harness code is exempt from the production lint gate the same way #[cfg(test)]
// modules are (the gate lints only --lib --bins). unwrap/expect on synthetic fixtures is fine here.
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use arrayvec::ArrayString;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use reduction::health::{Availability, BackendHealth, HealthBroadcast, HealthState};

fn make_broadcast(count: usize) -> HealthBroadcast {
    let entries: Vec<BackendHealth> = (0..count)
        .map(|i| BackendHealth {
            backend_id: ArrayString::from(&format!("backend-{i}")).unwrap(),
            load: 0.3,
            latency_ms: 50,
            availability: Availability::Online,
        })
        .collect();
    return HealthBroadcast { entries };
}

fn make_populated_state(count: usize) -> HealthState {
    let mut state: HealthState = HealthState::new();
    state.update(make_broadcast(count));
    return state;
}

fn bench_weight_factor(c: &mut Criterion) {
    let mut group = c.benchmark_group("health_weight_factor");

    for count in [10, 32, 64] {
        let state: HealthState = make_populated_state(count);

        group.bench_with_input(
            BenchmarkId::new("known_backend", count),
            &count,
            |b, _| {
                b.iter(|| state.weight_factor("backend-0"));
            },
        );

        group.bench_with_input(
            BenchmarkId::new("unknown_backend", count),
            &count,
            |b, _| {
                b.iter(|| state.weight_factor("nonexistent"));
            },
        );
    }

    group.finish();
}

fn bench_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("health_update");

    for count in [1, 10, 64] {
        let broadcast: HealthBroadcast = make_broadcast(count);

        group.bench_with_input(
            BenchmarkId::new("fresh_state", count),
            &broadcast,
            |b, broadcast| {
                b.iter(|| {
                    let mut state: HealthState = HealthState::new();
                    state.update(broadcast.clone());
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("overwrite_existing", count),
            &broadcast,
            |b, broadcast| {
                let mut state: HealthState = make_populated_state(count);
                b.iter(|| {
                    state.update(broadcast.clone());
                });
            },
        );
    }

    group.finish();
}

fn bench_is_valid(c: &mut Criterion) {
    let state: HealthState = make_populated_state(64);

    c.bench_function("health_is_valid_hit", |b| {
        b.iter(|| state.is_valid("backend-32"));
    });

    c.bench_function("health_is_valid_miss", |b| {
        b.iter(|| state.is_valid("nonexistent"));
    });
}

fn bench_bitcode_round_trip(c: &mut Criterion) {
    let mut group = c.benchmark_group("health_bitcode");

    for count in [2, 10, 64] {
        let broadcast: HealthBroadcast = make_broadcast(count);
        let encoded: Vec<u8> = bitcode::encode(&broadcast);

        group.bench_with_input(
            BenchmarkId::new("encode", count),
            &broadcast,
            |b, broadcast| {
                b.iter(|| bitcode::encode(broadcast));
            },
        );

        group.bench_with_input(
            BenchmarkId::new("decode", count),
            &encoded,
            |b, encoded| {
                b.iter(|| bitcode::decode::<HealthBroadcast>(encoded));
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_weight_factor, bench_update, bench_is_valid, bench_bitcode_round_trip);
criterion_main!(benches);
