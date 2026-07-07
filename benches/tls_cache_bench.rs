// Benchmark harness code is exempt from the production lint gate the same way #[cfg(test)]
// modules are (the gate lints only --lib --bins). unwrap/expect on synthetic fixtures is fine here.
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use std::time::Duration;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use reduction::tls::cache::TokenCache;

fn bench_get_hit(c: &mut Criterion) {
    let cache: TokenCache = TokenCache::new(Duration::from_secs(300));
    cache.insert("cert-fingerprint-abc".to_owned(), vec![0u8; 256]);

    c.bench_function("tls_cache_get_hit", |b| {
        b.iter(|| cache.get("cert-fingerprint-abc"));
    });
}

fn bench_get_miss(c: &mut Criterion) {
    let cache: TokenCache = TokenCache::new(Duration::from_secs(300));
    cache.insert("cert-fingerprint-abc".to_owned(), vec![0u8; 256]);

    c.bench_function("tls_cache_get_miss", |b| {
        b.iter(|| cache.get("nonexistent-fingerprint"));
    });
}

fn bench_insert(c: &mut Criterion) {
    let cache: TokenCache = TokenCache::new(Duration::from_secs(300));

    c.bench_function("tls_cache_insert", |b| {
        let mut i: u64 = 0;
        b.iter(|| {
            cache.insert(format!("cert-{i}"), vec![0u8; 256]);
            i += 1;
        });
    });
}

fn bench_get_at_scale(c: &mut Criterion) {
    let mut group = c.benchmark_group("tls_cache_get_at_scale");

    for entry_count in [10, 100, 1000] {
        let cache: TokenCache = TokenCache::new(Duration::from_secs(300));
        for i in 0..entry_count {
            cache.insert(format!("cert-{i}"), vec![0u8; 256]);
        }

        let target: String = format!("cert-{}", entry_count / 2);
        group.bench_with_input(
            BenchmarkId::from_parameter(entry_count),
            &target,
            |b, target| {
                b.iter(|| cache.get(target));
            },
        );
    }

    group.finish();
}

fn bench_insert_overwrite(c: &mut Criterion) {
    let cache: TokenCache = TokenCache::new(Duration::from_secs(300));
    cache.insert("cert-fixed".to_owned(), vec![0u8; 256]);

    c.bench_function("tls_cache_insert_overwrite", |b| {
        b.iter(|| {
            cache.insert("cert-fixed".to_owned(), vec![0u8; 256]);
        });
    });
}

criterion_group!(benches, bench_get_hit, bench_get_miss, bench_insert, bench_get_at_scale, bench_insert_overwrite);
criterion_main!(benches);
