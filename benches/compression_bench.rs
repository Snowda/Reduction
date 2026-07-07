// Benchmark harness code is exempt from the production lint gate the same way #[cfg(test)]
// modules are (the gate lints only --lib --bins). unwrap/expect and the deliberate u64->u8
// truncation that generates pseudo-random fixture bytes are fine in this synthetic context.
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::cast_possible_truncation)]

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use reduction::compression;

fn make_json_payload(size: usize) -> Vec<u8> {
    let pattern: &str = r#"{"id":12345,"name":"service-node","status":"healthy","load":0.42,"latency_ms":30},"#;
    return pattern.repeat(size / pattern.len() + 1)[..size].as_bytes().to_vec();
}

fn make_random_payload(size: usize) -> Vec<u8> {
    // Pseudorandom bytes that don't compress well
    let mut data: Vec<u8> = Vec::with_capacity(size);
    let mut state: u64 = 0xDEAD_BEEF_CAFE_1234;
    for _ in 0..size {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        data.push((state >> 33) as u8);
    }
    return data;
}

fn bench_compress(c: &mut Criterion) {
    let mut group = c.benchmark_group("compress");

    for size in [1_024, 100_000, 1_000_000] {
        let json: Vec<u8> = make_json_payload(size);
        group.bench_with_input(
            BenchmarkId::new("json", size),
            &json,
            |b, data| {
                b.iter(|| compression::compress(data));
            },
        );

        let random: Vec<u8> = make_random_payload(size);
        group.bench_with_input(
            BenchmarkId::new("random", size),
            &random,
            |b, data| {
                b.iter(|| compression::compress(data));
            },
        );
    }

    group.finish();
}

fn bench_decompress(c: &mut Criterion) {
    let mut group = c.benchmark_group("decompress");

    for size in [1_024, 100_000, 1_000_000] {
        let json: Vec<u8> = make_json_payload(size);
        let compressed_json: Vec<u8> = compression::compress(&json).unwrap();
        group.bench_with_input(
            BenchmarkId::new("json", size),
            &compressed_json,
            |b, data| {
                b.iter(|| compression::decompress(data));
            },
        );

        let random: Vec<u8> = make_random_payload(size);
        let compressed_random: Vec<u8> = compression::compress(&random).unwrap();
        group.bench_with_input(
            BenchmarkId::new("random", size),
            &compressed_random,
            |b, data| {
                b.iter(|| compression::decompress(data));
            },
        );
    }

    group.finish();
}

fn bench_decompress_bounded(c: &mut Criterion) {
    let mut group = c.benchmark_group("decompress_bounded");
    let max_bytes: usize = 10 * 1024 * 1024;

    for size in [1_024, 100_000, 1_000_000] {
        let json: Vec<u8> = make_json_payload(size);
        let compressed: Vec<u8> = compression::compress(&json).unwrap();
        group.bench_with_input(
            BenchmarkId::new("json", size),
            &compressed,
            |b, data| {
                b.iter(|| compression::decompress_bounded(data, max_bytes));
            },
        );
    }

    group.finish();
}

fn bench_compress_levels(c: &mut Criterion) {
    let mut group = c.benchmark_group("compress_levels");
    let data: Vec<u8> = make_json_payload(100_000);

    for level in [1, 3, 9, 19] {
        group.bench_with_input(
            BenchmarkId::from_parameter(level),
            &level,
            |b, &level| {
                b.iter(|| compression::compress_with_level(&data, level));
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_compress, bench_decompress, bench_decompress_bounded, bench_compress_levels);
criterion_main!(benches);
