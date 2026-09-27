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
	return pattern.repeat(size / pattern.len() + 1).as_bytes()[..size].to_vec();
}

fn bench_decompress_bounded(c: &mut Criterion) {
	let mut group = c.benchmark_group("decompress_bounded");
	let max_bytes: usize = 10 * 1024 * 1024;

	for size in [1_024, 100_000, 1_000_000] {
		let json: Vec<u8> = make_json_payload(size);
		let compressed: Vec<u8> =
			compression::compress_with_level(&json, compression::DEFAULT_COMPRESSION_LEVEL).unwrap();
		group.bench_with_input(BenchmarkId::new("json", size), &compressed, |b, data| {
			b.iter(|| compression::decompress_bounded(data, max_bytes));
		});
	}

	group.finish();
}

fn bench_compress_levels(c: &mut Criterion) {
	let mut group = c.benchmark_group("compress_levels");
	let data: Vec<u8> = make_json_payload(100_000);

	for level in [1, 3, 9, 19] {
		group.bench_with_input(BenchmarkId::from_parameter(level), &level, |b, &level| {
			b.iter(|| compression::compress_with_level(&data, level));
		});
	}

	group.finish();
}

criterion_group!(benches, bench_decompress_bounded, bench_compress_levels);
criterion_main!(benches);
