use std::io::{BufReader, Read, Take};

use crate::error::{ReductionError, Result};

pub const DEFAULT_COMPRESSION_LEVEL: i32 = 3;

pub fn compress_with_level(data: &[u8], level: i32) -> Result<Vec<u8>> {
	return zstd::encode_all(data, level).map_err(|e| ReductionError::Transport(format!("zstd compress: {e}")));
}

pub fn decompress_bounded(data: &[u8], max_bytes: usize) -> Result<Vec<u8>> {
	// Fresh decoder per call — safety-critical path that must enforce size limits
	// against malicious payloads (zip bombs). Thread-local reuse is not worth the
	// complexity here since the Decoder wraps the input reader.
	let decoder: zstd::Decoder<'static, BufReader<&[u8]>> =
		zstd::Decoder::new(data).map_err(|e| ReductionError::Transport(format!("zstd init: {e}")))?;
	let mut limited: Take<zstd::Decoder<'static, BufReader<&[u8]>>> =
		decoder.take(u64::try_from(max_bytes + 1).unwrap_or(u64::MAX));
	let mut output: Vec<u8> = Vec::new();
	limited
		.read_to_end(&mut output)
		.map_err(|e| ReductionError::Transport(format!("zstd decompress: {e}")))?;
	if output.len() > max_bytes {
		return Err(ReductionError::Transport(format!(
			"decompressed body exceeds {} byte limit",
			max_bytes
		)));
	}
	return Ok(output);
}

#[cfg(test)]
mod tests {
	use super::*;

	// Generous ceiling for round-trip decodes: large enough that no test fixture trips the guard.
	const ROUND_TRIP_CAP: usize = 8 * 1024 * 1024;

	#[test]
	fn test_compress_with_custom_level() {
		let data: Vec<u8> = "repeated data ".repeat(10_000).into_bytes();
		let low: Vec<u8> = compress_with_level(&data, 1).unwrap();
		let high: Vec<u8> = compress_with_level(&data, 19).unwrap();

		assert_eq!(decompress_bounded(&low, ROUND_TRIP_CAP).unwrap(), data);
		assert_eq!(decompress_bounded(&high, ROUND_TRIP_CAP).unwrap(), data);

		assert!(high.len() <= low.len());
	}

	#[test]
	fn test_compress_with_level_large_payload_round_trips() {
		let data: Vec<u8> = vec![42u8; 1_000_000];
		let compressed: Vec<u8> = compress_with_level(&data, DEFAULT_COMPRESSION_LEVEL).unwrap();
		let decompressed: Vec<u8> = decompress_bounded(&compressed, ROUND_TRIP_CAP).unwrap();

		assert_eq!(decompressed, data);
		assert!(compressed.len() < data.len() / 10);
	}

	#[test]
	fn test_decompress_bounded_within_limit() {
		let original: &[u8] = b"bounded decompression test data";
		let compressed: Vec<u8> = compress_with_level(original, DEFAULT_COMPRESSION_LEVEL).unwrap();
		let decompressed: Vec<u8> = decompress_bounded(&compressed, 1024).unwrap();
		assert_eq!(decompressed, original);
	}

	#[test]
	fn test_decompress_bounded_exceeds_limit() {
		let original: Vec<u8> = vec![0u8; 10_000];
		let compressed: Vec<u8> = compress_with_level(&original, DEFAULT_COMPRESSION_LEVEL).unwrap();
		let result: Result<Vec<u8>> = decompress_bounded(&compressed, 100);
		assert!(result.is_err());
	}

	#[test]
	fn test_decompress_bounded_invalid_data() {
		let result: Result<Vec<u8>> = decompress_bounded(&[0xFF, 0xFE, 0xFD, 0xFC], 1024);
		assert!(result.is_err());
	}
}
