use std::cell::RefCell;
use std::io::{BufReader, Read, Take};

use crate::error::{ReductionError, Result};

pub const DEFAULT_COMPRESSION_LEVEL: i32 = 3;

// Threshold below which compression is skipped entirely (bandwidth savings negligible).
pub const MIN_COMPRESS_BYTES: usize = 256;

// Bodies at or below this size are compressed inline on the async thread.
// Above this, compression is offloaded to spawn_blocking.
pub const INLINE_COMPRESS_THRESHOLD: usize = 8192;

// Thread-local encoders are stored as Option so a (practically impossible) construction
// failure degrades to a meaningful error at call time rather than panicking on init.
thread_local! {
    static COMPRESSOR: RefCell<Option<zstd::bulk::Compressor<'static>>> =
        RefCell::new(zstd::bulk::Compressor::new(DEFAULT_COMPRESSION_LEVEL).ok());

    static DECOMPRESSOR: RefCell<Option<zstd::bulk::Decompressor<'static>>> =
        RefCell::new(zstd::bulk::Decompressor::new().ok());
}

pub fn compress(data: &[u8]) -> Result<Vec<u8>> {
    return COMPRESSOR.with_borrow_mut(|c| {
        let compressor: &mut zstd::bulk::Compressor<'static> = c.as_mut()
            .ok_or_else(|| ReductionError::Transport("zstd compressor unavailable".to_owned()))?;
        compressor.compress(data)
            .map_err(|e| ReductionError::Transport(format!("zstd compress: {e}")))
    });
}

pub fn compress_with_level(data: &[u8], level: i32) -> Result<Vec<u8>> {
    return zstd::encode_all(data, level)
        .map_err(|e| ReductionError::Transport(format!("zstd compress: {e}")));
}

pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    let capacity: usize = zstd::bulk::Decompressor::upper_bound(data)
        .filter(|&n| n > 0)
        .unwrap_or(0);

    if capacity > 0 {
        return DECOMPRESSOR.with_borrow_mut(|d| {
            let decompressor: &mut zstd::bulk::Decompressor<'static> = d.as_mut()
                .ok_or_else(|| ReductionError::Transport("zstd decompressor unavailable".to_owned()))?;
            decompressor.decompress(data, capacity)
                .map_err(|e| ReductionError::Transport(format!("zstd decompress: {e}")))
        });
    }

    return zstd::decode_all(data)
        .map_err(|e| ReductionError::Transport(format!("zstd decompress: {e}")));
}

pub fn decompress_bounded(data: &[u8], max_bytes: usize) -> Result<Vec<u8>> {
    // Fresh decoder per call — safety-critical path that must enforce size limits
    // against malicious payloads (zip bombs). Thread-local reuse is not worth the
    // complexity here since the Decoder wraps the input reader.
    let decoder: zstd::Decoder<'static, BufReader<&[u8]>> = zstd::Decoder::new(data)
        .map_err(|e| ReductionError::Transport(format!("zstd init: {e}")))?;
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

    #[test]
    fn test_compress_decompress_round_trip() {
        let original: &[u8] = b"Hello, Reduction! This is test data for zstd compression.";
        let compressed: Vec<u8> = compress(original).unwrap();
        let decompressed: Vec<u8> = decompress(&compressed).unwrap();

        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_compress_empty() {
        let compressed: Vec<u8> = compress(b"").unwrap();
        let decompressed: Vec<u8> = decompress(&compressed).unwrap();

        assert!(decompressed.is_empty());
    }

    #[test]
    fn test_compress_with_custom_level() {
        let data: Vec<u8> = "repeated data ".repeat(10_000).into_bytes();
        let low: Vec<u8> = compress_with_level(&data, 1).unwrap();
        let high: Vec<u8> = compress_with_level(&data, 19).unwrap();

        assert_eq!(decompress(&low).unwrap(), data);
        assert_eq!(decompress(&high).unwrap(), data);

        assert!(high.len() <= low.len());
    }

    #[test]
    fn test_decompress_invalid_data() {
        let result: Result<Vec<u8>> = decompress(&[0xFF, 0xFE, 0xFD, 0xFC]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decompress_bounded_within_limit() {
        let original: &[u8] = b"bounded decompression test data";
        let compressed: Vec<u8> = compress(original).unwrap();
        let decompressed: Vec<u8> = decompress_bounded(&compressed, 1024).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_decompress_bounded_exceeds_limit() {
        let original: Vec<u8> = vec![0u8; 10_000];
        let compressed: Vec<u8> = compress(&original).unwrap();
        let result: Result<Vec<u8>> = decompress_bounded(&compressed, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_compress_large_payload() {
        let data: Vec<u8> = vec![42u8; 1_000_000];
        let compressed: Vec<u8> = compress(&data).unwrap();
        let decompressed: Vec<u8> = decompress(&compressed).unwrap();

        assert_eq!(decompressed, data);
        assert!(compressed.len() < data.len() / 10);
    }

    #[test]
    fn test_pooled_compress_multiple_calls() {
        let data_a: &[u8] = b"first payload for pooled compressor test";
        let data_b: &[u8] = b"second payload with different content to verify context reuse";

        let compressed_a: Vec<u8> = compress(data_a).unwrap();
        let compressed_b: Vec<u8> = compress(data_b).unwrap();

        assert_eq!(decompress(&compressed_a).unwrap(), data_a);
        assert_eq!(decompress(&compressed_b).unwrap(), data_b);
    }

    #[test]
    fn test_min_compress_threshold() {
        assert!(MIN_COMPRESS_BYTES > 0);
        assert!(MIN_COMPRESS_BYTES <= INLINE_COMPRESS_THRESHOLD);
    }

    #[test]
    fn test_inline_compress_threshold() {
        assert!(INLINE_COMPRESS_THRESHOLD >= MIN_COMPRESS_BYTES);
    }
}
