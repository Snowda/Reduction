use crate::error::{ReductionError, Result};

const DEFAULT_COMPRESSION_LEVEL: i32 = 3;

pub fn compress(data: &[u8]) -> Result<Vec<u8>> {
    return zstd::encode_all(data, DEFAULT_COMPRESSION_LEVEL)
        .map_err(|e| ReductionError::Transport(format!("zstd compress: {e}")));
}

pub fn compress_with_level(data: &[u8], level: i32) -> Result<Vec<u8>> {
    return zstd::encode_all(data, level)
        .map_err(|e| ReductionError::Transport(format!("zstd compress: {e}")));
}

pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    return zstd::decode_all(data)
        .map_err(|e| ReductionError::Transport(format!("zstd decompress: {e}")));
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
        // Use a large enough payload that compression level differences are visible
        let data: Vec<u8> = "repeated data ".repeat(10_000).into_bytes();
        let low: Vec<u8> = compress_with_level(&data, 1).unwrap();
        let high: Vec<u8> = compress_with_level(&data, 19).unwrap();

        // Both should decompress to the same data
        assert_eq!(decompress(&low).unwrap(), data);
        assert_eq!(decompress(&high).unwrap(), data);

        // Higher compression level should produce smaller output (or equal)
        assert!(high.len() <= low.len());
    }

    #[test]
    fn test_decompress_invalid_data() {
        let result: Result<Vec<u8>> = decompress(&[0xFF, 0xFE, 0xFD, 0xFC]);
        assert!(result.is_err());
    }

    #[test]
    fn test_compress_large_payload() {
        let data: Vec<u8> = vec![42u8; 1_000_000];
        let compressed: Vec<u8> = compress(&data).unwrap();
        let decompressed: Vec<u8> = decompress(&compressed).unwrap();

        assert_eq!(decompressed, data);
        // Repeated data should compress significantly
        assert!(compressed.len() < data.len() / 10);
    }
}
