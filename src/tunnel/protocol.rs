use bitcode::{Decode, Encode};

use crate::error::{ReductionError, Result};

const LENGTH_PREFIX_SIZE: usize = 4;
const MAX_FRAME_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone, Encode, Decode, PartialEq)]
pub enum TunnelFrame {
    Register {
        backend_id: String,
        pool: String,
        capabilities: Vec<String>,
    },
    RegisterAck {
        session_id: String,
    },
    Heartbeat {
        timestamp_ms: u64,
    },
    HeartbeatAck,
    NewStream {
        stream_id: u64,
    },
    Shutdown {
        reason: String,
    },
}

pub fn encode(frame: &TunnelFrame) -> Result<Vec<u8>> {
    let payload: Vec<u8> = bitcode::encode(frame);
    let len: u32 = payload.len() as u32;
    if len as usize > MAX_FRAME_SIZE {
        return Err(ReductionError::Tunnel(format!(
            "frame too large: {} bytes",
            len
        )));
    }
    let mut buf: Vec<u8> = Vec::with_capacity(LENGTH_PREFIX_SIZE + payload.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&payload);
    return Ok(buf);
}

pub fn decode(buf: &[u8]) -> Result<TunnelFrame> {
    if buf.len() < LENGTH_PREFIX_SIZE {
        return Err(ReductionError::Tunnel("frame too short for length prefix".to_string()));
    }
    let len: u32 = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let expected_total: usize = LENGTH_PREFIX_SIZE + len as usize;
    if buf.len() < expected_total {
        return Err(ReductionError::Tunnel(format!(
            "frame truncated: expected {} bytes, got {}",
            expected_total,
            buf.len()
        )));
    }
    if len as usize > MAX_FRAME_SIZE {
        return Err(ReductionError::Tunnel(format!(
            "frame too large: {} bytes",
            len
        )));
    }
    let payload: &[u8] = &buf[LENGTH_PREFIX_SIZE..expected_total];
    let frame: TunnelFrame = bitcode::decode(payload)
        .map_err(|e| ReductionError::Tunnel(format!("decode error: {e}")))?;
    return Ok(frame);
}

pub async fn read_frame<R: tokio::io::AsyncReadExt + Unpin>(reader: &mut R) -> Result<TunnelFrame> {
    let mut len_buf: [u8; LENGTH_PREFIX_SIZE] = [0u8; LENGTH_PREFIX_SIZE];
    reader.read_exact(&mut len_buf).await
        .map_err(|e| ReductionError::Tunnel(format!("read length: {e}")))?;

    let len: u32 = u32::from_be_bytes(len_buf);
    if len as usize > MAX_FRAME_SIZE {
        return Err(ReductionError::Tunnel(format!("frame too large: {} bytes", len)));
    }

    let mut payload: Vec<u8> = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await
        .map_err(|e| ReductionError::Tunnel(format!("read payload: {e}")))?;

    let frame: TunnelFrame = bitcode::decode(&payload)
        .map_err(|e| ReductionError::Tunnel(format!("decode error: {e}")))?;
    return Ok(frame);
}

pub async fn write_frame<W: tokio::io::AsyncWriteExt + Unpin>(
    writer: &mut W,
    frame: &TunnelFrame,
) -> Result<()> {
    let payload: Vec<u8> = bitcode::encode(frame);
    let len: u32 = payload.len() as u32;
    if len as usize > MAX_FRAME_SIZE {
        return Err(ReductionError::Tunnel(format!("frame too large: {} bytes", len)));
    }
    writer.write_all(&len.to_be_bytes()).await
        .map_err(|e| ReductionError::Tunnel(format!("write length: {e}")))?;
    writer.write_all(&payload).await
        .map_err(|e| ReductionError::Tunnel(format!("write payload: {e}")))?;
    writer.flush().await
        .map_err(|e| ReductionError::Tunnel(format!("flush: {e}")))?;
    return Ok(());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_register() {
        let frame: TunnelFrame = TunnelFrame::Register {
            backend_id: "api-1".to_string(),
            pool: "api".to_string(),
            capabilities: vec!["http".to_string(), "raw".to_string()],
        };
        let encoded: Vec<u8> = encode(&frame).unwrap();
        let decoded: TunnelFrame = decode(&encoded).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn test_encode_decode_register_ack() {
        let frame: TunnelFrame = TunnelFrame::RegisterAck {
            session_id: "sess-abc123".to_string(),
        };
        let encoded: Vec<u8> = encode(&frame).unwrap();
        let decoded: TunnelFrame = decode(&encoded).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn test_encode_decode_heartbeat() {
        let frame: TunnelFrame = TunnelFrame::Heartbeat {
            timestamp_ms: 1716220800000,
        };
        let encoded: Vec<u8> = encode(&frame).unwrap();
        let decoded: TunnelFrame = decode(&encoded).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn test_encode_decode_heartbeat_ack() {
        let frame: TunnelFrame = TunnelFrame::HeartbeatAck;
        let encoded: Vec<u8> = encode(&frame).unwrap();
        let decoded: TunnelFrame = decode(&encoded).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn test_encode_decode_new_stream() {
        let frame: TunnelFrame = TunnelFrame::NewStream { stream_id: 42 };
        let encoded: Vec<u8> = encode(&frame).unwrap();
        let decoded: TunnelFrame = decode(&encoded).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn test_encode_decode_shutdown() {
        let frame: TunnelFrame = TunnelFrame::Shutdown {
            reason: "graceful".to_string(),
        };
        let encoded: Vec<u8> = encode(&frame).unwrap();
        let decoded: TunnelFrame = decode(&encoded).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn test_decode_truncated_length() {
        let buf: Vec<u8> = vec![0, 0];
        let result = decode(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_truncated_payload() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&100u32.to_be_bytes());
        buf.extend_from_slice(&[0u8; 10]);
        let result = decode(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_invalid_payload() {
        let mut buf: Vec<u8> = Vec::new();
        let garbage: [u8; 8] = [0xFF; 8];
        buf.extend_from_slice(&(garbage.len() as u32).to_be_bytes());
        buf.extend_from_slice(&garbage);
        let result = decode(&buf);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_read_write_frame_round_trip() {
        let frame: TunnelFrame = TunnelFrame::Register {
            backend_id: "db-1".to_string(),
            pool: "db".to_string(),
            capabilities: vec!["raw".to_string()],
        };

        let mut buf: Vec<u8> = Vec::new();
        write_frame(&mut buf, &frame).await.unwrap();

        let mut cursor: &[u8] = &buf;
        let decoded: TunnelFrame = read_frame(&mut cursor).await.unwrap();
        assert_eq!(frame, decoded);
    }

    #[tokio::test]
    async fn test_read_write_multiple_frames() {
        let frames: Vec<TunnelFrame> = vec![
            TunnelFrame::Heartbeat { timestamp_ms: 1000 },
            TunnelFrame::HeartbeatAck,
            TunnelFrame::Shutdown { reason: "done".to_string() },
        ];

        let mut buf: Vec<u8> = Vec::new();
        for f in &frames {
            write_frame(&mut buf, f).await.unwrap();
        }

        let mut cursor: &[u8] = &buf;
        for expected in &frames {
            let decoded: TunnelFrame = read_frame(&mut cursor).await.unwrap();
            assert_eq!(expected, &decoded);
        }
    }
}
