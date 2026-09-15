use std::fmt;
use std::fmt::Write;

use arrayvec::{ArrayString, ArrayVec};
use bitcode::{Decode, Encode};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};

use crate::error::{ReductionError, Result};

const LENGTH_PREFIX_SIZE: usize = 4;
const MAX_FRAME_SIZE: usize = 64 * 1024;

// ── Version preamble ──
// bitcode frames are not self-describing: without a preamble, any TunnelFrame evolution makes a
// mismatched peer fail with an opaque decode error (or a caught decode panic). The control stream
// therefore opens with a 5-byte magic + version exchanged before any frame: the magic separates
// "not speaking this protocol at all" from "wrong version", and a version mismatch is rejected
// loudly on both sides instead of surfacing as framing garbage.
pub const PROTOCOL_MAGIC: [u8; 4] = *b"RDTN";
pub const PROTOCOL_VERSION: u8 = 1;
const PREAMBLE_LEN: usize = 5;

pub async fn write_preamble<W: tokio::io::AsyncWriteExt + Unpin>(writer: &mut W) -> Result<()> {
	let mut buf: [u8; PREAMBLE_LEN] = [0u8; PREAMBLE_LEN];
	buf[0..PROTOCOL_MAGIC.len()].copy_from_slice(&PROTOCOL_MAGIC);
	buf[PROTOCOL_MAGIC.len()] = PROTOCOL_VERSION;
	writer
		.write_all(&buf)
		.await
		.map_err(|e| ReductionError::Tunnel(format!("write preamble: {e}")))?;
	writer
		.flush()
		.await
		.map_err(|e| ReductionError::Tunnel(format!("flush preamble: {e}")))?;
	return Ok(());
}

// Read the peer's preamble: Err on a magic mismatch (the peer is not speaking this protocol at
// all), Ok(version) otherwise — the caller decides whether it supports that version.
pub async fn read_preamble<R: tokio::io::AsyncReadExt + Unpin>(reader: &mut R) -> Result<u8> {
	let mut buf: [u8; PREAMBLE_LEN] = [0u8; PREAMBLE_LEN];
	reader
		.read_exact(&mut buf)
		.await
		.map_err(|e| ReductionError::Tunnel(format!("read preamble: {e}")))?;
	if buf[0..PROTOCOL_MAGIC.len()] != PROTOCOL_MAGIC {
		return Err(ReductionError::Tunnel(
			"bad protocol magic: peer is not a reduction tunnel endpoint".into(),
		));
	}
	return Ok(buf[PROTOCOL_MAGIC.len()]);
}

pub const SESSION_ID_LEN: usize = 21;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Encode, Decode)]
pub struct SessionId(pub [u8; SESSION_ID_LEN]);

impl SessionId {
	// Random 64-bit id from the system CSPRNG. The previous derivation hashed addr + wall clock +
	// backend_id through DefaultHasher (fixed-key SipHash): predictable, and prone to collision
	// across rapid calls — and deregistration removes by id equality, so a collision cross-deletes
	// both sessions.
	pub fn generate() -> Result<Self> {
		let rng: SystemRandom = SystemRandom::new();
		let mut random: [u8; 8] = [0u8; 8];
		rng.fill(&mut random)
			.map_err(|_| ReductionError::Tunnel("system RNG unavailable for session id".into()))?;
		let value: u64 = u64::from_be_bytes(random);

		let mut buf: [u8; SESSION_ID_LEN] = [0u8; SESSION_ID_LEN];
		let mut tmp: ArrayString<24> = ArrayString::new();
		let _ = write!(tmp, "sess-{value:016x}");
		buf.copy_from_slice(tmp.as_bytes());
		return Ok(Self(buf));
	}

	#[must_use]
	pub fn as_str(&self) -> &str {
		// Session IDs are always ASCII hex, so this is infallible in practice
		return std::str::from_utf8(&self.0).unwrap_or("sess-????????????????");
	}
}

impl fmt::Display for SessionId {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		return f.write_str(self.as_str());
	}
}

impl fmt::Debug for SessionId {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		return write!(f, "SessionId({})", self.as_str());
	}
}

// Variants deliberately hold fixed-size inline buffers (ArrayString/ArrayVec) so frames encode with
// deterministic layout and zero heap allocation on the network path. Boxing the large `Register`
// variant to equalize sizes would defeat that and violate the project's no-Box convention.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Encode, Decode, PartialEq)]
pub enum TunnelFrame {
	Register {
		backend_id: ArrayString<256>,
		pool: ArrayString<32>,
		capabilities: ArrayVec<ArrayString<8>, 4>,
	},
	RegisterAck {
		session_id: SessionId,
	},
	Heartbeat {
		timestamp_ms: u64,
	},
	HeartbeatAck,
	NewStream {
		stream_id: u64,
	},
	// A control-plane availability update (finding F4). Sent by a peer that registered with
	// CONTROL_CAPABILITY; the listener applies it to the shared HealthState. `available` maps to
	// Availability Online/Offline (primitive so this frame stays lean-client compatible — the health
	// module is proxy-only).
	Health {
		backend_id: ArrayString<256>,
		available: bool,
	},
	// A wake request (finding F1), pushed by the proxy to a control-plane peer on a fresh uni-stream
	// when a request parks on a cold `wakeable` backend. `timeout_ms` is the park budget: the control
	// plane has that long to start the backend and register a session before the request 503s.
	Wake {
		backend_id: ArrayString<256>,
		timeout_ms: u64,
	},
	// A control peer's refusal of a wake (finding F1): the backend will NOT be started (e.g. over
	// budget), so the proxy should stop parking and 503 at once rather than wait out the deadline.
	RefuseWake {
		backend_id: ArrayString<256>,
	},
	Shutdown {
		reason: ArrayString<64>,
	},
}

/// Capability marking a control-plane publisher (e.g. Moist), permitted to send [`TunnelFrame::Health`].
///
/// Such a peer registers a session like any backend, but nothing routes to it (no
/// `[[routes]]`/`[[backends]]` names it), so it is never selected for traffic.
pub const CONTROL_CAPABILITY: &str = "control";

pub fn encode(frame: &TunnelFrame) -> Result<Vec<u8>> {
	let payload: Vec<u8> = bitcode::encode(frame);
	let len: u32 = u32::try_from(payload.len())
		.map_err(|_| ReductionError::Tunnel(format!("frame payload too large: {} bytes", payload.len())))?;
	if payload.len() > MAX_FRAME_SIZE {
		return Err(ReductionError::Tunnel(format!("frame too large: {} bytes", len)));
	}
	let mut buf: Vec<u8> = Vec::with_capacity(LENGTH_PREFIX_SIZE + payload.len());
	buf.extend_from_slice(&len.to_be_bytes());
	buf.extend_from_slice(&payload);
	return Ok(buf);
}

fn safe_decode(payload: &[u8]) -> Result<TunnelFrame> {
	std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| bitcode::decode::<TunnelFrame>(payload)))
		.map_err(|_| ReductionError::Tunnel("decode panic (possibly oversized field)".into()))?
		.map_err(|e| ReductionError::Tunnel(format!("decode error: {e}")))
}

pub fn decode(buf: &[u8]) -> Result<TunnelFrame> {
	if buf.len() < LENGTH_PREFIX_SIZE {
		return Err(ReductionError::Tunnel("frame too short for length prefix".into()));
	}
	let len: u32 = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
	let len_usize: usize = usize::try_from(len).unwrap_or(usize::MAX);
	let expected_total: usize = LENGTH_PREFIX_SIZE.saturating_add(len_usize);
	if buf.len() < expected_total {
		return Err(ReductionError::Tunnel(format!(
			"frame truncated: expected {} bytes, got {}",
			expected_total,
			buf.len()
		)));
	}
	if len_usize > MAX_FRAME_SIZE {
		return Err(ReductionError::Tunnel(format!("frame too large: {} bytes", len)));
	}
	let payload: &[u8] = &buf[LENGTH_PREFIX_SIZE..expected_total];
	return safe_decode(payload);
}

pub async fn read_frame<R: tokio::io::AsyncReadExt + Unpin>(reader: &mut R) -> Result<TunnelFrame> {
	let mut len_buf: [u8; LENGTH_PREFIX_SIZE] = [0u8; LENGTH_PREFIX_SIZE];
	reader
		.read_exact(&mut len_buf)
		.await
		.map_err(|e| ReductionError::Tunnel(format!("read length: {e}")))?;

	let len: u32 = u32::from_be_bytes(len_buf);
	let len_usize: usize = usize::try_from(len).unwrap_or(usize::MAX);
	if len_usize > MAX_FRAME_SIZE {
		return Err(ReductionError::Tunnel(format!("frame too large: {} bytes", len)));
	}

	let mut payload: Vec<u8> = vec![0u8; len_usize];
	reader
		.read_exact(&mut payload)
		.await
		.map_err(|e| ReductionError::Tunnel(format!("read payload: {e}")))?;

	return safe_decode(&payload);
}

pub async fn write_frame<W: tokio::io::AsyncWriteExt + Unpin>(writer: &mut W, frame: &TunnelFrame) -> Result<()> {
	let payload: Vec<u8> = bitcode::encode(frame);
	let len: u32 = u32::try_from(payload.len())
		.map_err(|_| ReductionError::Tunnel(format!("frame payload too large: {} bytes", payload.len())))?;
	if payload.len() > MAX_FRAME_SIZE {
		return Err(ReductionError::Tunnel(format!("frame too large: {} bytes", len)));
	}
	writer
		.write_all(&len.to_be_bytes())
		.await
		.map_err(|e| ReductionError::Tunnel(format!("write length: {e}")))?;
	writer
		.write_all(&payload)
		.await
		.map_err(|e| ReductionError::Tunnel(format!("write payload: {e}")))?;
	writer
		.flush()
		.await
		.map_err(|e| ReductionError::Tunnel(format!("flush: {e}")))?;
	return Ok(());
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_encode_decode_register() {
		let frame: TunnelFrame = TunnelFrame::Register {
			backend_id: ArrayString::from("api-1").unwrap(),
			pool: ArrayString::from("api").unwrap(),
			capabilities: ["http", "raw"].iter().map(|s| ArrayString::from(s).unwrap()).collect(),
		};
		let encoded: Vec<u8> = encode(&frame).unwrap();
		let decoded: TunnelFrame = decode(&encoded).unwrap();
		assert_eq!(frame, decoded);
	}

	#[test]
	fn test_encode_decode_register_ack() {
		let session_id: SessionId = SessionId::generate().unwrap();
		let frame: TunnelFrame = TunnelFrame::RegisterAck { session_id };
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
	fn test_encode_decode_wake() {
		let frame: TunnelFrame = TunnelFrame::Wake { backend_id: ArrayString::from("api-1").unwrap(), timeout_ms: 30_000 };
		let encoded: Vec<u8> = encode(&frame).unwrap();
		let decoded: TunnelFrame = decode(&encoded).unwrap();
		assert_eq!(frame, decoded);
	}

	#[test]
	fn test_encode_decode_refuse_wake() {
		let frame: TunnelFrame = TunnelFrame::RefuseWake { backend_id: ArrayString::from("api-1").unwrap() };
		let encoded: Vec<u8> = encode(&frame).unwrap();
		let decoded: TunnelFrame = decode(&encoded).unwrap();
		assert_eq!(frame, decoded);
	}

	#[test]
	fn test_encode_decode_health() {
		let frame: TunnelFrame = TunnelFrame::Health {
			backend_id: ArrayString::from("api-1").unwrap(),
			available: false,
		};
		let encoded: Vec<u8> = encode(&frame).unwrap();
		let decoded: TunnelFrame = decode(&encoded).unwrap();
		assert_eq!(frame, decoded);
	}

	#[test]
	fn test_encode_decode_shutdown() {
		let frame: TunnelFrame = TunnelFrame::Shutdown {
			reason: ArrayString::from("graceful").unwrap(),
		};
		let encoded: Vec<u8> = encode(&frame).unwrap();
		let decoded: TunnelFrame = decode(&encoded).unwrap();
		assert_eq!(frame, decoded);
	}

	#[tokio::test]
	async fn test_preamble_round_trip() {
		let mut buf: Vec<u8> = Vec::new();
		write_preamble(&mut buf).await.unwrap();
		let mut cursor: &[u8] = &buf;
		assert_eq!(read_preamble(&mut cursor).await.unwrap(), PROTOCOL_VERSION);
	}

	// A legacy (pre-preamble) client's first bytes are a frame's length prefix — a frame length can
	// never equal the magic bytes, so it must be refused as "not this protocol", not misparsed.
	#[tokio::test]
	async fn test_preamble_rejects_frame_bytes_as_bad_magic() {
		let mut buf: Vec<u8> = Vec::new();
		write_frame(&mut buf, &TunnelFrame::HeartbeatAck).await.unwrap();
		let mut cursor: &[u8] = &buf;
		assert!(
			read_preamble(&mut cursor).await.is_err(),
			"frame bytes must not pass as a preamble"
		);
	}

	// The reader reports the peer's version; judging it is the caller's job.
	#[tokio::test]
	async fn test_preamble_reports_foreign_version() {
		let mut buf: Vec<u8> = PROTOCOL_MAGIC.to_vec();
		buf.push(99);
		let mut cursor: &[u8] = &buf;
		assert_eq!(read_preamble(&mut cursor).await.unwrap(), 99);
	}

	#[test]
	fn test_session_ids_are_unique_and_well_formed() {
		let a: SessionId = SessionId::generate().unwrap();
		let b: SessionId = SessionId::generate().unwrap();
		assert_ne!(a, b, "two generated session ids must differ");
		assert!(a.as_str().starts_with("sess-"));
		assert_eq!(a.as_str().len(), SESSION_ID_LEN);
		assert!(
			a.as_str()["sess-".len()..].chars().all(|c| c.is_ascii_hexdigit()),
			"id body must be hex: {a}",
		);
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
		buf.extend_from_slice(&u32::try_from(garbage.len()).unwrap().to_be_bytes());
		buf.extend_from_slice(&garbage);
		let result = decode(&buf);
		assert!(result.is_err());
	}

	#[tokio::test]
	async fn test_read_write_frame_round_trip() {
		let frame: TunnelFrame = TunnelFrame::Register {
			backend_id: ArrayString::from("db-1").unwrap(),
			pool: ArrayString::from("db").unwrap(),
			capabilities: ["raw"].iter().map(|s| ArrayString::from(s).unwrap()).collect(),
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
			TunnelFrame::Shutdown {
				reason: ArrayString::from("done").unwrap(),
			},
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
