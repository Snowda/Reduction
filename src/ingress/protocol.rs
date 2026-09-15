use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use arrayvec::ArrayString;
use bitcode::{Decode, Encode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::{ReductionError, Result};

const LENGTH_PREFIX_SIZE: usize = 4;
// Frame ceiling (encoded bitcode payload, excluding the length prefix). Mirrors tunnel::protocol's
// MAX_FRAME_SIZE so a datagram batch can never exceed one QUIC-friendly frame.
pub const MAX_ENVELOPE_FRAME: usize = 64 * 1024;

// ── Version preamble ──
// Deliberately the same shape as tunnel::protocol's RDTN preamble: bitcode frames are not
// self-describing, so an Envelope evolution against a mismatched peer would fail with an opaque
// decode error (or a caught decode panic). The stream opens with a 5-byte magic + version before any
// frame: the magic separates "not speaking this protocol at all" from "wrong version", and a version
// mismatch is rejected loudly on both sides instead of surfacing as framing garbage.
pub const PROTOCOL_MAGIC: [u8; 4] = *b"RDIG";
pub const PROTOCOL_VERSION: u8 = 1;
const PREAMBLE_LEN: usize = 5;

pub async fn write_preamble<W: AsyncWriteExt + Unpin>(writer: &mut W) -> Result<()> {
	let mut buf: [u8; PREAMBLE_LEN] = [0u8; PREAMBLE_LEN];
	buf[0..PROTOCOL_MAGIC.len()].copy_from_slice(&PROTOCOL_MAGIC);
	buf[PROTOCOL_MAGIC.len()] = PROTOCOL_VERSION;
	writer
		.write_all(&buf)
		.await
		.map_err(|e| ReductionError::Ingress(format!("write preamble: {e}")))?;
	writer
		.flush()
		.await
		.map_err(|e| ReductionError::Ingress(format!("flush preamble: {e}")))?;
	return Ok(());
}

// Read the peer's preamble: Err on a magic mismatch (the peer is not speaking this protocol at all),
// Ok(version) otherwise — the caller decides whether it supports that version.
pub async fn read_preamble<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<u8> {
	let mut buf: [u8; PREAMBLE_LEN] = [0u8; PREAMBLE_LEN];
	reader
		.read_exact(&mut buf)
		.await
		.map_err(|e| ReductionError::Ingress(format!("read preamble: {e}")))?;
	if buf[0..PROTOCOL_MAGIC.len()] != PROTOCOL_MAGIC {
		return Err(ReductionError::Ingress(
			"bad protocol magic: peer is not a reduction ingress endpoint".into(),
		));
	}
	return Ok(buf[PROTOCOL_MAGIC.len()]);
}

// Original peer address, IPv4-mapped into a 16-byte slot so a single fixed layout carries both
// families. `#[repr(C)]` gives a deterministic in-memory layout for a value that crosses the network
// boundary (bitcode drives the wire encoding; the repr keeps the type itself unambiguous).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub struct Peer {
	pub ip: [u8; 16],
	pub port: u16,
}

impl Peer {
	// Build a Peer from a socket address, folding IPv4 into its v4-mapped IPv6 form so the 16-byte
	// slot is always populated the same way regardless of the listener's family.
	#[must_use]
	pub const fn from_socket_addr(addr: SocketAddr) -> Self {
		let ip: [u8; 16] = match addr.ip() {
			IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
			IpAddr::V6(v6) => v6.octets(),
		};
		return Self { ip, port: addr.port() };
	}

	// Recover the socket address, canonicalizing a v4-mapped value back to native IPv4 so the
	// consumer sees the same address form the sender used.
	#[must_use]
	pub fn socket_addr(&self) -> SocketAddr {
		let v6: Ipv6Addr = Ipv6Addr::from(self.ip);
		let ip: IpAddr = match v6.to_ipv4_mapped() {
			Some(v4) => IpAddr::V4(v4),
			None => IpAddr::V6(v6),
		};
		return SocketAddr::new(ip, self.port);
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct Datagram {
	pub peer: Peer,
	// Ingress receive time, for the consumer's lag accounting.
	pub recv_at_unix_nanos: u64,
	// Opaque, <= max_datagram_bytes. Reduction never inspects it beyond length.
	pub payload: Vec<u8>,
}

// The frame body. `Hello` opens every stream; `Batch` carries UDP datagrams; `Open` announces a TCP
// connection (the byte stream follows unframed — Phase 3).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum Envelope {
	Hello { ingress_id: ArrayString<64>, worker: u16 },
	Batch { datagrams: Vec<Datagram> },
	Open { peer: Peer },
}

pub fn encode(envelope: &Envelope) -> Result<Vec<u8>> {
	let payload: Vec<u8> = bitcode::encode(envelope);
	if payload.len() > MAX_ENVELOPE_FRAME {
		return Err(ReductionError::Ingress(format!(
			"envelope frame too large: {} bytes",
			payload.len()
		)));
	}
	let len: u32 = u32::try_from(payload.len())
		.map_err(|_| ReductionError::Ingress(format!("envelope payload too large: {} bytes", payload.len())))?;
	let mut buf: Vec<u8> = Vec::with_capacity(LENGTH_PREFIX_SIZE + payload.len());
	buf.extend_from_slice(&len.to_be_bytes());
	buf.extend_from_slice(&payload);
	return Ok(buf);
}

fn safe_decode(payload: &[u8]) -> Result<Envelope> {
	std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| bitcode::decode::<Envelope>(payload)))
		.map_err(|_| ReductionError::Ingress("decode panic (possibly oversized field)".into()))?
		.map_err(|e| ReductionError::Ingress(format!("decode error: {e}")))
}

pub fn decode(buf: &[u8]) -> Result<Envelope> {
	if buf.len() < LENGTH_PREFIX_SIZE {
		return Err(ReductionError::Ingress("frame too short for length prefix".into()));
	}
	let len: u32 = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
	let len_usize: usize = usize::try_from(len).unwrap_or(usize::MAX);
	// Reject an oversized declared length before honoring it, so a hostile prefix can never drive an
	// allocation or a slice past the buffer.
	if len_usize > MAX_ENVELOPE_FRAME {
		return Err(ReductionError::Ingress(format!("frame too large: {len} bytes")));
	}
	let expected_total: usize = LENGTH_PREFIX_SIZE.saturating_add(len_usize);
	if buf.len() < expected_total {
		return Err(ReductionError::Ingress(format!(
			"frame truncated: expected {} bytes, got {}",
			expected_total,
			buf.len()
		)));
	}
	let payload: &[u8] = &buf[LENGTH_PREFIX_SIZE..expected_total];
	return safe_decode(payload);
}

pub async fn read_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Envelope> {
	let mut len_buf: [u8; LENGTH_PREFIX_SIZE] = [0u8; LENGTH_PREFIX_SIZE];
	reader
		.read_exact(&mut len_buf)
		.await
		.map_err(|e| ReductionError::Ingress(format!("read length: {e}")))?;

	let len: u32 = u32::from_be_bytes(len_buf);
	let len_usize: usize = usize::try_from(len).unwrap_or(usize::MAX);
	// Cap the declared length before allocating the payload buffer, so a bogus prefix cannot force a
	// 4 GiB allocation.
	if len_usize > MAX_ENVELOPE_FRAME {
		return Err(ReductionError::Ingress(format!("frame too large: {len} bytes")));
	}

	let mut payload: Vec<u8> = vec![0u8; len_usize];
	reader
		.read_exact(&mut payload)
		.await
		.map_err(|e| ReductionError::Ingress(format!("read payload: {e}")))?;

	return safe_decode(&payload);
}

pub async fn write_frame<W: AsyncWriteExt + Unpin>(writer: &mut W, envelope: &Envelope) -> Result<()> {
	let frame: Vec<u8> = encode(envelope)?;
	writer
		.write_all(&frame)
		.await
		.map_err(|e| ReductionError::Ingress(format!("write frame: {e}")))?;
	writer
		.flush()
		.await
		.map_err(|e| ReductionError::Ingress(format!("flush frame: {e}")))?;
	return Ok(());
}

#[cfg(test)]
mod tests {
	use std::net::{Ipv4Addr, Ipv6Addr};

	use super::*;

	fn sample_peer() -> Peer {
		return Peer::from_socket_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 5000));
	}

	fn sample_datagram(port: u16, payload: &[u8]) -> Datagram {
		return Datagram {
			peer: Peer::from_socket_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)), port)),
			recv_at_unix_nanos: 1_716_220_800_000_000_000,
			payload: payload.to_vec(),
		};
	}

	#[test]
	fn test_peer_round_trips_ipv4() {
		let addr: SocketAddr = "192.168.1.100:5001".parse().unwrap();
		let peer: Peer = Peer::from_socket_addr(addr);
		assert_eq!(
			peer.socket_addr(),
			addr,
			"v4 peer must survive the v4-mapped round trip"
		);
		assert_eq!(peer.port, 5001);
	}

	#[test]
	fn test_peer_round_trips_ipv6() {
		let addr: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)), 9000);
		let peer: Peer = Peer::from_socket_addr(addr);
		assert_eq!(peer.socket_addr(), addr, "native v6 peer must survive the round trip");
	}

	#[test]
	fn test_envelope_hello_round_trip_every_field() {
		let envelope: Envelope = Envelope::Hello {
			ingress_id: ArrayString::from("site-dublin-udp").unwrap(),
			worker: 3,
		};
		let decoded: Envelope = decode(&encode(&envelope).unwrap()).unwrap();
		match decoded {
			Envelope::Hello { ingress_id, worker } => {
				assert_eq!(ingress_id.as_str(), "site-dublin-udp");
				assert_eq!(worker, 3);
			}
			other => panic!("expected Hello, got {other:?}"),
		}
	}

	#[test]
	fn test_envelope_batch_round_trip_every_field() {
		let datagrams: Vec<Datagram> = vec![sample_datagram(5000, b"first"), sample_datagram(5001, &[0xFF; 32])];
		let envelope: Envelope = Envelope::Batch {
			datagrams: datagrams.clone(),
		};
		let decoded: Envelope = decode(&encode(&envelope).unwrap()).unwrap();
		let Envelope::Batch { datagrams: got } = decoded else {
			panic!("expected Batch, got {decoded:?}");
		};
		assert_eq!(got.len(), datagrams.len());
		for (a, b) in got.iter().zip(datagrams.iter()) {
			assert_eq!(a.peer, b.peer, "peer must be byte-identical after round trip");
			assert_eq!(a.recv_at_unix_nanos, b.recv_at_unix_nanos);
			assert_eq!(a.payload, b.payload, "payload must be byte-identical after round trip");
		}
	}

	#[test]
	fn test_envelope_open_round_trip() {
		let envelope: Envelope = Envelope::Open { peer: sample_peer() };
		let decoded: Envelope = decode(&encode(&envelope).unwrap()).unwrap();
		assert_eq!(decoded, envelope);
	}

	// Distinct inputs must yield distinct output — proves the round trip carries the payload, not a
	// fixed shape that would pass a same-in-same-out check while dropping data.
	#[test]
	fn test_distinct_batches_encode_differently() {
		let a: Vec<u8> = encode(&Envelope::Batch {
			datagrams: vec![sample_datagram(1, b"alpha")],
		})
		.unwrap();
		let b: Vec<u8> = encode(&Envelope::Batch {
			datagrams: vec![sample_datagram(1, b"beta")],
		})
		.unwrap();
		assert_ne!(a, b, "different payloads must produce different frames");
	}

	#[test]
	fn test_decode_rejects_length_over_cap_before_slicing() {
		// A length prefix above MAX_ENVELOPE_FRAME must be rejected on inspection of the prefix alone,
		// never by allocating or slicing to that size.
		let mut buf: Vec<u8> = Vec::new();
		let bogus_len: u32 = u32::try_from(MAX_ENVELOPE_FRAME).unwrap() + 1;
		buf.extend_from_slice(&bogus_len.to_be_bytes());
		let err: ReductionError = decode(&buf).unwrap_err();
		assert!(format!("{err}").contains("frame too large"), "got: {err}");
	}

	#[tokio::test]
	async fn test_read_frame_rejects_length_over_cap_before_allocating() {
		// Feed only a 4-byte oversized length prefix and no payload. read_frame must reject on the
		// length alone — if it tried to allocate/read the payload it would block instead of erroring.
		let bogus_len: u32 = u32::try_from(MAX_ENVELOPE_FRAME).unwrap() + 1;
		let buf: Vec<u8> = bogus_len.to_be_bytes().to_vec();
		let mut cursor: &[u8] = &buf;
		let err: ReductionError = read_frame(&mut cursor).await.unwrap_err();
		assert!(format!("{err}").contains("frame too large"), "got: {err}");
	}

	#[test]
	fn test_decode_truncated_length_prefix() {
		assert!(decode(&[0u8, 0u8]).is_err());
	}

	#[test]
	fn test_decode_truncated_payload() {
		let mut buf: Vec<u8> = Vec::new();
		buf.extend_from_slice(&100u32.to_be_bytes());
		buf.extend_from_slice(&[0u8; 10]);
		assert!(decode(&buf).is_err());
	}

	#[tokio::test]
	async fn test_preamble_round_trip() {
		let mut buf: Vec<u8> = Vec::new();
		write_preamble(&mut buf).await.unwrap();
		let mut cursor: &[u8] = &buf;
		assert_eq!(read_preamble(&mut cursor).await.unwrap(), PROTOCOL_VERSION);
	}

	// The magic separates "not this protocol" from "wrong version": a frame's length-prefix bytes must
	// be refused as bad magic, not misparsed as a preamble.
	#[tokio::test]
	async fn test_preamble_rejects_frame_bytes_as_bad_magic() {
		let mut buf: Vec<u8> = Vec::new();
		write_frame(&mut buf, &Envelope::Open { peer: sample_peer() })
			.await
			.unwrap();
		let mut cursor: &[u8] = &buf;
		let err: ReductionError = read_preamble(&mut cursor).await.unwrap_err();
		assert!(format!("{err}").contains("bad protocol magic"), "got: {err}");
	}

	// The reader reports the peer's version verbatim; judging whether it is supported is the caller's
	// job. A mismatched version must come back as the number, not be silently accepted or masked.
	#[tokio::test]
	async fn test_preamble_reports_foreign_version() {
		let mut buf: Vec<u8> = PROTOCOL_MAGIC.to_vec();
		let foreign_version: u8 = PROTOCOL_VERSION + 42;
		buf.push(foreign_version);
		let mut cursor: &[u8] = &buf;
		assert_eq!(read_preamble(&mut cursor).await.unwrap(), foreign_version);
	}

	#[tokio::test]
	async fn test_read_write_frame_round_trip() {
		let envelope: Envelope = Envelope::Batch {
			datagrams: vec![sample_datagram(7000, b"payload-bytes")],
		};
		let mut buf: Vec<u8> = Vec::new();
		write_frame(&mut buf, &envelope).await.unwrap();
		let mut cursor: &[u8] = &buf;
		assert_eq!(read_frame(&mut cursor).await.unwrap(), envelope);
	}
}
