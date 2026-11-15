//! The `fastlane_chunked` target: fastlane's ChunkedDecoder on raw body bytes. The decode must not change with
//! the read boundaries, and it must agree with hyper's client decoder on the same body.

use http::{Method, StatusCode};
use reduction::proxy::handler::fastlane::chunked::{ChunkError, ChunkedDecoder};

use crate::oracle::{self, ClientRead};

const CHUNKED_HEAD: &[u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
	Done,
	Incomplete,
	Refused(ChunkError),
}

/// The data the decoder yielded, the bytes it consumed, and how it stopped.
#[derive(Debug, PartialEq, Eq)]
pub struct Decoded {
	pub data: Vec<u8>,
	pub consumed: usize,
	pub outcome: Outcome,
}

/// Decode `body` fed `piece` bytes at a time, as the relay feeds it one socket read at a time.
#[must_use]
pub fn decode(body: &[u8], piece: usize) -> Decoded {
	let mut decoder: ChunkedDecoder = ChunkedDecoder::default();
	let mut data: Vec<u8> = Vec::new();
	let mut consumed: usize = 0;
	for read in body.chunks(piece.max(1)) {
		match decoder.decode(read, &mut |span: &[u8]| data.extend_from_slice(span)) {
			Ok(taken) => consumed += taken,
			Err(error) => {
				return Decoded {
					data,
					consumed,
					outcome: Outcome::Refused(error),
				};
			}
		}
		if decoder.is_done() {
			return Decoded {
				data,
				consumed,
				outcome: Outcome::Done,
			};
		}
	}
	return Decoded {
		data,
		consumed,
		outcome: Outcome::Incomplete,
	};
}

// A refusal stops mid-read, so only the error is comparable; otherwise every field must match.
fn is_same_decode(whole: &Decoded, split: &Decoded) -> bool {
	return match (whole.outcome, split.outcome) {
		(Outcome::Refused(a), Outcome::Refused(b)) => a == b,
		_ => whole == split,
	};
}

/// The invariant. The first byte sets the read size and the rest is the body. A split decode equals the whole
/// one. An unfinished decode consumed every byte. hyper reads the same data exactly when fastlane finishes.
pub fn check(data: &[u8]) -> Result<(), String> {
	let Some((&piece, body)) = data.split_first() else {
		return Ok(());
	};
	let whole: Decoded = decode(body, body.len());
	let split: Decoded = decode(body, usize::from(piece));
	if !is_same_decode(&whole, &split) {
		return Err(format!("reads of {piece} bytes changed the decode: whole {whole:?}, split {split:?}"));
	}
	if whole.outcome == Outcome::Incomplete && whole.consumed != body.len() {
		return Err(format!("an unfinished body left {} of {} bytes unread", body.len() - whole.consumed, body.len()));
	}
	// Bytes after the last chunk belong to the next response, so hyper gets the body alone.
	let sent: &[u8] = if whole.outcome == Outcome::Done { &body[..whole.consumed] } else { body };
	let hyper: Result<ClientRead, String> = oracle::client_read(&Method::GET, &[CHUNKED_HEAD, sent].concat())?;
	return agrees(&whole, hyper);
}

// The differential verdict: fastlane finished with the data hyper read, or neither finished.
fn agrees(whole: &Decoded, hyper: Result<ClientRead, String>) -> Result<(), String> {
	return match (whole.outcome, hyper) {
		(Outcome::Done, Ok(read)) if read.status == StatusCode::OK && read.body == whole.data => Ok(()),
		(Outcome::Done, other) => Err(format!("fastlane decoded {:?}, hyper read {other:?}", whole.data)),
		(outcome, Ok(read)) => Err(format!("fastlane stopped {outcome:?}, hyper read {read:?}")),
		(_, Err(_)) => Ok(()),
	};
}

#[cfg(test)]
mod tests {
	use bytes::Bytes;

	use super::*;

	const VALID: &[u8] = b"4\r\nWiki\r\n5;x=y\r\npedia\r\n0\r\nx-t: 1\r\n\r\nNEXT";

	#[test]
	fn a_valid_body_agrees_with_hyper_at_every_read_size() -> Result<(), String> {
		(0..=u8::MAX).try_for_each(|piece: u8| return check(&[&[piece][..], VALID].concat()))?;
		let whole: Decoded = decode(VALID, VALID.len());
		assert_eq!((whole.data.as_slice(), whole.outcome), (&b"Wikipedia"[..], Outcome::Done), "the decode is not vacuous");
		assert_eq!(whole.consumed, VALID.len() - b"NEXT".len(), "the next response's bytes stay unread");
		return Ok(());
	}

	#[test]
	fn refused_and_unfinished_bodies_pass_because_hyper_refuses_them_too() -> Result<(), String> {
		check(b"\x01x\r\n")?;
		check(b"\x025\r\nab")?;
		assert_eq!(decode(b"5\r\nab", 1).outcome, Outcome::Incomplete);
		assert!(matches!(decode(b"x\r\n", 1).outcome, Outcome::Refused(_)), "a non-hex size is refused");
		return Ok(());
	}

	// Negative controls: each way of disagreeing with hyper fails the verdict, so a pass is not vacuous.
	#[test]
	fn every_disagreement_with_hyper_fails() {
		let read = |body: &'static [u8]| -> Result<ClientRead, String> {
			return Ok(ClientRead { status: StatusCode::OK, body: Bytes::from_static(body) });
		};
		let done: Decoded = Decoded { data: b"hi".to_vec(), consumed: 0, outcome: Outcome::Done };
		let stopped: Decoded = Decoded { data: Vec::new(), consumed: 0, outcome: Outcome::Incomplete };
		assert!(agrees(&done, read(b"hi")).is_ok(), "same data");
		assert!(agrees(&done, read(b"ho")).is_err(), "different data");
		assert!(agrees(&done, Err(String::from("refused"))).is_err(), "fastlane accepts what hyper refuses");
		assert!(agrees(&stopped, read(b"")).is_err(), "fastlane refuses what hyper accepts");
		assert!(agrees(&stopped, Err(String::from("refused"))).is_ok(), "both refuse");
	}
}
