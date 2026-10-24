//! Fuzz harnesses for Reduction's untrusted ingress boundary. Each takes raw bytes and asserts the boundary's
//! invariant; the libFuzzer targets (fuzz_targets/) and the stable replay test (src/replay.rs) both call them.

#[cfg(test)]
mod replay;

use reduction::ingress::protocol::{self, Envelope};

/// Any input is refused with an Err or decodes to an Envelope that round-trips exactly; a panic or abort is the bug.
pub fn envelope_decode(data: &[u8]) {
	let Ok(envelope) = protocol::decode(data) else {
		return;
	};
	let frame = protocol::encode(&envelope);
	assert!(frame.is_ok(), "a decoded envelope must re-encode under the frame cap");
	let Ok(frame) = frame else {
		return;
	};
	let again = protocol::decode(&frame);
	assert!(again.is_ok(), "a re-encoded envelope must decode");
	let Ok(again) = again else {
		return;
	};
	let again: Envelope = again;
	assert_eq!(again, envelope, "decode -> encode -> decode must be the identity");
}
