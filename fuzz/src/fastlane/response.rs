//! The `fastlane_response` target: raw backend bytes through fastlane's response-head parser and body framing.
//! hyper's client must read the same status and body. The head fastlane writes for the client, with the body
//! framed as its Encode says, must read back through hyper to that same status and body.

use http::Method;
use reduction::proxy::handler::fastlane::response::{Decode, Encode, ParsedHead, RequestMethod, ResponseFacts, parse_response};
use reduction::reserved_headers::HOP_BY_HOP_HEADERS;

use super::chunked::{self, Decoded, Outcome};
use crate::oracle::{self, ClientRead};

// Room for every backend field the head keeps, past fastlane's own 100-field cap.
const MAX_CLIENT_FIELDS: usize = 128;
// fastlane refuses these on purpose where hyper's client reads on; hyper's proxy path refuses them later.
const DELIBERATE_REFUSALS: [&str; 2] = ["unrequested protocol switch", "conflicting Content-Length beside Transfer-Encoding"];
const BLANK_LINE: &[u8] = b"\r\n";
const LAST_CHUNK: &[u8] = b"0\r\n\r\n";

/// What fastlane relays: the final head's facts, the head it writes for the client, and the decoded body.
#[derive(Debug)]
pub struct Relayed {
	pub facts: ResponseFacts,
	pub client_head: Vec<u8>,
	pub body: Vec<u8>,
	/// The fields the final backend head's Connection nominates, which the client head must not keep.
	pub nominated: Vec<String>,
}

// Skip interim heads, parse the final one, then frame the body by its Decode as the relay does.
fn relay(method: RequestMethod, backend: &[u8]) -> Result<Relayed, String> {
	let mut at: usize = 0;
	let mut client_head: Vec<u8> = Vec::new();
	let (facts, final_at): (ResponseFacts, usize) = loop {
		let start: usize = at;
		let (parsed, len) = parse_response(&backend[at..], method, &mut client_head).map_err(|e| return e.to_string())?;
		at += len;
		match parsed {
			ParsedHead::Final(facts) => break (facts, start),
			ParsedHead::Informational => {}
			ParsedHead::Partial => return Err(String::from("the head ends at EOF")),
		}
	};
	let nominated: Vec<String> = nominated(&backend[final_at..at]);
	let rest: &[u8] = &backend[at..];
	let body: Vec<u8> = match facts.decode {
		Decode::Empty => Vec::new(),
		Decode::Length(len) => {
			let len: usize = usize::try_from(len).map_err(|e| return e.to_string())?;
			rest.get(..len).ok_or("EOF inside a sized body")?.to_vec()
		}
		Decode::Chunked => {
			let decoded: Decoded = chunked::decode(rest, rest.len());
			if decoded.outcome != Outcome::Done {
				return Err(format!("chunked body stopped {:?}", decoded.outcome));
			}
			decoded.data
		}
		Decode::UntilClose => rest.to_vec(),
	};
	return Ok(Relayed { facts, client_head, body, nominated });
}

// The lowercase field names that the Connection fields of `head` nominate; strip_hop_by_hop_headers removes them.
fn nominated(head: &[u8]) -> Vec<String> {
	let mut fields: [httparse::Header<'_>; MAX_CLIENT_FIELDS] = [httparse::EMPTY_HEADER; MAX_CLIENT_FIELDS];
	let mut parsed: httparse::Response<'_, '_> = httparse::Response::new(&mut fields);
	if parsed.parse(head).is_err() {
		return Vec::new();
	}
	return parsed
		.headers
		.iter()
		.filter(|field: &&httparse::Header<'_>| return field.name.eq_ignore_ascii_case("connection"))
		.filter_map(|field: &httparse::Header<'_>| return str::from_utf8(field.value).ok())
		.flat_map(|value: &str| return value.split(','))
		.map(|token: &str| return token.trim().to_ascii_lowercase())
		.filter(|token: &String| return !token.is_empty())
		.collect();
}

// Re-frame `body` as `encode` tells the client, as the relay writes it.
fn framed_body(encode: Encode, body: &[u8]) -> Vec<u8> {
	return match encode {
		Encode::Empty => Vec::new(),
		Encode::Length(_) | Encode::UntilClose => body.to_vec(),
		Encode::Chunked if body.is_empty() => LAST_CHUNK.to_vec(),
		Encode::Chunked => [format!("{:x}\r\n", body.len()).as_bytes(), body, BLANK_LINE, LAST_CHUNK].concat(),
	};
}

fn is_length_list_of(value: &[u8], len: u64) -> bool {
	return str::from_utf8(value).is_ok_and(|text: &str| {
		return text.split(',').all(|item: &str| return item.trim().parse::<u64>() == Ok(len));
	});
}

// The client head is one well-formed head, with no hop-by-hop field and exactly the framing field its Encode needs.
fn check_client_head(relayed: &Relayed) -> Result<(), String> {
	let head: Vec<u8> = [relayed.client_head.as_slice(), BLANK_LINE].concat();
	let mut fields: [httparse::Header<'_>; MAX_CLIENT_FIELDS] = [httparse::EMPTY_HEADER; MAX_CLIENT_FIELDS];
	let mut parsed: httparse::Response<'_, '_> = httparse::Response::new(&mut fields);
	match parsed.parse(&head) {
		Ok(httparse::Status::Complete(len)) if len == head.len() => {}
		other => return Err(format!("the client head does not parse as one head: {other:?}")),
	}
	if parsed.code != Some(relayed.facts.status.as_u16()) {
		return Err(format!("the client head carries status {:?}, not {}", parsed.code, relayed.facts.status));
	}
	let named = |name: &str| -> Vec<&[u8]> {
		return parsed.headers.iter().filter(|f| return f.name.eq_ignore_ascii_case(name)).map(|f| return f.value).collect();
	};
	let lengths: Vec<&[u8]> = named("content-length");
	let codings: Vec<&[u8]> = named("transfer-encoding");
	let is_framed: bool = match relayed.facts.encode {
		Encode::Length(len) => codings.is_empty() && lengths.len() == 1 && is_length_list_of(lengths[0], len),
		Encode::Chunked => lengths.is_empty() && codings == [&b"chunked"[..]],
		Encode::UntilClose => lengths.is_empty() && codings.is_empty(),
		Encode::Empty => lengths.len() <= 1 && codings.is_empty(),
	};
	if !is_framed {
		return Err(format!("{:?} framed by lengths {lengths:?} and codings {codings:?}", relayed.facts.encode));
	}
	// The framing fields are fastlane's own, checked above, so only the rest must be stripped.
	let hop: Option<&httparse::Header<'_>> = parsed.headers.iter().find(|field| {
		let is_framing: bool =
			field.name.eq_ignore_ascii_case("transfer-encoding") || field.name.eq_ignore_ascii_case("content-length");
		let is_fixed_hop: bool = HOP_BY_HOP_HEADERS.iter().any(|name| return name.as_str().eq_ignore_ascii_case(field.name));
		let is_nominated: bool = relayed.nominated.iter().any(|name: &String| return name.eq_ignore_ascii_case(field.name));
		return !is_framing && (is_fixed_hop || is_nominated);
	});
	return hop.map_or(Ok(()), |field| return Err(format!("the client head keeps hop-by-hop field {}", field.name)));
}

fn is_deliberate(refusal: &str) -> bool {
	return DELIBERATE_REFUSALS.iter().any(|reason: &&str| return refusal.contains(reason));
}

// The differential verdict on the backend read: the same status and body as hyper, or both refuse.
fn agrees(relayed: &Result<Relayed, String>, hyper: &Result<ClientRead, String>) -> Result<(), String> {
	return match (relayed, hyper) {
		(Ok(ours), Ok(read)) if ours.facts.status == read.status && ours.body == read.body => Ok(()),
		(Ok(ours), other) => Err(format!("fastlane relays {} {:?}, hyper read {other:?}", ours.facts.status, ours.body)),
		(Err(refusal), Ok(read)) if !is_deliberate(refusal) => Err(format!("fastlane refused ({refusal}), hyper read {read:?}")),
		(Err(_), _) => Ok(()),
	};
}

/// The invariant. The first byte's low bit picks HEAD or GET, and the rest is what the backend sends.
pub fn check(data: &[u8]) -> Result<(), String> {
	let Some((&selector, backend)) = data.split_first() else {
		return Ok(());
	};
	let (method, ours): (Method, RequestMethod) =
		if selector & 1 == 1 { (Method::HEAD, RequestMethod::Head) } else { (Method::GET, RequestMethod::Other) };
	let relayed: Result<Relayed, String> = relay(ours, backend);
	agrees(&relayed, &oracle::client_read(&method, backend)?)?;
	let Ok(relayed) = relayed else {
		return Ok(());
	};
	check_client_head(&relayed)?;
	// A chunked body whose decoded size differs from a length beside it is the relay's to cut short, not the head's.
	if matches!(relayed.facts.encode, Encode::Length(len) if usize::try_from(len) != Ok(relayed.body.len())) {
		return Ok(());
	}
	let client: Vec<u8> = [&relayed.client_head, BLANK_LINE, &framed_body(relayed.facts.encode, &relayed.body)].concat();
	let expected: Result<ClientRead, String> = Ok(ClientRead {
		status: relayed.facts.status,
		body: relayed.body.into(),
	});
	let reread: Result<ClientRead, String> = oracle::client_read(&method, &client)?;
	if reread != expected {
		return Err(format!("the client head {:?} reads back as {reread:?}", String::from_utf8_lossy(&relayed.client_head)));
	}
	return Ok(());
}

#[cfg(test)]
mod tests {
	use bytes::Bytes;
	use http::StatusCode;

	use super::*;

	const AGREED: [&[u8]; 6] = [
		b"\x00HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: x-hop\r\nX-Hop: 1\r\n\r\nhello",
		b"\x00HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n",
		b"\x00HTTP/1.1 200 OK\r\n\r\nuntil close",
		b"\x00HTTP/1.0 200 OK\r\n\r\nold",
		b"\x01HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n",
		b"\x00HTTP/1.1 304 Not Modified\r\nContent-Length: 7\r\n\r\n",
	];

	#[test]
	fn responses_hyper_reads_agree_and_read_back() -> Result<(), String> {
		AGREED.iter().try_for_each(|data: &&[u8]| return check(data))?;
		let relayed: Relayed = relay(RequestMethod::Other, &AGREED[1][1..])?;
		assert_eq!((relayed.facts.decode, relayed.body.as_slice()), (Decode::Chunked, &b"hi"[..]), "not vacuous");
		return Ok(());
	}

	#[test]
	fn refusals_pass_when_hyper_refuses_or_the_refusal_is_deliberate() -> Result<(), String> {
		// The body covers either length, so a parser that picks one relays it and fails the differential.
		check(b"\x00HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!")?;
		check(b"\x00HTTP/1.1 200 OK\r\nContent-Length: 6, 5\r\n\r\nhello!")?;
		check(b"\x00HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort")?;
		check(b"\x00HTTP/1.1 101 Switching Protocols\r\n\r\n")?;
		assert!(relay(RequestMethod::Other, b"HTTP/1.1 101 Switching Protocols\r\n\r\n").is_err(), "101 is refused");
		return Ok(());
	}

	// Negative controls: a different body, a one-sided acceptance and a malformed client head each fail.
	#[test]
	fn every_disagreement_fails() -> Result<(), String> {
		let ours: Relayed = relay(RequestMethod::Other, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")?;
		let read = |body: &'static [u8]| -> Result<ClientRead, String> {
			return Ok(ClientRead { status: StatusCode::OK, body: Bytes::from_static(body) });
		};
		assert!(agrees(&Ok(ours), &read(b"ho")).is_err(), "different body");
		assert!(agrees(&Err(String::from("parse response head: bad")), &read(b"hi")).is_err(), "one-sided refusal");
		assert!(agrees(&Err(String::from("unrequested protocol switch")), &read(b"")).is_ok(), "deliberate refusal");
		let mut broken: Relayed = relay(RequestMethod::Other, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")?;
		broken.client_head.extend_from_slice(b"Keep-Alive: 5\r\n");
		assert!(check_client_head(&broken).is_err(), "a hop-by-hop field in the client head");
		broken.facts.encode = Encode::Chunked;
		assert!(check_client_head(&broken).is_err(), "a length where the client expects chunks");
		let mut leaked: Relayed = relay(RequestMethod::Other, &AGREED[0][1..])?;
		assert_eq!(leaked.nominated, ["x-hop"], "the backend's Connection nominates X-Hop");
		check_client_head(&leaked)?;
		leaked.client_head.extend_from_slice(b"X-Hop: 1\r\n");
		assert!(check_client_head(&leaked).is_err(), "a nominated field in the client head");
		return Ok(());
	}
}
