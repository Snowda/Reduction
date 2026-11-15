//! The `fastlane_classify` target: raw client bytes through fastlane's request classifier. A head it takes for
//! the raw plane must be one hyper's server accepts with the same method, target, version and body length.
//! On the HTTP/1.1 plane, the upstream template must carry the fields the hyper path forwards, no more, no less.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use http::header::HOST;
use http::{HeaderMap, HeaderName, HeaderValue, Version};
use reduction::proxy::ProxyState;
use reduction::proxy::handler::fastlane::fields::{peer_fields, peer_headers};
use reduction::proxy::handler::fastlane::request::{ClassifyInput, Classified, Plane, RequestFacts, Template, classify};
use reduction::proxy::handler::headers::{apply_forwarded_headers, apply_identity_headers, strip_hop_by_hop_headers};
use reduction::transport::ConnectAddr;

use crate::oracle::{self, ServerRead};

const CLIENT_PORT: u16 = 40_000;
const CLIENT_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
// Room for fastlane's 100-field cap plus the peer fields it appends.
const MAX_TEMPLATE_FIELDS: usize = 128;
const BLANK_LINE: &[u8] = b"\r\n";

/// One forwarded field as the backend reads it: the lowercase name and the value bytes.
type Field = (String, Vec<u8>);

// The fields in wire order do not matter to a backend, so both sides compare sorted.
fn sorted(mut fields: Vec<Field>) -> Vec<Field> {
	fields.sort_unstable();
	return fields;
}

// What hyper's path forwards from the parsed head: forward_request's rewrite, without the backend Host it adds.
fn hyper_forwarded(served: &ServerRead) -> Result<Vec<Field>, String> {
	let mut headers: HeaderMap = served.headers.clone();
	strip_hop_by_hop_headers(&mut headers);
	headers.remove(HOST);
	apply_forwarded_headers(&mut headers, CLIENT_IP).map_err(|e| return e.to_string())?;
	apply_identity_headers(&mut headers, None).map_err(|e| return e.to_string())?;
	let fields: Vec<Field> = headers
		.iter()
		.map(|(name, value): (&HeaderName, &HeaderValue)| return (name.as_str().to_owned(), value.as_bytes().to_vec()))
		.collect();
	return Ok(sorted(fields));
}

// The template must parse as a request head of the same method and target, holding exactly hyper's fields.
fn check_template(template: &[u8], served: &ServerRead) -> Result<(), String> {
	let head: Vec<u8> = [template, BLANK_LINE].concat();
	let mut fields: [httparse::Header<'_>; MAX_TEMPLATE_FIELDS] = [httparse::EMPTY_HEADER; MAX_TEMPLATE_FIELDS];
	let mut parsed: httparse::Request<'_, '_> = httparse::Request::new(&mut fields);
	match parsed.parse(&head) {
		Ok(httparse::Status::Complete(len)) if len == head.len() => {}
		other => return Err(format!("the template does not parse as one head: {other:?}")),
	}
	if (parsed.method, parsed.path, parsed.version) != (Some(served.method.as_str()), Some(served.target.as_str()), Some(1)) {
		return Err(format!("template line {:?} {:?} 1.{:?}", parsed.method, parsed.path, parsed.version));
	}
	let ours: Vec<Field> = sorted(
		parsed
			.headers
			.iter()
			.map(|field: &httparse::Header<'_>| return (field.name.to_ascii_lowercase(), field.value.to_vec()))
			.collect(),
	);
	let hyper: Vec<Field> = hyper_forwarded(served)?;
	if ours != hyper {
		return Err(format!("the template forwards {ours:?}, the hyper path forwards {hyper:?}"));
	}
	return Ok(());
}

// The differential verdict on a Ready head: hyper's server parsed it to the same request line and body length.
fn agrees(facts: &RequestFacts, served: Option<&ServerRead>) -> Result<(), String> {
	let Some(served) = served else {
		return Err(format!("fastlane serves a {} head that hyper's server refuses", facts.method));
	};
	let body_len: Option<u64> = u64::try_from(facts.body_len).ok();
	if served.method != facts.method || served.version != Version::HTTP_11 || served.body_len != body_len {
		return Err(format!(
			"fastlane read {} with a {}-byte body, hyper read {} {:?} with {:?}",
			facts.method, facts.body_len, served.method, served.version, served.body_len
		));
	}
	return Ok(());
}

/// The invariant for `client` on a connection whose `/` route `state` sends to one TLS backend.
/// Partial and Handoff leave every byte to hyper, so only a Ready head can diverge.
pub fn check(state: &ProxyState, client: &[u8]) -> Result<(), String> {
	let peer: ConnectAddr = ConnectAddr(SocketAddr::new(CLIENT_IP, CLIENT_PORT), None);
	let fields: Vec<u8> = peer_fields(peer).ok_or("loopback peer fields")?;
	let headers: HeaderMap = peer_headers(&fields).ok_or("loopback peer headers")?;
	let input: ClassifyInput<'_> = ClassifyInput {
		state,
		listener: None,
		peer,
		peer_fields: &fields,
		peer_headers: &headers,
	};
	let mut template: Template = Template::default();
	let Classified::Ready(facts) = classify(client, &input, &mut template) else {
		return Ok(());
	};
	if facts.head_len == 0 || facts.head_len > client.len() {
		return Err(format!("head length {} of a {}-byte input", facts.head_len, client.len()));
	}
	let served: Option<ServerRead> = oracle::server_read(client)?;
	agrees(&facts, served.as_ref())?;
	return match (facts.plane, served) {
		(Plane::H1, Some(served)) => check_template(&template.h1, &served),
		_ => Ok(()),
	};
}

#[cfg(test)]
mod tests {
	use http::Method;

	use super::*;
	use crate::fixture::{self, Fixture};

	const READY: [&[u8]; 4] = [
		b"GET /a?b=1 HTTP/1.1\r\nHost: front\r\nX-Forwarded-For: 6.6.6.6\r\nAccept: */*\r\n\r\n",
		b"POST /echo HTTP/1.1\r\nContent-Length: 3\r\nConnection: close, X-Hop\r\nX-Hop: 1\r\nX-M: a\r\nX-M: b\r\n\r\nabc",
		b"PUT /p HTTP/1.1\r\nconnection: keep-alive\r\nkeep-alive: 5\r\ncontent-length: 0\r\n\r\n",
		b"DELETE /d HTTP/1.1\r\nX-Reduction-Client-Id: forged\r\nTE: trailers\r\n\r\n",
	];

	// Each head must reach the raw plane on both states, or the differential checks nothing.
	#[test]
	fn plain_heads_are_ready_on_both_planes_and_agree_with_hyper() -> Result<(), String> {
		let fixture: &Fixture = fixture::get()?;
		let peer: ConnectAddr = ConnectAddr(SocketAddr::new(CLIENT_IP, CLIENT_PORT), None);
		let fields: Vec<u8> = peer_fields(peer).ok_or("peer fields")?;
		let headers: HeaderMap = peer_headers(&fields).ok_or("peer headers")?;
		return [fixture.raw.h1, fixture.raw.h2].iter().try_for_each(|state: &&'static ProxyState| {
			let input: ClassifyInput<'_> = ClassifyInput { state, listener: None, peer, peer_fields: &fields, peer_headers: &headers };
			return READY.iter().try_for_each(|client: &&[u8]| {
				let mut template: Template = Template::default();
				let is_ready: bool = matches!(classify(client, &input, &mut template), Classified::Ready(_));
				assert!(is_ready, "{:?} must take the raw plane", String::from_utf8_lossy(client));
				return check(state, client);
			});
		});
	}

	// Negative controls: a template that adds, drops or changes a field, or a refused head, each fail.
	#[test]
	fn every_disagreement_with_hyper_fails() -> Result<(), String> {
		let served: ServerRead = oracle::server_read(READY[1])?.ok_or("hyper refused a valid POST")?;
		let good: &[u8] = b"POST /echo HTTP/1.1\r\ncontent-length: 3\r\nx-m: a\r\nx-m: b\r\nx-forwarded-for: 127.0.0.1\r\nx-real-ip: 127.0.0.1\r\n";
		check_template(good, &served)?;
		let dropped: &[u8] = b"POST /echo HTTP/1.1\r\ncontent-length: 3\r\nx-m: a\r\nx-forwarded-for: 127.0.0.1\r\nx-real-ip: 127.0.0.1\r\n";
		assert!(check_template(dropped, &served).is_err(), "a dropped field");
		let leaked: Vec<u8> = [good, b"x-hop: 1\r\n"].concat();
		assert!(check_template(&leaked, &served).is_err(), "a nominated field forwarded");
		let retargeted: Vec<u8> = [b"POST /other".as_slice(), &good[b"POST /echo".len()..]].concat();
		assert!(check_template(&retargeted, &served).is_err(), "a changed target");
		let fixture: &Fixture = fixture::get()?;
		let peer: ConnectAddr = ConnectAddr(SocketAddr::new(CLIENT_IP, CLIENT_PORT), None);
		let fields: Vec<u8> = peer_fields(peer).ok_or("peer fields")?;
		let headers: HeaderMap = peer_headers(&fields).ok_or("peer headers")?;
		let input: ClassifyInput<'_> = ClassifyInput { state: fixture.raw.h1, listener: None, peer, peer_fields: &fields, peer_headers: &headers };
		let Classified::Ready(facts) = classify(READY[1], &input, &mut Template::default()) else {
			return Err(String::from("the POST must be Ready"));
		};
		assert!(agrees(&facts, None).is_err(), "a head hyper refuses");
		let mut other: ServerRead = served;
		other.method = Method::PUT;
		assert!(agrees(&facts, Some(&other)).is_err(), "a different method");
		return Ok(());
	}
}
