use super::{
	ACCEPT_ENCODING, Arc, ArrayString, Body, CONTENT_ENCODING, COOKIE, CacheDirectives, CacheKeyRef,
	Method, PeerIdentity, ProxyState, RANGE, Request, Response, SPKI_HEX_LEN, maybe_compress,
};

// Serve a cached response when caching applies and the per-identity key hits; a hit is compressed like a fresh
// miss. None = skipped or a (counted) miss; range/cookie requests bypass to avoid the wrong representation.
pub fn try_serve_from_cache(
	state: &Arc<ProxyState>,
	req: &Request<Body>,
	cache_identity: &str,
	accepts_zstd: bool,
	is_cacheable_method: bool,
	request_has_cookie: bool,
	request_has_range: bool,
) -> Option<Response<Body>> {
	let cache_lookup_applies: bool =
		state.cache_config.enabled && is_cacheable_method && !request_has_cookie && !request_has_range;
	if !cache_lookup_applies {
		return None;
	}
	let path: &str = req
		.uri()
		.path_and_query()
		.map(|pq| pq.as_str())
		.unwrap_or(req.uri().path());
	let key: CacheKeyRef<'_> = CacheKeyRef {
		method: req.method().as_str(),
		path,
		identity: cache_identity,
	};
	if let Some(cached) = state.response_cache.get(key) {
		state.metrics.cache_hits.add(1, &[]);
		let directives: CacheDirectives = CacheDirectives::from_response(&cached);
		return Some(maybe_compress(
			cached,
			accepts_zstd,
			&directives,
			&state.compression_config,
		));
	}
	state.metrics.cache_misses.add(1, &[]);
	return None;
}

// Cache-relevant request flags computed once and threaded into the retry loop (cacheability, compression, cookie, identity hex).
pub struct CacheNegotiation {
	pub is_cacheable_method: bool,
	pub accepts_zstd: bool,
	pub request_is_zstd: bool,
	pub request_has_cookie: bool,
	pub cache_identity_hex: Option<ArrayString<SPKI_HEX_LEN>>,
}

// A cache hit (ready to return) or a miss carrying the negotiation flags the rest of the pipeline needs.
pub enum CacheDecision {
	Hit(Response<Body>),
	Miss(CacheNegotiation),
}

// Compute cache-negotiation flags and attempt to serve from cache: range/cookie/non-cacheable bypass the store;
// a hit returns the stored response, a miss returns the flags for the forward path.
pub fn negotiate_cache(state: &Arc<ProxyState>, req: &Request<Body>, client_identity: Option<&PeerIdentity>) -> CacheDecision {
	let is_cacheable_method: bool = req.method() == Method::GET || req.method() == Method::HEAD;

	// Compression negotiation headers, captured before the request body is consumed.
	let accepts_zstd: bool = req
		.headers()
		.get(ACCEPT_ENCODING)
		.and_then(|v| v.to_str().ok())
		.map(|v| v.contains("zstd"))
		.unwrap_or(false);
	let request_is_zstd: bool = req
		.headers()
		.get(CONTENT_ENCODING)
		.and_then(|v| v.to_str().ok())
		.map(|v| v == "zstd")
		.unwrap_or(false);

	// Keyed per client identity so one device's response is never served to another; the empty-string fallback is defensive (peers are identified before routing).
	let cache_identity_hex: Option<ArrayString<SPKI_HEX_LEN>> = client_identity.map(PeerIdentity::spki_hex);
	let cache_identity: &str = cache_identity_hex.as_deref().unwrap_or("");
	// Cookie sessions and range requests bypass the cache (cross-session safety; Range is not a key dimension).
	let request_has_cookie: bool = req.headers().contains_key(COOKIE);
	let request_has_range: bool = req.headers().contains_key(RANGE);

	if let Some(response) = try_serve_from_cache(
		state,
		req,
		cache_identity,
		accepts_zstd,
		is_cacheable_method,
		request_has_cookie,
		request_has_range,
	) {
		return CacheDecision::Hit(response);
	}
	return CacheDecision::Miss(CacheNegotiation {
		is_cacheable_method,
		accepts_zstd,
		request_is_zstd,
		request_has_cookie,
		cache_identity_hex,
	});
}

#[cfg(test)]
mod tests {
	use std::collections::HashMap;
	use std::num::{NonZeroU64, NonZeroUsize};
	use std::sync::Arc;

	use arrayvec::ArrayString;
	use axum::body::Body;
	use axum::http::{HeaderMap, Request, StatusCode};
	use bytes::Bytes;
	use http_body_util::BodyExt;

	use super::{CacheDecision, PeerIdentity, ProxyState, negotiate_cache, try_serve_from_cache};
	use crate::acl::AccessControl;
	use crate::cache::CacheKeyRef;
	use crate::cache_control::CacheDirectives;
	use crate::config::{CacheConfig, TimeoutConfig};
	use crate::proxy::handler::{ReloadableState, TestProxyStateParams};
	use crate::proxy::router::Router;
	use crate::tls::SPKI_HEX_LEN;
	use crate::tunnel::revocation::RevocationSet;

	// A body comfortably over the 256-byte compression floor, so an accepts-zstd hit is actually encoded.
	const COMPRESSIBLE_BODY_LEN: usize = 512;

	fn install_crypto() {
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
	}

	fn client_config() -> Arc<rustls::ClientConfig> {
		return Arc::new(
			rustls::ClientConfig::builder()
				.with_root_certificates(rustls::RootCertStore::empty())
				.with_no_client_auth(),
		);
	}

	fn cache_off() -> CacheConfig {
		return CacheConfig {
			enabled: false,
			..CacheConfig::default()
		};
	}

	fn cache_on() -> CacheConfig {
		return CacheConfig {
			enabled: true,
			max_entries: NonZeroUsize::new(100).unwrap(),
			max_entry_bytes: NonZeroUsize::new(1024 * 1024).unwrap(),
			default_ttl_secs: NonZeroU64::new(300).unwrap(),
		};
	}

	fn make_state(cache: CacheConfig) -> Arc<ProxyState> {
		install_crypto();
		let reloadable: ReloadableState = ReloadableState {
			router: Router::new(&[]),
			backend_pools: HashMap::new(),
			acl: AccessControl::new(vec![], vec![]),
		};
		return ProxyState::for_test(TestProxyStateParams {
			cache_config: cache,
			..TestProxyStateParams::new(reloadable, RevocationSet::default(), client_config(), TimeoutConfig::default())
		});
	}

	fn get(uri: &str) -> Request<Body> {
		return Request::builder().method("GET").uri(uri).body(Body::empty()).unwrap();
	}

	// A parseable-free PeerIdentity built from its public fields; spki_hex() is deterministic from the bytes.
	fn identity() -> PeerIdentity {
		return PeerIdentity {
			common_name: ArrayString::from("dev").unwrap(),
			spki_sha256: [7u8; 32],
		};
	}

	// Store one entry under (method, path, identity) so a later lookup with the same key hits.
	fn seed_cache(state: &Arc<ProxyState>, method: &str, path: &str, identity: &str, body: &[u8]) {
		let key: CacheKeyRef<'_> = CacheKeyRef { method, path, identity };
		state
			.response_cache
			.put(key, StatusCode::OK, &HeaderMap::new(), Bytes::copy_from_slice(body), &CacheDirectives::default());
	}

	// --- try_serve_from_cache --------------------------------------------------------------------

	#[test]
	fn try_serve_returns_none_when_cache_disabled() {
		let state: Arc<ProxyState> = make_state(cache_off());
		let req: Request<Body> = get("/x");
		assert!(try_serve_from_cache(&state, &req, "", false, true, false, false).is_none());
	}

	#[test]
	fn try_serve_returns_none_for_non_cacheable_method() {
		let state: Arc<ProxyState> = make_state(cache_on());
		let req: Request<Body> = get("/x");
		assert!(try_serve_from_cache(&state, &req, "", false, false, false, false).is_none());
	}

	#[test]
	fn try_serve_returns_none_when_request_has_cookie() {
		let state: Arc<ProxyState> = make_state(cache_on());
		let req: Request<Body> = get("/x");
		assert!(try_serve_from_cache(&state, &req, "", false, true, true, false).is_none());
	}

	#[test]
	fn try_serve_returns_none_when_request_has_range() {
		let state: Arc<ProxyState> = make_state(cache_on());
		let req: Request<Body> = get("/x");
		assert!(try_serve_from_cache(&state, &req, "", false, true, false, true).is_none());
	}

	#[test]
	fn try_serve_returns_none_on_cache_miss() {
		let state: Arc<ProxyState> = make_state(cache_on());
		let req: Request<Body> = get("/absent");
		assert!(try_serve_from_cache(&state, &req, "", false, true, false, false).is_none(), "empty cache misses");
	}

	#[tokio::test]
	async fn try_serve_returns_stored_body_on_hit() {
		let state: Arc<ProxyState> = make_state(cache_on());
		seed_cache(&state, "GET", "/hit", "", b"cached");
		let req: Request<Body> = get("/hit");

		let served = try_serve_from_cache(&state, &req, "", false, true, false, false);

		match served {
			Some(response) => {
				assert_eq!(response.status(), StatusCode::OK);
				let bytes: Bytes = response.into_body().collect().await.unwrap().to_bytes();
				assert_eq!(&bytes[..], b"cached", "a hit returns the stored body unencoded when zstd is not accepted");
			}
			None => panic!("a populated key must hit the cache"),
		}
	}

	#[tokio::test]
	async fn try_serve_compresses_hit_when_client_accepts_zstd() {
		let state: Arc<ProxyState> = make_state(cache_on());
		let body: Vec<u8> = vec![b'a'; COMPRESSIBLE_BODY_LEN];
		seed_cache(&state, "GET", "/z", "", &body);
		let req: Request<Body> = get("/z");

		let served = try_serve_from_cache(&state, &req, "", true, true, false, false);

		match served {
			Some(response) => assert_eq!(
				response.headers().get("content-encoding").map(|v| v.to_str().unwrap()),
				Some("zstd"),
				"an accepts-zstd hit over the size floor is compressed"
			),
			None => panic!("the populated key must hit"),
		}
	}

	#[tokio::test]
	async fn try_serve_keys_on_path_and_query() {
		// Two requests differing only in query string must resolve to distinct cache keys, so a hit for
		// one is a miss for the other — proving the key uses path_and_query, not just the path.
		let state: Arc<ProxyState> = make_state(cache_on());
		seed_cache(&state, "GET", "/p?v=1", "", b"one");
		let hit: Request<Body> = get("/p?v=1");
		let miss: Request<Body> = get("/p?v=2");

		assert!(try_serve_from_cache(&state, &hit, "", false, true, false, false).is_some(), "exact query hits");
		assert!(try_serve_from_cache(&state, &miss, "", false, true, false, false).is_none(), "a different query misses");
	}

	#[tokio::test]
	async fn try_serve_keys_on_identity() {
		// The same URL cached under one identity must not be served to another — the cross-device guard.
		let state: Arc<ProxyState> = make_state(cache_on());
		seed_cache(&state, "GET", "/u", "device-a", b"a-body");
		let req: Request<Body> = get("/u");

		assert!(try_serve_from_cache(&state, &req, "device-a", false, true, false, false).is_some());
		assert!(
			try_serve_from_cache(&state, &req, "device-b", false, true, false, false).is_none(),
			"a different identity must not read device-a's entry"
		);
	}

	// --- negotiate_cache -------------------------------------------------------------------------

	#[test]
	fn negotiate_returns_miss_with_default_flags_for_plain_get() {
		let state: Arc<ProxyState> = make_state(cache_on());
		let req: Request<Body> = get("/x");

		match negotiate_cache(&state, &req, None) {
			CacheDecision::Miss(n) => {
				assert!(n.is_cacheable_method, "GET is cacheable");
				assert!(!n.accepts_zstd);
				assert!(!n.request_is_zstd);
				assert!(!n.request_has_cookie);
				assert!(n.cache_identity_hex.is_none(), "no identity yields no key dimension");
			}
			CacheDecision::Hit(_) => panic!("an empty cache cannot hit"),
		}
	}

	#[test]
	fn negotiate_marks_head_cacheable() {
		let state: Arc<ProxyState> = make_state(cache_on());
		let req: Request<Body> = Request::builder().method("HEAD").uri("/x").body(Body::empty()).unwrap();

		match negotiate_cache(&state, &req, None) {
			CacheDecision::Miss(n) => assert!(n.is_cacheable_method, "HEAD is cacheable"),
			CacheDecision::Hit(_) => panic!("empty cache"),
		}
	}

	#[test]
	fn negotiate_marks_post_non_cacheable() {
		let state: Arc<ProxyState> = make_state(cache_on());
		let req: Request<Body> = Request::builder().method("POST").uri("/x").body(Body::empty()).unwrap();

		match negotiate_cache(&state, &req, None) {
			CacheDecision::Miss(n) => assert!(!n.is_cacheable_method, "POST is not cacheable"),
			CacheDecision::Hit(_) => panic!("empty cache"),
		}
	}

	#[test]
	fn negotiate_detects_accept_and_content_encoding() {
		let state: Arc<ProxyState> = make_state(cache_on());
		let req: Request<Body> = Request::builder()
			.method("GET")
			.uri("/x")
			.header("accept-encoding", "gzip, zstd")
			.header("content-encoding", "zstd")
			.body(Body::empty())
			.unwrap();

		match negotiate_cache(&state, &req, None) {
			CacheDecision::Miss(n) => {
				assert!(n.accepts_zstd, "accept-encoding advertising zstd is detected");
				assert!(n.request_is_zstd, "a zstd-encoded request body is detected");
			}
			CacheDecision::Hit(_) => panic!("empty cache"),
		}
	}

	#[test]
	fn negotiate_detects_cookie_and_bypasses_cache() {
		let state: Arc<ProxyState> = make_state(cache_on());
		// Seed a matching entry: the cookie must force a Miss even though the key would otherwise hit.
		seed_cache(&state, "GET", "/c", "", b"body");
		let req: Request<Body> = Request::builder()
			.method("GET")
			.uri("/c")
			.header("cookie", "sid=abc")
			.body(Body::empty())
			.unwrap();

		match negotiate_cache(&state, &req, None) {
			CacheDecision::Miss(n) => assert!(n.request_has_cookie, "a cookie request bypasses the cache to a Miss"),
			CacheDecision::Hit(_) => panic!("a cookie-bearing request must never be served from cache"),
		}
	}

	#[test]
	fn negotiate_carries_identity_hex_when_present() {
		let state: Arc<ProxyState> = make_state(cache_on());
		let req: Request<Body> = get("/x");
		let id: PeerIdentity = identity();

		match negotiate_cache(&state, &req, Some(&id)) {
			CacheDecision::Miss(n) => {
				let hex = n.cache_identity_hex.expect("an identity yields its spki hex");
				assert_eq!(hex.len(), SPKI_HEX_LEN, "the hex is the full SPKI fingerprint");
				assert_eq!(hex.as_str(), id.spki_hex().as_str(), "the negotiated hex matches the identity");
			}
			CacheDecision::Hit(_) => panic!("empty cache"),
		}
	}

	#[tokio::test]
	async fn negotiate_returns_hit_for_populated_key() {
		let state: Arc<ProxyState> = make_state(cache_on());
		seed_cache(&state, "GET", "/h", "", b"stored");
		let req: Request<Body> = get("/h");

		match negotiate_cache(&state, &req, None) {
			CacheDecision::Hit(response) => {
				assert_eq!(response.status(), StatusCode::OK);
				let bytes: Bytes = response.into_body().collect().await.unwrap().to_bytes();
				assert_eq!(&bytes[..], b"stored");
			}
			CacheDecision::Miss(_) => panic!("a populated key must produce a Hit"),
		}
	}
}
