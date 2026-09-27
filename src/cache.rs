use std::borrow::Borrow;
use std::fmt::{self, Write};
use std::ops::Deref;
use std::time::{Duration, Instant};

use arrayvec::ArrayString;
use axum::body::Body;
use axum::http::{HeaderMap, Response, StatusCode};
use bytes::Bytes;
use lru::LruCache;
use parking_lot::Mutex;

use crate::cache_control::CacheDirectives;
use crate::config::CacheConfig;

// Response headers a shared cache must never store. Set-Cookie(2) would replay one request's session
// token on every hit for the whole TTL (RFC 6265 §8.3, RFC 7234 §8); the rest are hop-by-hop headers
// that describe a single connection, not the cached resource (RFC 7230 §6.1), and must not be resurrected
// on a later hit. Stored entries are stripped of these so a hit can never leak or replay them.
const UNCACHEABLE_HEADERS: [&str; 10] = [
	"set-cookie",
	"set-cookie2",
	"connection",
	"keep-alive",
	"proxy-authenticate",
	"proxy-authorization",
	"te",
	"trailer",
	"transfer-encoding",
	"upgrade",
];

// Clone `headers` minus the never-cache set, so the stored entry carries no session cookies or hop-by-hop
// headers to replay on a later hit. remove() drops all values for each name, so a repeated Set-Cookie is
// fully cleared, not just its first value.
fn sanitized_for_cache(headers: &HeaderMap) -> HeaderMap {
	let mut out: HeaderMap = headers.clone();
	for name in UNCACHEABLE_HEADERS {
		out.remove(name);
	}
	return out;
}

#[derive(Clone, Debug)]
struct CachedResponse {
	status: StatusCode,
	headers: HeaderMap,
	// Stored as Bytes so a cache hit clones by refcount rather than copying the whole body.
	body: Bytes,
	inserted_at: Instant,
	ttl: Duration,
}

impl CachedResponse {
	fn is_expired(&self) -> bool {
		return self.inserted_at.elapsed() > self.ttl;
	}
}

// Borrowed cache-key components a caller supplies for get/put. `identity` is the per-connection
// mTLS fingerprint (SPKI hex), or "" for an anonymous connection — keying on it prevents one device
// being served a response cached for another device.
#[derive(Clone, Copy, Debug)]
pub struct CacheKeyRef<'a> {
	pub method: &'a str,
	pub path: &'a str,
	pub identity: &'a str,
}

// Stack capacity for building a lookup key: covers a typical method + path + 64-char hex identity
// without touching the heap. A path past this cap falls back to a heap String (rare).
const CACHE_KEY_STACK_CAP: usize = 512;

// Injective length-prefixed join of the key parts: `<mlen>:<method><plen>:<path><ilen>:<identity>`.
// The length prefixes make it collision-proof for ANY content — a part may itself contain ':', digits,
// or control bytes without ambiguity — so two distinct (method, path, identity) triples can never share
// a key, which is what stops one device's cached response from ever being served to another. The joined
// string is never parsed back; it is only an opaque Hash/Eq token. One encoder is used by both the owned
// key and the lookup key so their bytes are identical.
fn write_cache_key<W: Write>(buf: &mut W, method: &str, path: &str, identity: &str) -> fmt::Result {
	return write!(
		buf,
		"{}:{}{}:{}{}:{}",
		method.len(),
		method,
		path.len(),
		path,
		identity.len(),
		identity,
	);
}

// Owned LRU key: the joined encoding in a single heap allocation. Deriving Hash over the one Box<str>
// field hashes as `str`, and Borrow<str> below yields the same bytes, so an owned key and a borrowed
// &str lookup hash and compare identically (the contract that lets LruCache::get take a borrowed key).
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct CacheKey(Box<str>);

impl From<CacheKeyRef<'_>> for CacheKey {
	fn from(key: CacheKeyRef<'_>) -> Self {
		let mut joined: String =
			String::with_capacity(key.method.len() + key.path.len() + key.identity.len() + CACHE_KEY_LEN_OVERHEAD);
		// Writing into a String is infallible.
		let _ = write_cache_key(&mut joined, key.method, key.path, key.identity);
		return Self(joined.into_boxed_str());
	}
}

impl Borrow<str> for CacheKey {
	fn borrow(&self) -> &str {
		return &self.0;
	}
}

// Slack for the three decimal length prefixes and their ':' markers when sizing the owned/heap buffers.
const CACHE_KEY_LEN_OVERHEAD: usize = 24;

// Lookup key built without heap for the common (bounded) case; a path past the stack cap falls back to a
// String. Never parsed — used only to borrow a &str for the LRU lookup.
// The Stack variant is intentionally large: it IS the stack buffer that lets a lookup avoid the heap, so
// boxing it (as clippy::large_enum_variant suggests) would reintroduce the very allocation we remove. The
// value is a short-lived local per get, never stored, so the size difference costs nothing.
#[allow(clippy::large_enum_variant)]
enum KeyBuf {
	Stack(ArrayString<CACHE_KEY_STACK_CAP>),
	Heap(String),
}

impl Deref for KeyBuf {
	type Target = str;
	fn deref(&self) -> &str {
		return match self {
			Self::Stack(s) => s.as_str(),
			Self::Heap(s) => s.as_str(),
		};
	}
}

fn build_lookup_key(method: &str, path: &str, identity: &str) -> KeyBuf {
	let mut stack: ArrayString<CACHE_KEY_STACK_CAP> = ArrayString::new();
	if write_cache_key(&mut stack, method, path, identity).is_ok() {
		return KeyBuf::Stack(stack);
	}
	// Over-cap path: the partial stack write is discarded and the key is rebuilt on the heap.
	let mut heap: String = String::with_capacity(method.len() + path.len() + identity.len() + CACHE_KEY_LEN_OVERHEAD);
	let _ = write_cache_key(&mut heap, method, path, identity);
	return KeyBuf::Heap(heap);
}

pub struct ResponseCache {
	store: Mutex<LruCache<CacheKey, CachedResponse>>,
	config: CacheConfig,
}

impl ResponseCache {
	#[must_use]
	pub fn new(config: &CacheConfig) -> Self {
		return Self {
			store: Mutex::new(LruCache::new(config.max_entries)),
			config: config.clone(),
		};
	}

	pub fn get(&self, key: CacheKeyRef<'_>) -> Option<Response<Body>> {
		// Borrowed lookup: build the joined key on the stack (heap only for an over-cap path) instead of
		// allocating an owned CacheKey per get. LruCache::get accepts a &str via CacheKey: Borrow<str>.
		let lookup: KeyBuf = build_lookup_key(key.method, key.path, key.identity);

		// Clone the minimum under the lock (status Copy, headers small, body a Bytes refcount bump), then
		// release before building the response — keeps the body copy and builder out of the critical section.
		let (status, headers, body): (StatusCode, HeaderMap, Bytes) = {
			let mut store = self.store.lock();
			let entry: &CachedResponse = store.get(&*lookup)?;
			if entry.is_expired() {
				store.pop(&*lookup);
				return None;
			}
			(entry.status, entry.headers.clone(), entry.body.clone())
		};

		// Move the already-cloned header map into the response rather than re-inserting each header
		// through the builder, which would construct and grow a SECOND HeaderMap. The one clone above is
		// irreducible (the stored entry keeps its own copy for later hits); the rebuild was pure waste.
		let mut response: Response<Body> = Response::new(Body::from(body));
		*response.status_mut() = status;
		*response.headers_mut() = headers;
		return Some(response);
	}

	pub fn put(
		&self,
		key: CacheKeyRef<'_>,
		status: StatusCode,
		headers: &HeaderMap,
		body: Bytes,
		directives: &CacheDirectives,
	) -> bool {
		if directives.no_store || directives.is_private {
			return false;
		}

		if body.len() > self.config.max_entry_bytes.get() {
			return false;
		}

		let ttl_secs: u64 = directives.max_age.unwrap_or(self.config.default_ttl_secs.get());
		if ttl_secs == 0 {
			return false;
		}

		let key: CacheKey = key.into();
		let entry: CachedResponse = CachedResponse {
			status,
			// Strip Set-Cookie and hop-by-hop headers before storing so a hit never replays one request's
			// session token or a stale per-connection header for the whole TTL.
			headers: sanitized_for_cache(headers),
			body,
			inserted_at: Instant::now(),
			ttl: Duration::from_secs(ttl_secs),
		};

		let mut store = self.store.lock();
		store.put(key, entry);
		return true;
	}

	// Drop every cached entry. Called on config reload: cache lookup runs before route resolution, so
	// without this a deleted or repointed route would keep serving responses cached from the old backend
	// until each entry's TTL expired. Flushing on reload trades a briefly cold cache for correctness.
	pub fn clear(&self) {
		self.store.lock().clear();
	}

	pub fn len(&self) -> usize {
		return self.store.lock().len();
	}

	#[must_use]
	pub fn is_empty(&self) -> bool {
		return self.store.lock().is_empty();
	}
}

#[cfg(test)]
mod tests {
	use std::num::{NonZeroU64, NonZeroUsize};

	use axum::http::HeaderValue;

	use super::*;

	fn ck<'a>(method: &'a str, path: &'a str, identity: &'a str) -> CacheKeyRef<'a> {
		return CacheKeyRef { method, path, identity };
	}

	fn test_config() -> CacheConfig {
		return CacheConfig {
			enabled: true,
			max_entries: NonZeroUsize::new(100).unwrap(),
			max_entry_bytes: NonZeroUsize::new(1024 * 1024).unwrap(),
			default_ttl_secs: NonZeroU64::new(60).unwrap(),
		};
	}

	#[test]
	fn test_cache_miss() {
		let cache: ResponseCache = ResponseCache::new(&test_config());
		let result: Option<Response<Body>> = cache.get(ck("GET", "/api/data", ""));
		assert!(result.is_none());
	}

	#[test]
	fn test_cache_hit() {
		let cache: ResponseCache = ResponseCache::new(&test_config());
		let mut headers: HeaderMap = HeaderMap::new();
		headers.insert("x-custom", HeaderValue::from_static("value"));

		let directives: CacheDirectives = CacheDirectives {
			max_age: Some(300),
			..CacheDirectives::default()
		};

		let stored: bool = cache.put(
			ck("GET", "/api/data", ""),
			StatusCode::OK,
			&headers,
			Bytes::from_static(b"response body"),
			&directives,
		);
		assert!(stored);

		let response: Response<Body> = cache.get(ck("GET", "/api/data", "")).expect("expected cache hit");
		assert_eq!(response.status(), StatusCode::OK);
		assert_eq!(response.headers().get("x-custom").unwrap(), "value");
	}

	#[test]
	fn test_cache_no_store_rejected() {
		let cache: ResponseCache = ResponseCache::new(&test_config());
		let directives: CacheDirectives = CacheDirectives {
			no_store: true,
			..CacheDirectives::default()
		};

		let stored: bool = cache.put(
			ck("GET", "/api/data", ""),
			StatusCode::OK,
			&HeaderMap::new(),
			Bytes::from_static(b"body"),
			&directives,
		);
		assert!(!stored);
		assert_eq!(cache.len(), 0);
	}

	#[test]
	fn test_cache_private_rejected() {
		let cache: ResponseCache = ResponseCache::new(&test_config());
		let directives: CacheDirectives = CacheDirectives {
			is_private: true,
			..CacheDirectives::default()
		};

		let stored: bool = cache.put(
			ck("GET", "/api/data", ""),
			StatusCode::OK,
			&HeaderMap::new(),
			Bytes::from_static(b"body"),
			&directives,
		);
		assert!(!stored);
	}

	#[test]
	fn test_cache_max_age_zero_rejected() {
		let cache: ResponseCache = ResponseCache::new(&test_config());
		let directives: CacheDirectives = CacheDirectives {
			max_age: Some(0),
			..CacheDirectives::default()
		};

		let stored: bool = cache.put(
			ck("GET", "/api/data", ""),
			StatusCode::OK,
			&HeaderMap::new(),
			Bytes::from_static(b"body"),
			&directives,
		);
		assert!(!stored);
	}

	#[test]
	fn test_cache_oversized_entry_rejected() {
		let mut config: CacheConfig = test_config();
		config.max_entry_bytes = NonZeroUsize::new(10).unwrap();
		let cache: ResponseCache = ResponseCache::new(&config);

		let directives: CacheDirectives = CacheDirectives {
			max_age: Some(300),
			..CacheDirectives::default()
		};

		let stored: bool = cache.put(
			ck("GET", "/api/data", ""),
			StatusCode::OK,
			&HeaderMap::new(),
			Bytes::from_static(b"this body is way too large"),
			&directives,
		);
		assert!(!stored);
	}

	#[test]
	fn test_cache_clear_removes_entries_and_prevents_stale_hit() {
		let cache: ResponseCache = ResponseCache::new(&test_config());
		let directives: CacheDirectives = CacheDirectives {
			max_age: Some(300),
			..CacheDirectives::default()
		};

		let stored: bool = cache.put(
			ck("GET", "/api/data", ""),
			StatusCode::OK,
			&HeaderMap::new(),
			Bytes::from_static(b"old backend body"),
			&directives,
		);
		assert!(stored);
		assert!(cache.get(ck("GET", "/api/data", "")).is_some());

		// A reload flushes the cache so a repointed/deleted route can't be served from the old entry.
		cache.clear();

		assert_eq!(cache.len(), 0);
		assert!(cache.is_empty());
		assert!(cache.get(ck("GET", "/api/data", "")).is_none());
	}

	#[test]
	fn test_cache_expired_entry_evicted() {
		// Insert a backdated entry directly into the store so expiry is deterministic without a
		// wall-clock sleep: inserted 2s ago with a 1s TTL is unambiguously expired. This drives the
		// eviction branch in get() (is_expired -> pop -> miss) rather than merely confirming storage.
		let cache: ResponseCache = ResponseCache::new(&test_config());
		let key: CacheKey = ck("GET", "/api/data", "").into();
		let expired: CachedResponse = CachedResponse {
			status: StatusCode::OK,
			headers: HeaderMap::new(),
			body: Bytes::from_static(b"stale"),
			inserted_at: Instant::now() - Duration::from_secs(2),
			ttl: Duration::from_secs(1),
		};
		assert!(expired.is_expired());
		cache.store.lock().put(key, expired);
		assert_eq!(cache.len(), 1);

		// get() observes the expiry, returns a miss, AND removes the entry from the store.
		assert!(cache.get(ck("GET", "/api/data", "")).is_none());
		assert_eq!(cache.len(), 0, "expired entry must be evicted on access");
	}

	#[test]
	fn test_cache_unexpired_entry_not_evicted() {
		// Control for the eviction test: a fresh entry (elapsed < ttl) survives a get() so the
		// eviction above is attributable to expiry, not to get() always popping.
		let cache: ResponseCache = ResponseCache::new(&test_config());
		let key: CacheKey = ck("GET", "/api/data", "").into();
		let fresh: CachedResponse = CachedResponse {
			status: StatusCode::OK,
			headers: HeaderMap::new(),
			body: Bytes::from_static(b"fresh"),
			inserted_at: Instant::now(),
			ttl: Duration::from_secs(60),
		};
		assert!(!fresh.is_expired());
		cache.store.lock().put(key, fresh);

		assert!(cache.get(ck("GET", "/api/data", "")).is_some());
		assert_eq!(cache.len(), 1, "unexpired entry must remain cached");
	}

	#[test]
	fn test_cache_default_ttl_used() {
		let config: CacheConfig = test_config();
		let cache: ResponseCache = ResponseCache::new(&config);

		let directives: CacheDirectives = CacheDirectives::default();

		let stored: bool = cache.put(
			ck("GET", "/api/data", ""),
			StatusCode::OK,
			&HeaderMap::new(),
			Bytes::from_static(b"body"),
			&directives,
		);
		assert!(stored);
		assert!(cache.get(ck("GET", "/api/data", "")).is_some());
	}

	#[test]
	fn test_cache_different_methods_different_keys() {
		let cache: ResponseCache = ResponseCache::new(&test_config());
		let directives: CacheDirectives = CacheDirectives {
			max_age: Some(300),
			..CacheDirectives::default()
		};

		cache.put(
			ck("GET", "/api/data", ""),
			StatusCode::OK,
			&HeaderMap::new(),
			Bytes::from_static(b"get body"),
			&directives,
		);
		cache.put(
			ck("HEAD", "/api/data", ""),
			StatusCode::OK,
			&HeaderMap::new(),
			Bytes::from_static(b""),
			&directives,
		);

		assert_eq!(cache.len(), 2);
	}

	#[test]
	fn test_cache_lru_eviction() {
		let mut config: CacheConfig = test_config();
		config.max_entries = NonZeroUsize::new(2).unwrap();
		let cache: ResponseCache = ResponseCache::new(&config);

		let directives: CacheDirectives = CacheDirectives {
			max_age: Some(300),
			..CacheDirectives::default()
		};

		cache.put(
			ck("GET", "/a", ""),
			StatusCode::OK,
			&HeaderMap::new(),
			Bytes::from_static(b"a"),
			&directives,
		);
		cache.put(
			ck("GET", "/b", ""),
			StatusCode::OK,
			&HeaderMap::new(),
			Bytes::from_static(b"b"),
			&directives,
		);
		cache.put(
			ck("GET", "/c", ""),
			StatusCode::OK,
			&HeaderMap::new(),
			Bytes::from_static(b"c"),
			&directives,
		);

		assert_eq!(cache.len(), 2);
		assert!(cache.get(ck("GET", "/a", "")).is_none());
		assert!(cache.get(ck("GET", "/b", "")).is_some());
		assert!(cache.get(ck("GET", "/c", "")).is_some());
	}

	#[test]
	fn test_cache_put_updates_existing() {
		let cache: ResponseCache = ResponseCache::new(&test_config());
		let directives: CacheDirectives = CacheDirectives {
			max_age: Some(300),
			..CacheDirectives::default()
		};

		cache.put(
			ck("GET", "/api", ""),
			StatusCode::OK,
			&HeaderMap::new(),
			Bytes::from_static(b"v1"),
			&directives,
		);
		cache.put(
			ck("GET", "/api", ""),
			StatusCode::OK,
			&HeaderMap::new(),
			Bytes::from_static(b"v2"),
			&directives,
		);

		assert_eq!(cache.len(), 1);
	}

	#[test]
	fn test_cache_preserves_status_code() {
		let cache: ResponseCache = ResponseCache::new(&test_config());
		let directives: CacheDirectives = CacheDirectives {
			max_age: Some(300),
			..CacheDirectives::default()
		};

		cache.put(
			ck("GET", "/api/data", ""),
			StatusCode::NOT_FOUND,
			&HeaderMap::new(),
			Bytes::from_static(b"not found"),
			&directives,
		);

		let response: Response<Body> = cache.get(ck("GET", "/api/data", "")).unwrap();
		assert_eq!(response.status(), StatusCode::NOT_FOUND);
	}

	#[test]
	fn test_cache_isolates_by_identity() {
		// Security invariant: a response cached under device A's identity must never be served to
		// device B, and an anonymous lookup must not see either device's entry.
		let cache: ResponseCache = ResponseCache::new(&test_config());
		let directives: CacheDirectives = CacheDirectives {
			max_age: Some(300),
			..CacheDirectives::default()
		};

		cache.put(
			ck("GET", "/api/data", "device-a"),
			StatusCode::OK,
			&HeaderMap::new(),
			Bytes::from_static(b"secret-a"),
			&directives,
		);

		// Same method+path, different identity -> miss.
		assert!(
			cache.get(ck("GET", "/api/data", "device-b")).is_none(),
			"device B must not read device A's entry"
		);
		assert!(
			cache.get(ck("GET", "/api/data", "")).is_none(),
			"anonymous must not read device A's entry"
		);

		// The owning identity still hits and gets its own body.
		let hit: Response<Body> = cache
			.get(ck("GET", "/api/data", "device-a"))
			.expect("device A should hit");
		assert_eq!(hit.status(), StatusCode::OK);
	}

	#[test]
	fn test_cache_strips_set_cookie_and_hop_by_hop() {
		// Security invariant: a stored response must not carry Set-Cookie or hop-by-hop headers, so a hit
		// can never replay one request's session token. Functional diff: an ordinary header survives the
		// round-trip while the sensitive ones are gone — proving the strip acts, not that storage is inert.
		let cache: ResponseCache = ResponseCache::new(&test_config());
		let mut headers: HeaderMap = HeaderMap::new();
		headers.insert("set-cookie", HeaderValue::from_static("session=secret; HttpOnly"));
		headers.insert("connection", HeaderValue::from_static("keep-alive"));
		headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
		headers.insert("x-app", HeaderValue::from_static("keep-me"));
		let directives: CacheDirectives = CacheDirectives {
			max_age: Some(300),
			..CacheDirectives::default()
		};

		assert!(cache.put(
			ck("GET", "/api/data", "device-a"),
			StatusCode::OK,
			&headers,
			Bytes::from_static(b"body"),
			&directives,
		));

		let hit: Response<Body> = cache
			.get(ck("GET", "/api/data", "device-a"))
			.expect("expected a cache hit");
		assert!(
			hit.headers().get("set-cookie").is_none(),
			"Set-Cookie must be stripped from a cached response"
		);
		assert!(
			hit.headers().get("connection").is_none(),
			"hop-by-hop Connection must be stripped"
		);
		assert!(
			hit.headers().get("transfer-encoding").is_none(),
			"hop-by-hop Transfer-Encoding must be stripped"
		);
		assert_eq!(
			hit.headers().get("x-app").unwrap(),
			"keep-me",
			"ordinary headers must survive caching"
		);
	}

	#[test]
	fn test_cache_strips_repeated_set_cookie() {
		// A response can carry multiple Set-Cookie values; remove() must clear all of them, not just the first.
		let cache: ResponseCache = ResponseCache::new(&test_config());
		let mut headers: HeaderMap = HeaderMap::new();
		headers.append("set-cookie", HeaderValue::from_static("a=1"));
		headers.append("set-cookie", HeaderValue::from_static("b=2"));
		let directives: CacheDirectives = CacheDirectives {
			max_age: Some(300),
			..CacheDirectives::default()
		};

		cache.put(
			ck("GET", "/x", "d"),
			StatusCode::OK,
			&headers,
			Bytes::from_static(b"body"),
			&directives,
		);
		let hit: Response<Body> = cache.get(ck("GET", "/x", "d")).expect("expected a cache hit");
		assert_eq!(
			hit.headers().get_all("set-cookie").iter().count(),
			0,
			"every Set-Cookie value must be stripped"
		);
	}

	#[test]
	fn test_cache_distinct_identities_coexist() {
		let cache: ResponseCache = ResponseCache::new(&test_config());
		let directives: CacheDirectives = CacheDirectives {
			max_age: Some(300),
			..CacheDirectives::default()
		};

		cache.put(
			ck("GET", "/api/data", "device-a"),
			StatusCode::OK,
			&HeaderMap::new(),
			Bytes::from_static(b"a"),
			&directives,
		);
		cache.put(
			ck("GET", "/api/data", "device-b"),
			StatusCode::OK,
			&HeaderMap::new(),
			Bytes::from_static(b"b"),
			&directives,
		);

		// Same URL, two identities -> two independent entries.
		assert_eq!(cache.len(), 2);
		assert!(cache.get(ck("GET", "/api/data", "device-a")).is_some());
		assert!(cache.get(ck("GET", "/api/data", "device-b")).is_some());
	}

	// Changing exactly one key field must never produce a hit on another field's entry — the core
	// isolation property the joined key must preserve.
	#[test]
	fn one_field_difference_never_cross_hits() {
		let cache: ResponseCache = ResponseCache::new(&test_config());
		let directives: CacheDirectives = CacheDirectives {
			max_age: Some(300),
			..CacheDirectives::default()
		};
		cache.put(
			ck("GET", "/a", "idA"),
			StatusCode::OK,
			&HeaderMap::new(),
			Bytes::from_static(b"x"),
			&directives,
		);

		assert!(cache.get(ck("GET", "/a", "idA")).is_some(), "exact key must hit");
		assert!(
			cache.get(ck("POST", "/a", "idA")).is_none(),
			"different method must miss"
		);
		assert!(cache.get(ck("GET", "/b", "idA")).is_none(), "different path must miss");
		assert!(
			cache.get(ck("GET", "/a", "idB")).is_none(),
			"different identity must miss"
		);
	}

	// Length-prefixing is injective across field boundaries where a naive concatenation would collide:
	// (method="a", path="bc") and (method="ab", path="c") both concatenate to "abc", but their
	// length-prefixed keys differ ("1:a2:bc..." vs "2:ab1:c..."), so one is never served for the other.
	// Also covers a path that itself contains the ':' marker and digits — content is consumed by count,
	// so it cannot be mistaken for a length prefix.
	#[test]
	fn key_encoding_injective_across_field_boundaries() {
		let cache: ResponseCache = ResponseCache::new(&test_config());
		let directives: CacheDirectives = CacheDirectives {
			max_age: Some(300),
			..CacheDirectives::default()
		};

		cache.put(
			ck("a", "bc", "id"),
			StatusCode::OK,
			&HeaderMap::new(),
			Bytes::from_static(b"1"),
			&directives,
		);
		assert!(
			cache.get(ck("ab", "c", "id")).is_none(),
			"field-boundary shift must not cross-hit"
		);
		assert!(cache.get(ck("a", "bc", "id")).is_some(), "exact key still hits");

		// A path containing a ':' + digits (which a length prefix looks like) must round-trip exactly and
		// not collide with a different split.
		cache.put(
			ck("GET", "9:evil", "id"),
			StatusCode::OK,
			&HeaderMap::new(),
			Bytes::from_static(b"2"),
			&directives,
		);
		assert!(
			cache.get(ck("GET", "9:evil", "id")).is_some(),
			"colon/digit path must round-trip"
		);
		assert!(
			cache.get(ck("GET", "9", "evil")).is_none(),
			"no cross-hit from a different field split"
		);
	}

	// A path past the stack cap forces KeyBuf::Heap; the lookup must still round-trip and stay distinct
	// from a different over-cap path. Also asserts the stack and heap builders encode identically to the
	// owned key so a stack- or heap-built lookup hashes/compares equal to a stored entry.
	#[test]
	fn oversized_path_uses_heap_and_round_trips() {
		let short: KeyBuf = build_lookup_key("GET", "/api/data", "id");
		assert!(matches!(short, KeyBuf::Stack(_)), "a short key must stay on the stack");
		let owned: CacheKey = CacheKey::from(ck("GET", "/api/data", "id"));
		assert_eq!(
			&*short, &*owned.0,
			"stack lookup must encode identically to the owned key"
		);

		let long_path: String = format!("/{}", "x".repeat(CACHE_KEY_STACK_CAP));
		let long: KeyBuf = build_lookup_key("GET", &long_path, "id");
		assert!(
			matches!(long, KeyBuf::Heap(_)),
			"an over-cap key must fall back to the heap"
		);
		let long_owned: CacheKey = CacheKey::from(ck("GET", &long_path, "id"));
		assert_eq!(
			&*long, &*long_owned.0,
			"heap lookup must encode identically to the owned key"
		);

		let cache: ResponseCache = ResponseCache::new(&test_config());
		let directives: CacheDirectives = CacheDirectives {
			max_age: Some(300),
			..CacheDirectives::default()
		};
		cache.put(
			ck("GET", &long_path, "id"),
			StatusCode::OK,
			&HeaderMap::new(),
			Bytes::from_static(b"L"),
			&directives,
		);
		assert!(
			cache.get(ck("GET", &long_path, "id")).is_some(),
			"over-cap key must hit itself"
		);
		let other_long: String = format!("/{}", "y".repeat(CACHE_KEY_STACK_CAP));
		assert!(
			cache.get(ck("GET", &other_long, "id")).is_none(),
			"a different over-cap path must miss"
		);
	}
}
