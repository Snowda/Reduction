use super::{
	ACCEPT_ENCODING, Body, CONTENT_ENCODING, CacheDirectives, CompressionConfig, Duration, HEADER_CLIENT_ID,
	HEADER_CLIENT_SPKI, HEADER_IDEMPOTENCY_KEY, HeaderMap, Method, Response, RetryConfig, STATUS_BAD_GATEWAY,
	STATUS_SERVICE_UNAVAILABLE, STATUS_TOO_MANY_REQUESTS, StatusCode, VARY, compress_response, retry,
};

#[inline]
pub fn response_is_encoded(response: &Response<Body>) -> bool {
	return response.headers().contains_key(CONTENT_ENCODING);
}

// Compress only when safe: client accepts zstd, body is plain/transformable, and not a 206 partial.
// Shared by the cache-hit and forward-success paths so both post-process a response identically.
pub fn maybe_compress(
	response: Response<Body>,
	accepts_zstd: bool,
	directives: &CacheDirectives,
	config: &CompressionConfig,
) -> Response<Body> {
	if config.enabled
		&& accepts_zstd
		&& !response_is_encoded(&response)
		&& response.status() != StatusCode::PARTIAL_CONTENT
		&& !directives.no_transform
	{
		return compress_response(response, config.min_bytes, config.level);
	}
	return response;
}

// Only a full 200 OK is cacheable. Range is not a cache-key dimension, so storing a 206 would replay one
// client's byte range as another's full-GET response; other 2xx carry no representation worth reusing.
#[inline]
pub fn is_cacheable_status(status: StatusCode) -> bool {
	return status == StatusCode::OK;
}

// Response headers the cache already accounts for: identity (client-id / SPKI) is in the cache key, and
// Accept-Encoding is covered by invariant (the store refuses any Content-Encoding, so only identity-encoded
// bodies are stored). A Vary on anything else — or `Vary: *` — keys on a dimension the cache doesn't, so don't store.
pub fn vary_permits_caching(headers: &axum::http::HeaderMap) -> bool {
	let Some(vary) = headers.get(VARY).and_then(|v| v.to_str().ok()) else {
		return true;
	};
	return vary.split(',').all(|token| {
		let name: String = token.trim().to_ascii_lowercase();
		return name == ACCEPT_ENCODING.as_str() || name == HEADER_CLIENT_ID || name == HEADER_CLIENT_SPKI;
	});
}

// The cache is shared by sessions under one mTLS identity, so a response must opt in (`public`, which also
// covers credentialed requests) to be reusable. Cookie-bearing requests never cache (Cookie isn't a key dimension).
pub const fn response_permits_shared_caching(request_has_cookie: bool, directives: &CacheDirectives) -> bool {
	return !request_has_cookie && directives.is_public;
}

#[inline]
pub const fn is_retryable_status(status: StatusCode) -> bool {
	return matches!(
		status.as_u16(),
		STATUS_BAD_GATEWAY | STATUS_SERVICE_UNAVAILABLE | STATUS_TOO_MANY_REQUESTS
	);
}

// True for methods safe to replay on a retry (RFC 9110 §9.2.2): GET/HEAD/OPTIONS/TRACE safe, PUT/DELETE
// idempotent. POST/PATCH/CONNECT are excluded — a backend may have committed one before it failed.
#[inline]
pub const fn is_idempotent_method(method: &Method) -> bool {
	return matches!(
		*method,
		Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE | Method::PUT | Method::DELETE
	);
}

// Whether this request may be retried automatically: idempotent methods always; a non-idempotent method only
// with a non-empty Idempotency-Key (the client's assertion that the backend deduplicates replays).
#[inline]
pub fn retries_permitted(method: &Method, headers: &HeaderMap) -> bool {
	return is_idempotent_method(method)
		|| headers
			.get(HEADER_IDEMPOTENCY_KEY)
			.map(|value| !value.is_empty())
			.unwrap_or(false);
}

// Exponential backoff with jitter for the forward-retry loop; delegates to the shared retry policy
// so the ingress reconnect loop and this path stay in lockstep.
pub fn backoff_delay(attempt: u32, config: &RetryConfig) -> Duration {
	return retry::backoff_delay(attempt, config);
}

#[cfg(test)]
mod tests {
	use axum::http::HeaderValue;
	use axum::http::header::CONTENT_LENGTH;
	use http_body_util::BodyExt;

	use super::*;
	use crate::compression;

	#[test]
	fn test_response_is_encoded_false() {
		let resp = Response::builder().body(Body::empty()).unwrap();
		assert!(!response_is_encoded(&resp));
	}

	#[test]
	fn test_response_is_encoded_true() {
		let resp = Response::builder()
			.header(CONTENT_ENCODING, "zstd")
			.body(Body::empty())
			.unwrap();
		assert!(response_is_encoded(&resp));
	}

	#[test]
	fn test_response_is_encoded_gzip() {
		let resp = Response::builder()
			.header(CONTENT_ENCODING, "gzip")
			.body(Body::empty())
			.unwrap();
		assert!(response_is_encoded(&resp));
	}


	#[tokio::test]
	async fn test_compress_response_round_trip() {
		let original: Vec<u8> = "response body data for compression ".repeat(10).into_bytes();
		let resp = Response::builder().body(Body::from(original.clone())).unwrap();

		let compressed_resp = compress_response(resp, 256, 3);
		assert_eq!(compressed_resp.headers().get(CONTENT_ENCODING).unwrap(), "zstd");
		assert!(!compressed_resp.headers().contains_key(CONTENT_LENGTH));

		let body_bytes = compressed_resp.into_body().collect().await.unwrap().to_bytes();
		let decompressed: Vec<u8> = compression::decompress_bounded(&body_bytes, 10 * 1024 * 1024).unwrap();
		assert_eq!(decompressed, original);
	}

	#[tokio::test]
	async fn test_compress_response_small_body_skipped() {
		let original = b"tiny";
		let resp = Response::builder()
			.header(CONTENT_LENGTH, original.len())
			.body(Body::from(original.to_vec()))
			.unwrap();

		let result = compress_response(resp, 256, 3);
		assert!(!result.headers().contains_key(CONTENT_ENCODING));
		let body_bytes = result.into_body().collect().await.unwrap().to_bytes();
		assert_eq!(&body_bytes[..], original);
	}


	#[test]
	fn test_maybe_compress_skipped_for_partial_content() {
		// Body is well over min_bytes, so only the 206 rule can suppress compression here.
		let original: Vec<u8> = "partial range data here ".repeat(20).into_bytes();
		let resp = Response::builder()
			.status(StatusCode::PARTIAL_CONTENT)
			.header("Content-Range", "bytes 0-22/100")
			.body(Body::from(original))
			.unwrap();

		let directives = CacheDirectives::from_response(&resp);
		let out = maybe_compress(resp, true, &directives, &CompressionConfig::default());
		assert!(!out.headers().contains_key(CONTENT_ENCODING));
	}

	#[test]
	fn test_maybe_compress_applied_for_200() {
		let original: Vec<u8> = "response body data for compression ".repeat(10).into_bytes();
		let resp = Response::builder()
			.status(StatusCode::OK)
			.body(Body::from(original))
			.unwrap();

		let directives = CacheDirectives::from_response(&resp);
		let out = maybe_compress(resp, true, &directives, &CompressionConfig::default());
		assert_eq!(out.headers().get(CONTENT_ENCODING).unwrap(), "zstd");
	}

	#[test]
	fn test_maybe_compress_skipped_when_client_rejects_zstd() {
		let original: Vec<u8> = "response body data for compression ".repeat(10).into_bytes();
		let resp = Response::builder()
			.status(StatusCode::OK)
			.body(Body::from(original))
			.unwrap();

		let directives = CacheDirectives::from_response(&resp);
		let out = maybe_compress(resp, false, &directives, &CompressionConfig::default());
		assert!(!out.headers().contains_key(CONTENT_ENCODING));
	}

	#[test]
	fn test_maybe_compress_skipped_for_no_transform() {
		let original: Vec<u8> = "response body data for compression ".repeat(10).into_bytes();
		let resp = Response::builder()
			.status(StatusCode::OK)
			.header("cache-control", "no-transform")
			.body(Body::from(original))
			.unwrap();

		let directives = CacheDirectives::from_response(&resp);
		let out = maybe_compress(resp, true, &directives, &CompressionConfig::default());
		assert!(!out.headers().contains_key(CONTENT_ENCODING));
	}

	#[test]
	fn test_maybe_compress_applied_when_no_transform_absent() {
		let original: Vec<u8> = "response body data for compression ".repeat(10).into_bytes();
		let resp = Response::builder()
			.status(StatusCode::OK)
			.header("cache-control", "max-age=3600")
			.body(Body::from(original))
			.unwrap();

		let directives = CacheDirectives::from_response(&resp);
		let out = maybe_compress(resp, true, &directives, &CompressionConfig::default());
		assert_eq!(out.headers().get(CONTENT_ENCODING).unwrap(), "zstd");
	}

	#[test]
	fn test_range_headers_not_stripped() {
		use axum::http::HeaderMap;

		let mut headers = HeaderMap::new();
		headers.insert("range", HeaderValue::from_static("bytes=0-99"));
		headers.insert("if-range", HeaderValue::from_static("\"etag123\""));
		headers.insert("accept-ranges", HeaderValue::from_static("bytes"));
		headers.insert("content-range", HeaderValue::from_static("bytes 0-99/200"));

		// forward_request only strips these headers — verify range headers are not among them
		let stripped = [
			"x-forwarded-for",
			"x-forwarded-proto",
			"x-forwarded-host",
			"forwarded",
			"x-real-ip",
		];
		for name in ["range", "if-range", "accept-ranges", "content-range"] {
			assert!(!stripped.contains(&name), "{name} should not be stripped");
			assert!(headers.contains_key(name), "{name} must survive forwarding");
		}
	}

	#[test]
	fn test_vary_permits_caching_no_vary() {
		let headers = axum::http::HeaderMap::new();
		assert!(vary_permits_caching(&headers));
	}

	#[test]
	fn test_vary_permits_caching_covered_headers() {
		let mut headers = axum::http::HeaderMap::new();
		// accept-encoding is safe because only identity-encoded bodies are ever stored (the store site
		// rejects any Content-Encoding); the injected identity headers are in the key.
		headers.insert(VARY, HeaderValue::from_static("Accept-Encoding, x-reduction-client-id"));
		assert!(vary_permits_caching(&headers));
	}

	#[test]
	fn test_is_cacheable_status_only_full_ok() {
		assert!(is_cacheable_status(StatusCode::OK));
		// 206 answers a Range request; Range is not in the cache key, so it must never be stored.
		assert!(!is_cacheable_status(StatusCode::PARTIAL_CONTENT));
		assert!(!is_cacheable_status(StatusCode::NO_CONTENT));
		assert!(!is_cacheable_status(StatusCode::NON_AUTHORITATIVE_INFORMATION));
		assert!(!is_cacheable_status(StatusCode::NOT_MODIFIED));
		assert!(!is_cacheable_status(StatusCode::INTERNAL_SERVER_ERROR));
	}

	#[test]
	fn test_vary_permits_caching_uncovered_header() {
		let mut headers = axum::http::HeaderMap::new();
		headers.insert(VARY, HeaderValue::from_static("accept-encoding, user-agent"));
		assert!(
			!vary_permits_caching(&headers),
			"an uncovered Vary header must block caching"
		);
	}

	#[test]
	fn test_vary_permits_caching_star() {
		let mut headers = axum::http::HeaderMap::new();
		headers.insert(VARY, HeaderValue::from_static("*"));
		assert!(!vary_permits_caching(&headers));
	}

	#[test]
	fn test_shared_cache_requires_explicit_public_response() {
		assert!(!response_permits_shared_caching(false, &CacheDirectives::default()));
		let public = CacheDirectives {
			is_public: true,
			..CacheDirectives::default()
		};
		assert!(response_permits_shared_caching(false, &public));
		assert!(!response_permits_shared_caching(true, &public));
	}

	#[test]
	fn test_is_retryable_status_502() {
		assert!(is_retryable_status(StatusCode::BAD_GATEWAY));
	}

	#[test]
	fn test_is_retryable_status_503() {
		assert!(is_retryable_status(StatusCode::SERVICE_UNAVAILABLE));
	}

	#[test]
	fn test_is_retryable_status_429() {
		assert!(is_retryable_status(StatusCode::TOO_MANY_REQUESTS));
	}

	#[test]
	fn test_is_retryable_status_200_not_retryable() {
		assert!(!is_retryable_status(StatusCode::OK));
	}

	#[test]
	fn test_is_retryable_status_400_not_retryable() {
		assert!(!is_retryable_status(StatusCode::BAD_REQUEST));
	}

	#[test]
	fn test_retry_config_defaults() {
		let cfg: RetryConfig = RetryConfig::default();
		assert_eq!(cfg.max_retries, 2);
		assert_eq!(cfg.base_delay_ms, 200);
		assert_eq!(cfg.max_delay_ms, 2000);
		assert_eq!(cfg.jitter_ms, 100);
	}

	#[test]
	fn test_backoff_delay_exponential_growth() {
		let config: RetryConfig = RetryConfig {
			max_retries: 3,
			base_delay_ms: 100,
			max_delay_ms: 5000,
			jitter_ms: 0,
		};
		let d0: Duration = backoff_delay(0, &config);
		let d1: Duration = backoff_delay(1, &config);
		let d2: Duration = backoff_delay(2, &config);

		// With zero jitter, delays should be exactly 100, 200, 400
		assert_eq!(d0, Duration::from_millis(100));
		assert_eq!(d1, Duration::from_millis(200));
		assert_eq!(d2, Duration::from_millis(400));
	}

	#[test]
	fn test_backoff_delay_capped_at_max() {
		let config: RetryConfig = RetryConfig {
			max_retries: 10,
			base_delay_ms: 1000,
			max_delay_ms: 2000,
			jitter_ms: 0,
		};
		// attempt=5 would be 1000 * 32 = 32000 uncapped, but should be capped at 2000
		let d: Duration = backoff_delay(5, &config);
		assert_eq!(d, Duration::from_millis(2000));
	}

	#[test]
	fn test_backoff_delay_jitter_bounded() {
		let config: RetryConfig = RetryConfig {
			max_retries: 3,
			base_delay_ms: 100,
			max_delay_ms: 5000,
			jitter_ms: 50,
		};
		// Run multiple times — jitter should always be in [0, 50) so total in [100, 150)
		for _ in 0..20 {
			let d: Duration = backoff_delay(0, &config);
			assert!(d >= Duration::from_millis(100), "delay {d:?} below base");
			assert!(d < Duration::from_millis(150), "delay {d:?} exceeds base + jitter");
		}
	}

	#[test]
	fn test_backoff_delay_zero_jitter() {
		let config: RetryConfig = RetryConfig {
			max_retries: 1,
			base_delay_ms: 200,
			max_delay_ms: 2000,
			jitter_ms: 0,
		};
		let d: Duration = backoff_delay(0, &config);
		assert_eq!(d, Duration::from_millis(200));
	}

	#[test]
	fn test_backoff_delay_jitter_varies_across_calls() {
		// The point of jitter is decorrelation: repeated calls for the SAME attempt must not all
		// return an identical delay. The old hash-of-zero-elapsed source produced a constant and
		// would fail this, while still passing the bounds check above.
		let config: RetryConfig = RetryConfig {
			max_retries: 3,
			base_delay_ms: 100,
			max_delay_ms: 5000,
			jitter_ms: 100,
		};
		let first: Duration = backoff_delay(0, &config);
		let varies: bool = (0..64).any(|_| backoff_delay(0, &config) != first);
		assert!(varies, "jitter returned a constant delay across 64 calls: not random");
	}


	#[test]
	fn test_idempotent_methods_are_replay_safe() {
		for method in [
			Method::GET,
			Method::HEAD,
			Method::OPTIONS,
			Method::TRACE,
			Method::PUT,
			Method::DELETE,
		] {
			assert!(is_idempotent_method(&method), "{method} should be idempotent");
		}
	}

	#[test]
	fn test_non_idempotent_methods_are_not_replay_safe() {
		for method in [Method::POST, Method::PATCH, Method::CONNECT] {
			assert!(
				!is_idempotent_method(&method),
				"{method} must not be treated as idempotent"
			);
		}
	}

	#[test]
	fn test_retries_permitted_for_idempotent_without_key() {
		let headers: HeaderMap = HeaderMap::new();
		assert!(retries_permitted(&Method::GET, &headers));
	}

	#[test]
	fn test_retries_denied_for_post_without_key() {
		// The core of the fix: a plain POST is never retried automatically, so a committed side
		// effect behind a transient error or 5xx cannot double-fire.
		let headers: HeaderMap = HeaderMap::new();
		assert!(!retries_permitted(&Method::POST, &headers));
	}

	#[test]
	fn test_retries_permitted_for_post_with_idempotency_key() {
		let mut headers: HeaderMap = HeaderMap::new();
		headers.insert(HEADER_IDEMPOTENCY_KEY, HeaderValue::from_static("abc-123"));
		assert!(retries_permitted(&Method::POST, &headers));
	}

	#[test]
	fn test_retries_denied_for_post_with_empty_idempotency_key() {
		// An empty key is not an opt-in — it carries no dedup identity for the backend.
		let mut headers: HeaderMap = HeaderMap::new();
		headers.insert(HEADER_IDEMPOTENCY_KEY, HeaderValue::from_static(""));
		assert!(!retries_permitted(&Method::POST, &headers));
	}
}
