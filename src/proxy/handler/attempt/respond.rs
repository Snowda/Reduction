use axum::body::Body;
use axum::http::request::Parts;
use axum::http::{Response, StatusCode};
use bytes::Bytes;
use http_body_util::BodyExt;
use tracing::warn;

use crate::cache::CacheKeyRef;
use crate::cache_control::CacheDirectives;
use crate::proxy::handler::{
	error_response, is_cacheable_status, maybe_compress, record_completion, response_is_encoded,
	response_permits_shared_caching, vary_permits_caching,
};

use super::{AttemptOutcome, RequestCtx};

// Whether a forward-success response may be stored in the shared cache. A backend-encoded body is keyed
// without an encoding dimension (its Content-Encoding is the backend's — the proxy adds zstd only after
// this store site), so an encoded body is refused rather than replayed to a client that never asked for it.
pub fn should_cache_response(ctx: &RequestCtx<'_>, response: &Response<Body>, status: StatusCode, directives: &CacheDirectives) -> bool {
	return ctx.state.cache_config.enabled
		&& ctx.is_cacheable_method
		&& is_cacheable_status(status)
		&& !response_is_encoded(response)
		&& vary_permits_caching(response.headers())
		&& response_permits_shared_caching(ctx.request_has_cookie, directives);
}

// Buffer a cacheable response, store it under the request's cache key, and return it (compressed if the
// client accepts zstd). A failure to buffer the body surfaces as a 502 rather than a corrupt cache entry.
pub async fn store_and_respond(
	ctx: &RequestCtx<'_>,
	response: Response<Body>,
	status: StatusCode,
	directives: &CacheDirectives,
	req_parts: &Parts,
) -> AttemptOutcome {
	let (parts, body) = response.into_parts();
	let body_bytes: Bytes = match body.collect().await {
		Ok(collected) => collected.to_bytes(),
		Err(e) => {
			warn!(error = %e, "failed to buffer response for caching");
			record_completion(ctx.state, ctx.start, status, ctx.backend_id.as_str());
			return AttemptOutcome::Return(error_response(StatusCode::BAD_GATEWAY, "failed to read response"));
		}
	};

	// Method and path for the cache key are read from the still-live request parts and borrowed as &str.
	// The path expression matches the get site so a put stores under the exact key a later get looks up.
	let cache_path: &str = req_parts
		.uri
		.path_and_query()
		.map(|pq| pq.as_str())
		.unwrap_or(req_parts.uri.path());
	let key: CacheKeyRef<'_> = CacheKeyRef {
		method: req_parts.method.as_str(),
		path: cache_path,
		identity: ctx.cache_identity,
	};
	ctx.state
		.response_cache
		.put(key, status, &parts.headers, body_bytes.clone(), directives);

	let response: Response<Body> = Response::from_parts(parts, Body::from(body_bytes));
	record_completion(ctx.state, ctx.start, status, ctx.backend_id.as_str());
	return AttemptOutcome::Return(maybe_compress(response, ctx.accepts_zstd, directives, &ctx.state.compression_config));
}

#[cfg(test)]
mod tests {
	use std::pin::Pin;
	use std::task::{Context, Poll};

	use axum::body::Body;
	use axum::http::request::Parts;
	use axum::http::{Response, StatusCode};
	use bytes::Bytes;
	use http_body::{Body as HttpBody, Frame};
	use http_body_util::BodyExt;

	use super::super::testutil::*;
	use super::{AttemptOutcome, CacheDirectives, CacheKeyRef, should_cache_response, store_and_respond};

	// A response body that fails on the first frame poll, so store_and_respond's `collect().await` errors.
	struct ErrBody;

	impl HttpBody for ErrBody {
		type Data = Bytes;
		type Error = std::io::Error;

		fn poll_frame(
			self: Pin<&mut Self>,
			_cx: &mut Context<'_>,
		) -> Poll<Option<std::result::Result<Frame<Bytes>, std::io::Error>>> {
			return Poll::Ready(Some(Err(std::io::Error::other("boom"))));
		}
	}

	// --- should_cache_response -------------------------------------------------------------------

	#[test]
	fn should_cache_response_true_for_public_ok_get() {
		let state = make_state(cb_opens_immediately(), fast_retry(), cache_on());
		let fx: Fixture = Fixture::new(state, vec![make_backend("b1")]);
		let ctx = fx.ctx(2, true, false, false);
		let resp: Response<Body> = response_with(StatusCode::OK, Some("public, max-age=300"), "ok");
		let directives: CacheDirectives = CacheDirectives::from_response(&resp);

		assert!(should_cache_response(&ctx, &resp, StatusCode::OK, &directives));
	}

	#[test]
	fn should_cache_response_false_when_cache_disabled() {
		let state = make_state(cb_opens_immediately(), fast_retry(), cache_off());
		let fx: Fixture = Fixture::new(state, vec![make_backend("b1")]);
		let ctx = fx.ctx(2, true, false, false);
		let resp: Response<Body> = response_with(StatusCode::OK, Some("public"), "ok");
		let directives: CacheDirectives = CacheDirectives::from_response(&resp);

		assert!(!should_cache_response(&ctx, &resp, StatusCode::OK, &directives), "disabled cache never stores");
	}

	#[test]
	fn should_cache_response_false_for_non_cacheable_method() {
		let state = make_state(cb_opens_immediately(), fast_retry(), cache_on());
		let fx: Fixture = Fixture::new(state, vec![make_backend("b1")]);
		let ctx = fx.ctx(2, false, false, false);
		let resp: Response<Body> = response_with(StatusCode::OK, Some("public"), "ok");
		let directives: CacheDirectives = CacheDirectives::from_response(&resp);

		assert!(!should_cache_response(&ctx, &resp, StatusCode::OK, &directives));
	}

	#[test]
	fn should_cache_response_false_for_non_ok_status() {
		let state = make_state(cb_opens_immediately(), fast_retry(), cache_on());
		let fx: Fixture = Fixture::new(state, vec![make_backend("b1")]);
		let ctx = fx.ctx(2, true, false, false);
		let resp: Response<Body> = response_with(StatusCode::NO_CONTENT, Some("public"), "");
		let directives: CacheDirectives = CacheDirectives::from_response(&resp);

		assert!(!should_cache_response(&ctx, &resp, StatusCode::NO_CONTENT, &directives));
	}

	#[test]
	fn should_cache_response_false_for_encoded_body() {
		let state = make_state(cb_opens_immediately(), fast_retry(), cache_on());
		let fx: Fixture = Fixture::new(state, vec![make_backend("b1")]);
		let ctx = fx.ctx(2, true, false, false);
		let resp: Response<Body> = Response::builder()
			.status(StatusCode::OK)
			.header("cache-control", "public")
			.header("content-encoding", "gzip")
			.body(Body::from("x"))
			.unwrap();
		let directives: CacheDirectives = CacheDirectives::from_response(&resp);

		assert!(!should_cache_response(&ctx, &resp, StatusCode::OK, &directives), "a backend-encoded body is never shared-cached");
	}

	#[test]
	fn should_cache_response_false_when_request_has_cookie() {
		let state = make_state(cb_opens_immediately(), fast_retry(), cache_on());
		let fx: Fixture = Fixture::new(state, vec![make_backend("b1")]);
		let ctx = fx.ctx(2, true, true, false);
		let resp: Response<Body> = response_with(StatusCode::OK, Some("public"), "ok");
		let directives: CacheDirectives = CacheDirectives::from_response(&resp);

		assert!(!should_cache_response(&ctx, &resp, StatusCode::OK, &directives), "a cookie-bearing request never caches");
	}

	// --- store_and_respond -----------------------------------------------------------------------

	#[tokio::test]
	async fn store_and_respond_populates_cache_and_returns_body() {
		let state = make_state(cb_opens_immediately(), fast_retry(), cache_on());
		let fx: Fixture = Fixture::new(state, vec![make_backend("b1")]);
		let ctx = fx.ctx(2, true, false, false);
		let resp: Response<Body> = response_with(StatusCode::OK, Some("public, max-age=300"), "cached-body");
		let directives: CacheDirectives = CacheDirectives::from_response(&resp);
		let parts: Parts = parts_for("GET", "/foo");

		let outcome: AttemptOutcome = store_and_respond(&ctx, resp, StatusCode::OK, &directives, &parts).await;

		match outcome {
			AttemptOutcome::Return(response) => {
				assert_eq!(response.status(), StatusCode::OK);
				let bytes: Bytes = response.into_body().collect().await.unwrap().to_bytes();
				assert_eq!(&bytes[..], b"cached-body", "the returned body is the stored body");
			}
			_ => panic!("a cacheable success must Return a buffered response"),
		}

		// The entry must be retrievable under the exact key store_and_respond wrote.
		let key: CacheKeyRef<'_> = CacheKeyRef { method: "GET", path: "/foo", identity: "" };
		assert!(fx.state.response_cache.get(key).is_some(), "the response must be stored in the cache");
	}

	#[tokio::test]
	async fn store_and_respond_returns_502_when_body_unreadable() {
		let state = make_state(cb_opens_immediately(), fast_retry(), cache_on());
		let fx: Fixture = Fixture::new(state, vec![make_backend("b1")]);
		let ctx = fx.ctx(2, true, false, false);
		let resp: Response<Body> = Response::builder()
			.status(StatusCode::OK)
			.header("cache-control", "public")
			.body(Body::new(ErrBody))
			.unwrap();
		let directives: CacheDirectives = CacheDirectives::from_response(&resp);
		let parts: Parts = parts_for("GET", "/foo");

		let outcome: AttemptOutcome = store_and_respond(&ctx, resp, StatusCode::OK, &directives, &parts).await;

		match outcome {
			AttemptOutcome::Return(response) => assert_eq!(response.status(), StatusCode::BAD_GATEWAY),
			_ => panic!("an unreadable body must surface as a 502, not a corrupt cache entry"),
		}
		let key: CacheKeyRef<'_> = CacheKeyRef { method: "GET", path: "/foo", identity: "" };
		assert!(fx.state.response_cache.get(key).is_none(), "a failed buffer must not leave a cache entry");
	}
}
