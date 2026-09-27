use super::{
	Arc, ArrayString, Body, BodyExt, Bytes, CONTENT_ENCODING, CONTENT_LENGTH, CompressedBody, HeaderValue,
	Instant, LengthLimitError, Limited, ProxyState, ReplayBody, Request, Response, StatusCode, compression, error,
	error_response, record_completion, retries_permitted, warn,
};

pub enum PreparedBody {
	Ready(ReplayBody, u32),
	Respond(Response<Body>),
}

// Decompress a zstd request body, decide the retry budget, and buffer the body for replay when it fits the
// cap (a declared length above it streams through in one attempt). `Respond` carries a ready error response.
pub async fn prepare_replay_body(
	req: Request<Body>,
	state: &Arc<ProxyState>,
	request_is_zstd: bool,
	backend_id: &ArrayString<256>,
	start: Instant,
) -> PreparedBody {
	let req: Request<Body> = if request_is_zstd {
		match decompress_request(
			req,
			state.proxy_config.max_request_body_bytes,
			state.proxy_config.inline_compress_threshold,
		)
		.await
		{
			Ok(r) => r,
			Err(response) => {
				record_completion(state, start, response.status(), backend_id.as_str());
				return PreparedBody::Respond(response);
			}
		}
	} else {
		req
	};

	// Automatic retries replay the body against another backend, safe only for idempotent methods: a
	// non-idempotent POST/PATCH a backend already committed must not be resent. Allowed otherwise only with
	// an Idempotency-Key header (which asserts the backend deduplicates replays).
	let retries_allowed: bool = retries_permitted(req.method(), req.headers());
	let max_attempts: u32 = if retries_allowed {
		state.retry_config.max_retries + 1
	} else {
		1
	};
	let request_body_cap: u32 = state.proxy_config.max_request_body_bytes;

	let (req_parts, body) = req.into_parts();
	let can_buffer: bool = max_attempts > 1 && !declared_length_exceeds(&req_parts.headers, request_body_cap);
	let (body_bytes, streaming_body): (Option<Bytes>, Option<Body>) = if can_buffer {
		match buffer_request_body(body, request_body_cap).await {
			Ok(bytes) => (Some(bytes), None),
			Err(status) => {
				record_completion(state, start, status, backend_id.as_str());
				let message: &str = if status == StatusCode::PAYLOAD_TOO_LARGE {
					"request body too large"
				} else {
					"failed to read request body"
				};
				return PreparedBody::Respond(error_response(status, message));
			}
		}
	} else {
		(None, Some(body))
	};

	return PreparedBody::Ready(ReplayBody { body_bytes, streaming_body, req_parts }, max_attempts);
}


fn declared_length_exceeds(headers: &axum::http::HeaderMap, cap: u32) -> bool {
	return headers
		.get(CONTENT_LENGTH)
		.and_then(|v| v.to_str().ok())
		.and_then(|v| v.parse::<u64>().ok())
		.map(|len| len > u64::from(cap))
		.unwrap_or(false);
}

// Buffer the request body for retries, held to the cap so a chunked upload (or one whose
// Content-Length lied) cannot balloon proxy memory. Returns the rejection status on failure.
async fn buffer_request_body(body: Body, cap: u32) -> std::result::Result<Bytes, StatusCode> {
	let cap_usize: usize = usize::try_from(cap).unwrap_or(usize::MAX);
	return match Limited::new(body, cap_usize).collect().await {
		Ok(collected) => Ok(collected.to_bytes()),
		Err(e) => {
			if e.downcast_ref::<LengthLimitError>().is_some() {
				warn!(cap, "request body exceeded buffer cap");
				Err(StatusCode::PAYLOAD_TOO_LARGE)
			} else {
				warn!(error = %e, "failed to buffer request body");
				Err(StatusCode::BAD_REQUEST)
			}
		}
	};
}

#[tracing::instrument(skip_all)]
async fn decompress_request(
	req: Request<Body>,
	max_body: u32,
	inline_threshold: u32,
) -> std::result::Result<Request<Body>, Response<Body>> {
	let (mut parts, body) = req.into_parts();

	let max_body_usize: usize = usize::try_from(max_body).unwrap_or(usize::MAX);
	// Bound the compressed input too — without this a client could stream an arbitrarily large
	// body into memory before the decompression bound is ever consulted.
	let body_bytes: Bytes = Limited::new(body, max_body_usize)
		.collect()
		.await
		.map(|c| c.to_bytes())
		.map_err(|e| {
			if e.downcast_ref::<LengthLimitError>().is_some() {
				warn!(max_body, "compressed request body exceeded cap");
				error_response(StatusCode::PAYLOAD_TOO_LARGE, "request body too large")
			} else {
				warn!(error = %e, "failed to read request body for decompression");
				error_response(StatusCode::BAD_REQUEST, "failed to read request body")
			}
		})?;
	let decompressed: Vec<u8> = if body_bytes.len() <= usize::try_from(inline_threshold).unwrap_or(usize::MAX) {
		compression::decompress_bounded(&body_bytes, max_body_usize).map_err(|e| {
			warn!(error = %e, "request decompression failed");
			error_response(StatusCode::BAD_REQUEST, "invalid zstd body")
		})?
	} else {
		tokio::task::spawn_blocking(move || compression::decompress_bounded(&body_bytes, max_body_usize))
			.await
			.map_err(|e| {
				error!(error = %e, "decompression task panicked");
				error_response(StatusCode::INTERNAL_SERVER_ERROR, "decompression failed")
			})?
			.map_err(|e| {
				warn!(error = %e, "request decompression failed");
				error_response(StatusCode::BAD_REQUEST, "invalid zstd body")
			})?
	};

	parts.headers.remove(CONTENT_ENCODING);
	parts
		.headers
		.insert(CONTENT_LENGTH, HeaderValue::from(decompressed.len()));

	return Ok(Request::from_parts(parts, Body::from(decompressed)));
}

pub fn compress_response(response: Response<Body>, min_bytes: u32, compression_level: i32) -> Response<Body> {
	let (mut parts, body) = response.into_parts();

	if let Some(len) = parts
		.headers
		.get(CONTENT_LENGTH)
		.and_then(|v| v.to_str().ok())
		.and_then(|v| v.parse::<u32>().ok())
		&& len < min_bytes
	{
		return Response::from_parts(parts, body);
	}

	// Build the encoder before touching the headers. `with_level` consumes the body, so a failure
	// after stamping `Content-Encoding: zstd` would leave a 200 whose headers claim zstd over an
	// empty body — silent truncation. Surface the failure as a 500 instead.
	let compressed: CompressedBody<Body> = match CompressedBody::with_level(body, compression_level) {
		Ok(c) => c,
		Err(e) => {
			error!(error = %e, "failed to initialize zstd encoder for response compression");
			return error_response(StatusCode::INTERNAL_SERVER_ERROR, "response compression failed");
		}
	};

	parts.headers.insert(CONTENT_ENCODING, HeaderValue::from_static("zstd"));
	parts.headers.remove(CONTENT_LENGTH);

	return Response::from_parts(parts, Body::new(compressed));
}

#[cfg(test)]
mod tests {
	use std::collections::HashMap;
	use std::pin::Pin;
	use std::task::{Context, Poll};

	use http_body::{Body as HttpBody, Frame};

	use super::*;
	use crate::acl::AccessControl;
	use crate::config::TimeoutConfig;
	use crate::proxy::handler::{ReloadableState, TestProxyStateParams};
	use crate::proxy::router::Router;
	use crate::tunnel::revocation::RevocationSet;

	#[tokio::test]
	async fn test_decompress_request_valid() {
		let original = b"hello world from the client";
		let compressed: Vec<u8> =
			compression::compress_with_level(original, compression::DEFAULT_COMPRESSION_LEVEL).unwrap();

		let req = Request::builder()
			.header(CONTENT_ENCODING, "zstd")
			.body(Body::from(compressed))
			.unwrap();

		let result = decompress_request(req, 10 * 1024 * 1024, 8192).await;
		assert!(result.is_ok());
		let decompressed_req = result.unwrap();
		assert!(!decompressed_req.headers().contains_key(CONTENT_ENCODING));

		let body_bytes = decompressed_req.into_body().collect().await.unwrap().to_bytes();
		assert_eq!(&body_bytes[..], original);
	}

	#[tokio::test]
	async fn test_decompress_request_compressed_body_over_cap_rejected() {
		let original: Vec<u8> = b"payload that compresses to more than eight bytes".to_vec();
		let compressed: Vec<u8> =
			compression::compress_with_level(&original, compression::DEFAULT_COMPRESSION_LEVEL).unwrap();
		assert!(compressed.len() > 8, "fixture must exceed the cap");

		let req = Request::builder()
			.header(CONTENT_ENCODING, "zstd")
			.body(Body::from(compressed))
			.unwrap();

		let result = decompress_request(req, 8, 8192).await;
		let resp = match result {
			Err(r) => r,
			Ok(_) => panic!("expected over-cap rejection"),
		};
		assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
	}

	#[test]
	fn test_declared_length_exceeds_over_cap() {
		let mut headers = axum::http::HeaderMap::new();
		headers.insert(CONTENT_LENGTH, HeaderValue::from_static("1001"));
		assert!(declared_length_exceeds(&headers, 1000));
	}

	#[test]
	fn test_declared_length_at_cap_allows_buffering() {
		let mut headers = axum::http::HeaderMap::new();
		headers.insert(CONTENT_LENGTH, HeaderValue::from_static("1000"));
		assert!(!declared_length_exceeds(&headers, 1000));
	}

	#[test]
	fn test_declared_length_absent_allows_buffering() {
		// Chunked bodies declare no length — the Limited guard catches those at read time instead.
		let headers = axum::http::HeaderMap::new();
		assert!(!declared_length_exceeds(&headers, 1000));
	}

	#[test]
	fn test_declared_length_garbage_allows_buffering() {
		let mut headers = axum::http::HeaderMap::new();
		headers.insert(CONTENT_LENGTH, HeaderValue::from_static("not-a-number"));
		assert!(!declared_length_exceeds(&headers, 1000));
	}

	#[tokio::test]
	async fn test_buffer_request_body_under_cap() {
		let body: Body = Body::from(&b"small body"[..]);
		let bytes: Bytes = buffer_request_body(body, 1024).await.unwrap();
		assert_eq!(&bytes[..], b"small body");
	}

	#[tokio::test]
	async fn test_buffer_request_body_over_cap_rejected() {
		// No Content-Length short-circuit here: the Limited guard itself must trip.
		let body: Body = Body::from(vec![0u8; 2048]);
		let result = buffer_request_body(body, 1024).await;
		assert_eq!(result.unwrap_err(), StatusCode::PAYLOAD_TOO_LARGE);
	}

	#[tokio::test]
	async fn test_decompress_request_invalid_zstd() {
		let req = Request::builder()
			.header(CONTENT_ENCODING, "zstd")
			.body(Body::from(vec![0xFF, 0xFE, 0xFD]))
			.unwrap();

		let result = decompress_request(req, 10 * 1024 * 1024, 8192).await;
		assert!(result.is_err());
		let resp = result.unwrap_err();
		assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
	}

	// Larger than the 10 MiB default request-body cap, so the streaming buffer trips PAYLOAD_TOO_LARGE.
	const OVER_DEFAULT_CAP_BYTES: usize = 10 * 1024 * 1024 + 1;

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

	fn make_state() -> Arc<ProxyState> {
		install_crypto();
		let reloadable: ReloadableState = ReloadableState {
			router: Router::new(&[]),
			backend_pools: HashMap::new(),
			acl: AccessControl::new(vec![], vec![]),
		};
		return ProxyState::for_test(TestProxyStateParams::new(
			reloadable,
			RevocationSet::default(),
			client_config(),
			TimeoutConfig::default(),
		));
	}

	fn backend_id() -> ArrayString<256> {
		return ArrayString::from("svc").unwrap();
	}

	// A request body that errors on the first frame poll, so buffering fails with a non-length error.
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

	#[tokio::test]
	async fn prepare_replay_buffers_idempotent_body_for_retry() {
		let state: Arc<ProxyState> = make_state();
		let req: Request<Body> = Request::builder().method("GET").uri("/x").body(Body::from("hello")).unwrap();

		let prepared: PreparedBody =
			prepare_replay_body(req, &state, false, &backend_id(), Instant::now()).await;

		match prepared {
			PreparedBody::Ready(replay, max_attempts) => {
				assert_eq!(max_attempts, state.retry_config.max_retries + 1, "an idempotent method gets the full retry budget");
				assert_eq!(replay.body_bytes.as_deref(), Some(&b"hello"[..]), "the body is buffered for replay");
				assert!(replay.streaming_body.is_none());
			}
			PreparedBody::Respond(_) => panic!("a small idempotent body must be Ready"),
		}
	}

	#[tokio::test]
	async fn prepare_replay_streams_non_idempotent_body_without_buffering() {
		let state: Arc<ProxyState> = make_state();
		let req: Request<Body> = Request::builder().method("POST").uri("/x").body(Body::from("payload")).unwrap();

		let prepared: PreparedBody =
			prepare_replay_body(req, &state, false, &backend_id(), Instant::now()).await;

		match prepared {
			PreparedBody::Ready(replay, max_attempts) => {
				assert_eq!(max_attempts, 1, "a non-idempotent POST is never auto-retried");
				assert!(replay.body_bytes.is_none(), "a one-shot body is not buffered");
				assert!(replay.streaming_body.is_some());
			}
			PreparedBody::Respond(_) => panic!("a POST body must still be Ready to forward once"),
		}
	}

	#[tokio::test]
	async fn prepare_replay_streams_when_declared_length_exceeds_cap() {
		let state: Arc<ProxyState> = make_state();
		// A declared length above the cap must stream through in one attempt, not buffer.
		let huge: u64 = u64::from(state.proxy_config.max_request_body_bytes) + 1;
		let req: Request<Body> = Request::builder()
			.method("GET")
			.uri("/x")
			.header(CONTENT_LENGTH, huge.to_string())
			.body(Body::from("small-actual-body"))
			.unwrap();

		let prepared: PreparedBody =
			prepare_replay_body(req, &state, false, &backend_id(), Instant::now()).await;

		match prepared {
			PreparedBody::Ready(replay, _) => {
				assert!(replay.body_bytes.is_none(), "an over-cap declared length skips buffering");
				assert!(replay.streaming_body.is_some());
			}
			PreparedBody::Respond(_) => panic!("an over-cap declared length still streams, not rejects"),
		}
	}

	#[tokio::test]
	async fn prepare_replay_decompresses_zstd_body() {
		let state: Arc<ProxyState> = make_state();
		let original = b"decompressed request payload";
		let compressed: Vec<u8> =
			compression::compress_with_level(original, compression::DEFAULT_COMPRESSION_LEVEL).unwrap();
		let req: Request<Body> = Request::builder()
			.method("GET")
			.uri("/x")
			.header(CONTENT_ENCODING, "zstd")
			.body(Body::from(compressed))
			.unwrap();

		let prepared: PreparedBody =
			prepare_replay_body(req, &state, true, &backend_id(), Instant::now()).await;

		match prepared {
			PreparedBody::Ready(replay, _) => {
				assert_eq!(replay.body_bytes.as_deref(), Some(&original[..]), "the zstd body is decompressed then buffered");
			}
			PreparedBody::Respond(_) => panic!("a valid zstd body must decompress to Ready"),
		}
	}

	#[tokio::test]
	async fn prepare_replay_responds_on_invalid_zstd_body() {
		let state: Arc<ProxyState> = make_state();
		let req: Request<Body> = Request::builder()
			.method("GET")
			.uri("/x")
			.header(CONTENT_ENCODING, "zstd")
			.body(Body::from(vec![0xFF, 0xFE, 0xFD]))
			.unwrap();

		let prepared: PreparedBody =
			prepare_replay_body(req, &state, true, &backend_id(), Instant::now()).await;

		match prepared {
			PreparedBody::Respond(response) => assert_eq!(response.status(), StatusCode::BAD_REQUEST),
			PreparedBody::Ready(..) => panic!("an invalid zstd body must Respond with an error"),
		}
	}

	#[tokio::test]
	async fn prepare_replay_responds_bad_request_when_body_read_fails() {
		let state: Arc<ProxyState> = make_state();
		// Idempotent method enables buffering; the erroring body then fails the read as a non-length error.
		let req: Request<Body> = Request::builder().method("GET").uri("/x").body(Body::new(ErrBody)).unwrap();

		let prepared: PreparedBody =
			prepare_replay_body(req, &state, false, &backend_id(), Instant::now()).await;

		match prepared {
			PreparedBody::Respond(response) => assert_eq!(response.status(), StatusCode::BAD_REQUEST),
			PreparedBody::Ready(..) => panic!("an unreadable body must Respond, not proceed"),
		}
	}

	#[tokio::test]
	async fn prepare_replay_responds_payload_too_large_when_buffered_body_exceeds_cap() {
		let state: Arc<ProxyState> = make_state();
		// No Content-Length, idempotent method: buffering runs and the Limited guard trips over the cap.
		let req: Request<Body> = Request::builder()
			.method("GET")
			.uri("/x")
			.body(Body::from(vec![0u8; OVER_DEFAULT_CAP_BYTES]))
			.unwrap();

		let prepared: PreparedBody =
			prepare_replay_body(req, &state, false, &backend_id(), Instant::now()).await;

		match prepared {
			PreparedBody::Respond(response) => assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE),
			PreparedBody::Ready(..) => panic!("an over-cap buffered body must Respond 413"),
		}
	}

	#[tokio::test]
	async fn decompress_request_uses_offload_path_over_inline_threshold() {
		// An inline threshold of zero forces the spawn_blocking offload branch for any non-empty body.
		let original = b"payload decompressed off-thread";
		let compressed: Vec<u8> =
			compression::compress_with_level(original, compression::DEFAULT_COMPRESSION_LEVEL).unwrap();
		let req: Request<Body> = Request::builder()
			.header(CONTENT_ENCODING, "zstd")
			.body(Body::from(compressed))
			.unwrap();

		let result = decompress_request(req, 10 * 1024 * 1024, 0).await;

		let decompressed_req = match result {
			Ok(r) => r,
			Err(_) => panic!("the offload path must decompress a valid body"),
		};
		let body_bytes = decompressed_req.into_body().collect().await.unwrap().to_bytes();
		assert_eq!(&body_bytes[..], original);
	}
}
