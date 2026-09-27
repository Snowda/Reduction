use super::{
	Arc, ArrayString, ArrayVec, Body, BackendConfig, BackendPool, Bytes, CacheDirectives, CircuitState,
	ConnPermitGuard, Duration, HalfOpenGuard, Instant, IpAddr, KeyValue, MAX_BACKENDS, Parts, PeerIdentity,
	ProxyState, ReductionError, Request, Response, Result, StatusCode, backend_label, backoff_delay, error,
	error_response, forward_request, from_ref, info, is_retryable_status, mark_failed, maybe_compress,
	record_completion, select_backend_excluding, warn,
};

// The cold-start wake/park subsystem (F1/F2) lives in a submodule.
mod wake;
// The response-caching decision and shared-cache store live in a submodule.
mod respond;
#[cfg(test)]
mod testutil;

use respond::{should_cache_response, store_and_respond};
use wake::park_for_wake;

pub struct RequestCtx<'a> {
	pub state: &'a Arc<ProxyState>,
	pub pool: &'a BackendPool,
	pub client_ip: IpAddr,
	pub client_identity: Option<PeerIdentity>,
	pub backend_id: ArrayString<256>,
	pub cache_identity: &'a str,
	pub start: Instant,
	pub max_attempts: u32,
	pub is_cacheable_method: bool,
	pub request_has_cookie: bool,
	pub accepts_zstd: bool,
}

// The request body prepared for replay: a buffered copy (retryable) or a one-shot streaming body, plus the request parts cloned per attempt.
pub struct ReplayBody {
	pub body_bytes: Option<Bytes>,
	pub streaming_body: Option<Body>,
	pub req_parts: Parts,
}

// State across retry attempts: tried backends + the last retryable response/error for budget exhaustion.
pub struct RetryState {
	pub failed_backends: ArrayVec<ArrayString<256>, MAX_BACKENDS>,
	pub last_response: Option<Response<Body>>,
	pub last_error_msg: Option<String>,
}

// A backend selected and gated for one attempt, carrying its per-attempt guards (connection permit, half-open probe).
pub struct Selected {
	backend: BackendConfig,
	sel_label: KeyValue,
	conn: ConnPermitGuard,
	half_open: Option<HalfOpenGuard>,
}

// How one attempt ended: retry next, stop, return a response, or stream a success (caller bundles its guards).
pub enum AttemptOutcome {
	Continue,
	Break,
	Return(Response<Body>),
	Stream {
		response: Response<Body>,
		conn: ConnPermitGuard,
		half_open: Option<HalfOpenGuard>,
	},
}

// Loop control for a skipped attempt (tiny enum so select_and_gate's Result Err stays small).
enum Skip {
	Break,
	Continue,
}

// Select a backend (preferring untried), acquire its connection permit, and gate on the circuit breaker.
// `Err(Skip)` carries loop control: Break (no backend) or Continue (permit exhausted / circuit open).
fn select_and_gate(ctx: &RequestCtx<'_>, attempt: u32, retry: &mut RetryState) -> std::result::Result<Selected, Skip> {
	// Prefer a backend not yet tried this request; fall back to re-selecting among all of them so a
	// retry still fires for single-backend pools and exhausted multi-backend pools.
	let selection: Result<BackendConfig> =
		select_backend_excluding(ctx.pool, ctx.client_ip, &ctx.state.health_rx, &ctx.state.conn_pool, &retry.failed_backends)
			.or_else(|_| select_backend_excluding(ctx.pool, ctx.client_ip, &ctx.state.health_rx, &ctx.state.conn_pool, &[]));
	let backend: BackendConfig = match selection {
		Ok(b) => b,
		Err(e) => {
			warn!(attempt, error = %e, "no backend available");
			retry.last_error_msg = Some(format!("{e}"));
			return Err(Skip::Break);
		}
	};
	let sel_label: KeyValue = backend_label(&ctx.state.labels, &backend.id);
	ctx.state.metrics.backend_selections.add(1, from_ref(&sel_label));
	let sel_attr: [KeyValue; 1] = [sel_label.clone()];

	// Per-attempt connection permit — released when this attempt ends, or, on the winning attempt, moved
	// into the response body so it is held until the body finishes streaming.
	let conn: ConnPermitGuard = match ctx.state.conn_pool.try_acquire_conn_permit(&backend) {
		Ok(permit) => {
			ctx.state.metrics.backend_active_connections.add(1, &sel_attr);
			ConnPermitGuard {
				counter: ctx.state.metrics.backend_active_connections.clone(),
				backend_kv: sel_label.clone(),
				_permit: permit,
			}
		}
		Err(_) => {
			ctx.state.metrics.backend_conn_limit_rejected.add(1, &sel_attr);
			warn!(
				backend = backend.id.as_str(),
				max = backend.max_connections,
				"connection limit reached, trying another backend"
			);
			retry.last_error_msg = Some("backend connection limit reached".into());
			mark_failed(&mut retry.failed_backends, backend.id);
			return Err(Skip::Continue);
		}
	};

	// Per-attempt circuit-breaker gate; an open circuit skips this backend, not the request.
	let half_open: Option<HalfOpenGuard>;
	match ctx.state.circuit_breakers.check(backend.id.as_str()) {
		(CircuitState::Open, _) => {
			ctx.state.metrics.circuit_open_total.add(1, &sel_attr);
			warn!(backend = backend.id.as_str(), "circuit breaker open, trying another backend");
			retry.last_error_msg = Some("circuit open".into());
			mark_failed(&mut retry.failed_backends, backend.id);
			return Err(Skip::Continue);
		}
		(CircuitState::HalfOpen, guard) => {
			half_open = guard;
			ctx.state.metrics.circuit_half_open_probes.add(1, &sel_attr);
		}
		(CircuitState::Closed, _) => {
			half_open = None;
		}
	}

	return Ok(Selected { backend, sel_label, conn, half_open });
}

// Rebuild the request for one attempt: a buffered body clones; a streaming body consumed once yields None (stop retrying).
fn build_retry_req(replay: &mut ReplayBody, backend: &BackendConfig, attempt: u32) -> Option<Request<Body>> {
	return match &replay.body_bytes {
		Some(bytes) => Some(Request::from_parts(replay.req_parts.clone(), Body::from(bytes.clone()))),
		None => match replay.streaming_body.take() {
			Some(body) => Some(Request::from_parts(replay.req_parts.clone(), body)),
			None => {
				warn!(
					backend = backend.id.as_str(),
					attempt, "streaming body already consumed; cannot retry"
				);
				None
			}
		},
	};
}

// Run one attempt end to end: select+gate a backend, rebuild the request, forward it, interpret the result.
pub async fn run_attempt(ctx: &RequestCtx<'_>, attempt: u32, remaining: Duration, replay: &mut ReplayBody, retry: &mut RetryState) -> AttemptOutcome {
	let selected: Selected = match select_and_gate(ctx, attempt, retry) {
		Ok(s) => s,
		Err(Skip::Break) => return AttemptOutcome::Break,
		Err(Skip::Continue) => return AttemptOutcome::Continue,
	};
	let retry_req: Request<Body> = match build_retry_req(replay, &selected.backend, attempt) {
		Some(r) => r,
		None => return AttemptOutcome::Break,
	};
	info!(backend = selected.backend.id.as_str(), attempt, "forwarding request");
	let result: Result<Response<Body>> = forward_request(
		retry_req,
		&selected.backend,
		ctx.state,
		remaining,
		ctx.client_identity.as_ref(),
		ctx.client_ip,
	)
	.await;
	// Pass only the request parts (not the whole ReplayBody, whose streaming `Body` is !Sync) so the
	// forward-handling future stays Send across its awaits.
	return handle_response(ctx, attempt, selected, result, &replay.req_parts, retry).await;
}

// A transport-level forward failure: record it, then retry with backoff or return 502 on the final attempt.
async fn handle_forward_error(
	ctx: &RequestCtx<'_>,
	attempt: u32,
	backend: &BackendConfig,
	sel_label: KeyValue,
	e: ReductionError,
	retry: &mut RetryState,
) -> AttemptOutcome {
	// F1/F2: a transport miss on a wakeable backend is a cold start, not a failure. Park the request
	// for a wake (F1) rather than counting a breaker failure (F2), so it releases the moment the woken
	// backend is reachable — one round trip, no client retry. Every other error counts.
	if backend.wakeable && e.is_transport_miss() {
		return park_for_wake(ctx, backend).await;
	}
	ctx.state.circuit_breakers.record_failure(backend.id.as_str());
	ctx.state.metrics.retry_attempts.add(
		1,
		&[sel_label, KeyValue::new("attempt", i64::from(attempt + 1)), KeyValue::new("outcome", "error")],
	);
	if attempt + 1 < ctx.max_attempts {
		warn!(backend = backend.id.as_str(), attempt, error = %e, "forward failed, will retry");
		mark_failed(&mut retry.failed_backends, backend.id);
		tokio::time::sleep(backoff_delay(attempt, &ctx.state.retry_config)).await;
		retry.last_error_msg = Some(format!("{e}"));
		return AttemptOutcome::Continue;
	}
	error!(backend = backend.id.as_str(), error = %e, "failed to forward request after all attempts");
	record_completion(ctx.state, ctx.start, StatusCode::BAD_GATEWAY, ctx.backend_id.as_str());
	return AttemptOutcome::Return(error_response(StatusCode::BAD_GATEWAY, "backend error"));
}

// Interpret a forward result: a transport error or retryable status retries (or returns on the final attempt);
// a cacheable success is stored and returned buffered; any other success streams with its guards moved into the body.
async fn handle_response(
	ctx: &RequestCtx<'_>,
	attempt: u32,
	selected: Selected,
	result: Result<Response<Body>>,
	req_parts: &Parts,
	retry: &mut RetryState,
) -> AttemptOutcome {
	let Selected { backend, sel_label, conn, half_open } = selected;

	let response: Response<Body> = match result {
		Ok(response) => response,
		Err(e) => return handle_forward_error(ctx, attempt, &backend, sel_label, e, retry).await,
	};

	let status: StatusCode = response.status();
	if is_retryable_status(status) {
		ctx.state.circuit_breakers.record_failure(backend.id.as_str());
		ctx.state.metrics.retry_attempts.add(
			1,
			&[
				sel_label,
				KeyValue::new("attempt", i64::from(attempt + 1)),
				KeyValue::new("outcome", "retryable_status"),
			],
		);
		if attempt + 1 < ctx.max_attempts {
			warn!(
				backend = backend.id.as_str(),
				attempt,
				status = status.as_u16(),
				"retryable status, will retry"
			);
			mark_failed(&mut retry.failed_backends, backend.id);
			tokio::time::sleep(backoff_delay(attempt, &ctx.state.retry_config)).await;
			retry.last_response = Some(response);
			return AttemptOutcome::Continue;
		}
		// Final attempt — fall through and return this response.
	}

	if status.is_server_error() {
		ctx.state.circuit_breakers.record_failure(backend.id.as_str());
	} else {
		ctx.state.circuit_breakers.record_success(backend.id.as_str());
	}

	let cache_directives: CacheDirectives = CacheDirectives::from_response(&response);
	if should_cache_response(ctx, &response, status, &cache_directives) {
		return store_and_respond(ctx, response, status, &cache_directives, req_parts).await;
	}

	record_completion(ctx.state, ctx.start, status, ctx.backend_id.as_str());
	let response: Response<Body> = maybe_compress(response, ctx.accepts_zstd, &cache_directives, &ctx.state.compression_config);
	// Winning attempt: hand the per-attempt guards back so the caller bundles them with the
	// request-level guards into the streaming body.
	return AttemptOutcome::Stream { response, conn, half_open };
}

#[cfg(test)]
mod tests {
	use std::net::SocketAddr;

	use super::testutil::*;
	use super::*;
	use crate::cache::CacheKeyRef;
	use crate::config::TransportKind;

	// --- build_retry_req -------------------------------------------------------------------------

	#[test]
	fn build_retry_req_clones_buffered_body_and_leaves_it_reusable() {
		let backend: BackendConfig = make_backend("b1");
		let mut replay: ReplayBody = ReplayBody {
			body_bytes: Some(Bytes::from_static(b"payload")),
			streaming_body: None,
			req_parts: parts_for("GET", "/x"),
		};

		let first: Option<Request<Body>> = build_retry_req(&mut replay, &backend, 0);
		let second: Option<Request<Body>> = build_retry_req(&mut replay, &backend, 1);

		// A buffered body clones, so both attempts get a request and the buffer survives.
		assert!(first.is_some());
		assert!(second.is_some(), "a buffered body must be replayable across attempts");
		assert!(replay.body_bytes.is_some());
	}

	#[test]
	fn build_retry_req_consumes_streaming_body_once_then_refuses() {
		let backend: BackendConfig = make_backend("b1");
		let mut replay: ReplayBody = ReplayBody {
			body_bytes: None,
			streaming_body: Some(Body::from("streamed")),
			req_parts: parts_for("POST", "/x"),
		};

		let first: Option<Request<Body>> = build_retry_req(&mut replay, &backend, 0);
		let second: Option<Request<Body>> = build_retry_req(&mut replay, &backend, 1);

		assert!(first.is_some(), "the first attempt takes the one-shot streaming body");
		assert!(second.is_none(), "a consumed streaming body cannot be replayed");
		assert!(replay.streaming_body.is_none());
	}

	#[test]
	fn build_retry_req_none_when_no_body_available() {
		let backend: BackendConfig = make_backend("b1");
		let mut replay: ReplayBody = ReplayBody {
			body_bytes: None,
			streaming_body: None,
			req_parts: parts_for("GET", "/x"),
		};

		assert!(build_retry_req(&mut replay, &backend, 0).is_none());
	}

	// --- select_and_gate -------------------------------------------------------------------------

	#[test]
	fn select_and_gate_breaks_when_no_backend_available() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_off());
		let fx: Fixture = Fixture::new(state, vec![]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		let mut retry: RetryState = empty_retry();

		let outcome = select_and_gate(&ctx, 0, &mut retry);

		assert!(matches!(outcome, Err(Skip::Break)), "an empty pool must Break the retry loop");
		assert!(retry.last_error_msg.is_some(), "the no-backend error is recorded for the final response");
	}

	#[test]
	fn select_and_gate_returns_selected_for_healthy_closed_backend() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_off());
		let fx: Fixture = Fixture::new(state, vec![make_backend("b1")]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		let mut retry: RetryState = empty_retry();

		let outcome = select_and_gate(&ctx, 0, &mut retry);

		match outcome {
			Ok(selected) => {
				assert_eq!(selected.backend.id.as_str(), "b1");
				assert!(selected.half_open.is_none(), "a closed circuit carries no half-open probe");
			}
			_ => panic!("a healthy closed backend must be selected"),
		}
	}

	#[test]
	fn select_and_gate_breaks_when_only_backend_fully_pressured() {
		// Holding the only permit drives the backend's connection pressure to 1.0, which the balancer
		// scores as ineligible (weight 0) — so selection returns nothing and the loop Breaks. This is
		// the deterministic single-threaded outcome; the connection-limit `Continue` branch (the
		// try_acquire_conn_permit Err arm) is only reachable when a permit is taken between selection and
		// acquire, a TOCTOU race exercised concurrently by the `h2_pool_caps_and_evicts_dead_connections`
		// integration test, not here.
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_off());
		let backend: BackendConfig = make_backend_capped("b1", 1);
		let _held = state.conn_pool.try_acquire_conn_permit(&backend).unwrap();
		let fx: Fixture = Fixture::new(state, vec![backend]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		let mut retry: RetryState = empty_retry();

		let outcome = select_and_gate(&ctx, 0, &mut retry);

		assert!(matches!(outcome, Err(Skip::Break)), "a fully-pressured sole backend leaves nothing to select");
	}

	#[test]
	fn select_and_gate_continues_when_circuit_open() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_off());
		// Trip the breaker for b1 so check() reports Open.
		state.circuit_breakers.record_failure("b1");
		assert_eq!(state.circuit_breakers.state("b1"), CircuitState::Open, "precondition: breaker is open");
		let fx: Fixture = Fixture::new(state, vec![make_backend("b1")]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		let mut retry: RetryState = empty_retry();

		let outcome = select_and_gate(&ctx, 0, &mut retry);

		assert!(matches!(outcome, Err(Skip::Continue)), "an open circuit must Continue past the backend");
		assert!(retry.failed_backends.iter().any(|id| id.as_str() == "b1"));
	}

	#[test]
	fn select_and_gate_probes_half_open_backend() {
		let state: Arc<ProxyState> = make_state(cb_half_opens_immediately(), fast_retry(), cache_off());
		// Open the breaker; with a zero recovery window the next check transitions to half-open.
		state.circuit_breakers.record_failure("b1");
		let fx: Fixture = Fixture::new(state, vec![make_backend("b1")]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		let mut retry: RetryState = empty_retry();

		let outcome = select_and_gate(&ctx, 0, &mut retry);

		match outcome {
			Ok(selected) => assert!(selected.half_open.is_some(), "a half-open probe carries its guard"),
			_ => panic!("a half-open backend must be selected as a probe"),
		}
	}

	// --- handle_response -------------------------------------------------------------------------

	#[tokio::test]
	async fn handle_response_forward_error_retries_before_final_attempt() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_off());
		let fx: Fixture = Fixture::new(state.clone(), vec![make_backend("b1")]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		let selected: Selected = make_selected(&state, make_backend("b1"));
		let parts: Parts = parts_for("GET", "/x");
		let mut retry: RetryState = empty_retry();

		let outcome: AttemptOutcome =
			handle_response(&ctx, 0, selected, Err(ReductionError::BackendUnavailable), &parts, &mut retry).await;

		assert!(matches!(outcome, AttemptOutcome::Continue), "a non-final forward error retries");
		assert!(retry.failed_backends.iter().any(|id| id.as_str() == "b1"));
		assert!(retry.last_error_msg.is_some());
	}

	#[tokio::test]
	async fn handle_response_forward_error_returns_502_on_final_attempt() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_off());
		let fx: Fixture = Fixture::new(state.clone(), vec![make_backend("b1")]);
		let ctx: RequestCtx<'_> = fx.ctx(1, true, false, false);
		let selected: Selected = make_selected(&state, make_backend("b1"));
		let parts: Parts = parts_for("GET", "/x");
		let mut retry: RetryState = empty_retry();

		let outcome: AttemptOutcome =
			handle_response(&ctx, 0, selected, Err(ReductionError::BackendUnavailable), &parts, &mut retry).await;

		match outcome {
			AttemptOutcome::Return(response) => assert_eq!(response.status(), StatusCode::BAD_GATEWAY),
			_ => panic!("the final forward error must Return a 502"),
		}
	}

	#[tokio::test]
	async fn handle_response_retryable_status_retries_before_final_attempt() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_off());
		let fx: Fixture = Fixture::new(state.clone(), vec![make_backend("b1")]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		let selected: Selected = make_selected(&state, make_backend("b1"));
		let resp: Response<Body> = response_with(StatusCode::SERVICE_UNAVAILABLE, None, "down");
		let parts: Parts = parts_for("GET", "/x");
		let mut retry: RetryState = empty_retry();

		let outcome: AttemptOutcome = handle_response(&ctx, 0, selected, Ok(resp), &parts, &mut retry).await;

		assert!(matches!(outcome, AttemptOutcome::Continue), "a retryable 503 before the final attempt retries");
		match retry.last_response {
			Some(r) => assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE, "the 503 is captured for budget exhaustion"),
			None => panic!("the retryable response must be captured"),
		}
	}

	#[tokio::test]
	async fn handle_response_retryable_status_streams_on_final_attempt() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_off());
		let fx: Fixture = Fixture::new(state.clone(), vec![make_backend("b1")]);
		let ctx: RequestCtx<'_> = fx.ctx(1, true, false, false);
		let selected: Selected = make_selected(&state, make_backend("b1"));
		let resp: Response<Body> = response_with(StatusCode::SERVICE_UNAVAILABLE, None, "down");
		let parts: Parts = parts_for("GET", "/x");
		let mut retry: RetryState = empty_retry();

		let outcome: AttemptOutcome = handle_response(&ctx, 0, selected, Ok(resp), &parts, &mut retry).await;

		match outcome {
			AttemptOutcome::Stream { response, .. } => assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE),
			_ => panic!("the final retryable attempt streams its response back"),
		}
	}

	#[tokio::test]
	async fn handle_response_success_streams_and_records_circuit_success() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_off());
		let fx: Fixture = Fixture::new(state.clone(), vec![make_backend("b1")]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		let selected: Selected = make_selected(&state, make_backend("b1"));
		let resp: Response<Body> = response_with(StatusCode::OK, None, "hello");
		let parts: Parts = parts_for("GET", "/x");
		let mut retry: RetryState = empty_retry();

		let outcome: AttemptOutcome = handle_response(&ctx, 0, selected, Ok(resp), &parts, &mut retry).await;

		match outcome {
			AttemptOutcome::Stream { response, .. } => assert_eq!(response.status(), StatusCode::OK),
			_ => panic!("a non-cacheable success streams"),
		}
		assert_eq!(state.circuit_breakers.state("b1"), CircuitState::Closed, "a 2xx records success and keeps the circuit closed");
	}

	#[tokio::test]
	async fn handle_response_server_error_streams_and_records_circuit_failure() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_off());
		let fx: Fixture = Fixture::new(state.clone(), vec![make_backend("b1")]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		let selected: Selected = make_selected(&state, make_backend("b1"));
		// 500 is a server error but not retryable, so it streams back while recording a circuit failure.
		let resp: Response<Body> = response_with(StatusCode::INTERNAL_SERVER_ERROR, None, "boom");
		let parts: Parts = parts_for("GET", "/x");
		let mut retry: RetryState = empty_retry();

		let outcome: AttemptOutcome = handle_response(&ctx, 0, selected, Ok(resp), &parts, &mut retry).await;

		match outcome {
			AttemptOutcome::Stream { response, .. } => assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR),
			_ => panic!("a non-retryable 500 streams back"),
		}
		assert_eq!(state.circuit_breakers.state("b1"), CircuitState::Open, "a 5xx records a failure, tripping the one-shot breaker");
	}

	// A `wakeable` backend whose address currently accepts connections (a live stand-in for a woken
	// service), so `park_for_wake`'s reachability probe releases at once.
	fn wakeable_backend_at(id: &str, addr: SocketAddr) -> BackendConfig {
		return BackendConfig::new(id, addr, 1.0, TransportKind::Tcp).unwrap().with_wakeable(true);
	}

	// F1/F2 `with`: a transport miss (the real cold-start error — connect refused → `Forward`) on a
	// wakeable backend PARKS. With the backend reachable the park releases (`Continue`) and the breaker
	// stays closed — the woken service is routable, uncharged.
	#[tokio::test]
	async fn wakeable_transport_miss_parks_and_releases_when_reachable() {
		let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
		let addr: SocketAddr = listener.local_addr().unwrap();
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_off());
		let backend: BackendConfig = wakeable_backend_at("b1", addr);
		let fx: Fixture = Fixture::new(state.clone(), vec![backend.clone()]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		let sel: KeyValue = backend_label(&state.labels, &backend.id);
		let mut retry: RetryState = empty_retry();

		let outcome = handle_forward_error(&ctx, 0, &backend, sel, ReductionError::Forward("connect refused".to_owned()), &mut retry).await;

		assert!(matches!(outcome, AttemptOutcome::Continue), "a reachable woken backend releases the park to retry");
		assert_eq!(state.circuit_breakers.state("b1"), CircuitState::Closed, "a wakeable cold miss must not trip the breaker (F2)");
	}

	// F1/F2 `without`: the same `Forward` miss on a NON-wakeable backend is a real failure — it records
	// against the breaker (and never parks).
	#[tokio::test]
	async fn non_wakeable_transport_miss_opens_the_breaker() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_off());
		let backend: BackendConfig = make_backend("b1"); // wakeable = false → Phase 1 behavior
		let fx: Fixture = Fixture::new(state.clone(), vec![backend.clone()]);
		let ctx: RequestCtx<'_> = fx.ctx(1, true, false, false);
		let sel: KeyValue = backend_label(&state.labels, &backend.id);
		let mut retry: RetryState = empty_retry();

		let _ = handle_forward_error(&ctx, 0, &backend, sel, ReductionError::Forward("connect refused".to_owned()), &mut retry).await;

		assert_eq!(state.circuit_breakers.state("b1"), CircuitState::Open, "without the flag, a cold miss trips the breaker");
	}

	// A `wakeable` QUIC (tunnel) backend. With no tunnel registry wired into the test conn pool, its
	// reachability check resolves to "not reachable" at once, so the park returns without polling.
	fn wakeable_quic_backend(id: &str, addr: SocketAddr) -> BackendConfig {
		return BackendConfig::new(id, addr, 1.0, TransportKind::Quic).unwrap().with_wakeable(true);
	}

	// F1: a wakeable QUIC backend with no live session (and no registry to wait on) is unreachable, so the
	// park returns 503 + Retry-After immediately — the backend is starting, not broken.
	#[tokio::test]
	async fn park_for_wake_returns_503_when_quic_backend_unreachable() {
		let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
		let state: Arc<ProxyState> = make_state_short_wake();
		let backend: BackendConfig = wakeable_quic_backend("b1", addr);
		let fx: Fixture = Fixture::new(state.clone(), vec![backend.clone()]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);

		let outcome: AttemptOutcome = park_for_wake(&ctx, &backend).await;

		match outcome {
			AttemptOutcome::Return(response) => {
				assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
				assert_eq!(response.headers().get("Retry-After").and_then(|v| v.to_str().ok()), Some("1"), "the 503 advertises the wake deadline");
			}
			_ => panic!("an unreachable QUIC wake must Return a 503"),
		}
		assert_eq!(state.circuit_breakers.state("b1"), CircuitState::Closed, "a wake timeout must not trip the breaker (F2)");
	}

	// F1: a wakeable direct (TCP) backend that never accepts a connection parks to its deadline, then
	// returns 503 + Retry-After — the timeout arm of the direct reachability probe.
	#[tokio::test]
	async fn park_for_wake_times_out_to_503_when_tcp_backend_unreachable() {
		// Bind then drop so the port is allocated but refuses connections for the whole park window.
		let dead: std::net::TcpListener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
		let addr: SocketAddr = dead.local_addr().unwrap();
		drop(dead);
		let state: Arc<ProxyState> = make_state_short_wake();
		let backend: BackendConfig = wakeable_backend_at("b1", addr);
		let fx: Fixture = Fixture::new(state.clone(), vec![backend.clone()]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);

		let outcome: AttemptOutcome = park_for_wake(&ctx, &backend).await;

		match outcome {
			AttemptOutcome::Return(response) => assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE),
			_ => panic!("an unreachable direct backend must time out to a 503"),
		}
	}

	#[tokio::test]
	async fn handle_response_cacheable_success_returns_and_caches() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_on());
		let fx: Fixture = Fixture::new(state.clone(), vec![make_backend("b1")]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		let selected: Selected = make_selected(&state, make_backend("b1"));
		let resp: Response<Body> = response_with(StatusCode::OK, Some("public, max-age=300"), "cacheme");
		let parts: Parts = parts_for("GET", "/foo");
		let mut retry: RetryState = empty_retry();

		let outcome: AttemptOutcome = handle_response(&ctx, 0, selected, Ok(resp), &parts, &mut retry).await;

		assert!(matches!(outcome, AttemptOutcome::Return(_)), "a cacheable success Returns a buffered response");
		let key: CacheKeyRef<'_> = CacheKeyRef { method: "GET", path: "/foo", identity: "" };
		assert!(state.response_cache.get(key).is_some(), "the cacheable success is stored");
	}

	// --- run_attempt -----------------------------------------------------------------------------

	#[tokio::test]
	async fn run_attempt_breaks_when_no_backend() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_off());
		let fx: Fixture = Fixture::new(state, vec![]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		let mut replay: ReplayBody = ReplayBody {
			body_bytes: Some(Bytes::from_static(b"x")),
			streaming_body: None,
			req_parts: parts_for("GET", "/x"),
		};
		let mut retry: RetryState = empty_retry();

		let outcome: AttemptOutcome =
			run_attempt(&ctx, 0, Duration::from_secs(5), &mut replay, &mut retry).await;

		assert!(matches!(outcome, AttemptOutcome::Break), "no backend Breaks the loop before any forward");
	}

	#[tokio::test]
	async fn run_attempt_continues_when_circuit_open() {
		// An open circuit gates the backend, so run_attempt Continues to the next attempt without ever
		// forwarding — the deterministic path through select_and_gate's Skip::Continue.
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_off());
		state.circuit_breakers.record_failure("b1");
		let fx: Fixture = Fixture::new(state, vec![make_backend("b1")]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		let mut replay: ReplayBody = ReplayBody {
			body_bytes: Some(Bytes::from_static(b"x")),
			streaming_body: None,
			req_parts: parts_for("GET", "/x"),
		};
		let mut retry: RetryState = empty_retry();

		let outcome: AttemptOutcome =
			run_attempt(&ctx, 0, Duration::from_secs(5), &mut replay, &mut retry).await;

		assert!(matches!(outcome, AttemptOutcome::Continue), "a gated backend Continues without forwarding");
	}

	#[tokio::test]
	async fn run_attempt_breaks_when_streaming_body_already_consumed() {
		let state: Arc<ProxyState> = make_state(cb_opens_immediately(), fast_retry(), cache_off());
		let fx: Fixture = Fixture::new(state, vec![make_backend("b1")]);
		let ctx: RequestCtx<'_> = fx.ctx(2, true, false, false);
		// Backend selectable and gated open, but no body to replay -> build_retry_req returns None -> Break.
		let mut replay: ReplayBody = ReplayBody {
			body_bytes: None,
			streaming_body: None,
			req_parts: parts_for("GET", "/x"),
		};
		let mut retry: RetryState = empty_retry();

		let outcome: AttemptOutcome =
			run_attempt(&ctx, 0, Duration::from_secs(5), &mut replay, &mut retry).await;

		assert!(matches!(outcome, AttemptOutcome::Break), "an unreplayable body Breaks before forwarding");
	}
}
