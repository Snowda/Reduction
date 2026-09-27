use std::sync::Arc;
use std::time::{Duration, Instant};

use arrayvec::ArrayString;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use super::{DropReason, IngressCounters};
use crate::circuit::{CircuitBreakers, CircuitState};
use crate::config::{BackendConfig, RetryConfig};
use crate::error::Result;
use crate::ingress::protocol::{self, Datagram, Envelope};
use crate::proxy::pool::ConnPool;
use crate::retry;
use crate::transport::quic::QuicStream;

struct WriterState {
	stream: Option<QuicStream>,
	// Consecutive dial/write failures; drives the reconnect backoff and resets on success.
	attempt: u32,
	// Earliest instant the next dial may be attempted (reconnect backoff window).
	cooldown_until: Option<Instant>,
	// True once a stream has been established, so a later re-establishment is counted as a reconnect
	// rather than the first connect.
	established_once: bool,
}

impl WriterState {
	const fn new() -> Self {
		return Self {
			stream: None,
			attempt: 0,
			cooldown_until: None,
			established_once: false,
		};
	}
}

// One backend's long-lived writer: owns the QUIC raw stream, dials it lazily on the first batch, and
// writes preamble + Hello once, then a Batch frame per received batch. Dial and write failures feed
// the shared circuit breaker and pace reconnect via the shared retry/jitter policy.
pub struct BackendWriter {
	pub backend: BackendConfig,
	pub ingress_id: ArrayString<64>,
	pub worker: u16,
	pub conn_pool: Arc<ConnPool>,
	pub client_tls_config: Arc<rustls::ClientConfig>,
	pub connect_timeout: Duration,
	pub counters: Arc<IngressCounters>,
	pub circuit: Arc<CircuitBreakers>,
	pub retry: RetryConfig,
}

impl BackendWriter {
	async fn dial(&self) -> Result<QuicStream> {
		let mut stream: QuicStream = self
			.conn_pool
			.acquire_raw_stream(&self.backend, &self.client_tls_config, self.connect_timeout)
			.await?;
		protocol::write_preamble(&mut stream).await?;
		let hello: Envelope = Envelope::Hello {
			ingress_id: self.ingress_id,
			worker: self.worker,
		};
		protocol::write_frame(&mut stream, &hello).await?;
		return Ok(stream);
	}

	pub async fn run(self, mut rx: mpsc::Receiver<Vec<Datagram>>, shutdown: CancellationToken) {
		let mut state: WriterState = WriterState::new();
		loop {
			tokio::select! {
				_ = shutdown.cancelled() => {
					if let Some(mut s) = state.stream {
						s.finish();
					}
					return;
				}
				maybe = rx.recv() => {
					let Some(datagrams) = maybe else {
						if let Some(mut s) = state.stream {
							s.finish();
						}
						return;
					};
					self.counters.queue_depth_add(&self.backend.id, -1);
					self.write_batch(&mut state, datagrams).await;
				}
			}
		}
	}

	// Record a dial/write failure: open the breaker path, arm the reconnect backoff, drop the batch as
	// protocol, and drop the stream so the next batch redials.
	fn on_failure(&self, state: &mut WriterState, count: u64) {
		state.stream = None;
		state.attempt = state.attempt.saturating_add(1);
		state.cooldown_until = Some(Instant::now() + retry::backoff_delay(state.attempt - 1, &self.retry));
		self.circuit.record_failure(&self.backend.id);
		self.counters.record_drop(DropReason::Protocol, count);
	}

	async fn write_batch(&self, state: &mut WriterState, datagrams: Vec<Datagram>) {
		if datagrams.is_empty() {
			return;
		}
		let count: u64 = u64::try_from(datagrams.len()).unwrap_or(u64::MAX);

		// Circuit gate: an open breaker sheds the batch cheaply without a dial. The half-open guard is
		// held for the duration of this probe (dial + write).
		let (circuit_state, _half_open_guard) = self.circuit.check(&self.backend.id);
		if circuit_state == CircuitState::Open {
			self.counters.record_drop(DropReason::CircuitOpen, count);
			return;
		}
		// Reconnect backoff window: not yet time to redial, so shed cheaply.
		if let Some(until) = state.cooldown_until
			&& Instant::now() < until
		{
			self.counters.record_drop(DropReason::CircuitOpen, count);
			return;
		}

		if state.stream.is_none() {
			match self.dial().await {
				Ok(stream) => {
					state.stream = Some(stream);
					state.attempt = 0;
					state.cooldown_until = None;
					self.circuit.record_success(&self.backend.id);
					if state.established_once {
						self.counters.record_stream_reconnect(&self.backend.id);
					}
					state.established_once = true;
				}
				Err(e) => {
					warn!(backend = %self.backend.id, error = %e, "ingress backend dial failed; dropping batch");
					self.on_failure(state, count);
					return;
				}
			}
		}

		let Some(stream) = state.stream.as_mut() else {
			self.counters.record_drop(DropReason::Protocol, count);
			return;
		};
		match protocol::write_frame(stream, &Envelope::Batch { datagrams }).await {
			Ok(()) => {
				self.circuit.record_success(&self.backend.id);
				self.counters.record_relayed(count);
				self.counters.record_batch_sent(count);
				state.attempt = 0;
			}
			Err(e) => {
				warn!(backend = %self.backend.id, error = %e, "ingress batch write failed; will redial");
				self.on_failure(state, count);
			}
		}
	}
}

// The per-worker UDP recv loop. Owns the reused recv buffer, per-backend in-flight batches, and the
// senders into each backend writer. Selection, batching, and drop accounting all happen here; the

#[cfg(test)]
mod tests {
	use super::super::testutil::{breakers, datagram, empty_client_config, fast_retry, quic_backend};
	use super::*;

	fn make_writer(counters: Arc<IngressCounters>, circuit: Arc<CircuitBreakers>) -> BackendWriter {
		return BackendWriter {
			backend: quic_backend("ingest-a").with_host("localhost".to_owned()),
			ingress_id: ArrayString::from("site-udp").unwrap(),
			worker: 0,
			conn_pool: Arc::new(ConnPool::new()),
			client_tls_config: empty_client_config(),
			connect_timeout: Duration::from_millis(50),
			counters,
			circuit,
			retry: fast_retry(),
		};
	}

	#[tokio::test]
	async fn test_writer_dial_failure_counts_protocol_and_arms_cooldown() {
		let counters: Arc<IngressCounters> = Arc::new(IngressCounters::new("site-udp"));
		let circuit: Arc<CircuitBreakers> = breakers();
		let writer: BackendWriter = make_writer(Arc::clone(&counters), Arc::clone(&circuit));
		let mut state: WriterState = WriterState::new();

		writer
			.write_batch(&mut state, vec![datagram(b"a"), datagram(b"b")])
			.await;
		assert_eq!(
			counters.dropped(DropReason::Protocol),
			2,
			"an undialable backend drops the whole batch"
		);
		assert!(
			state.stream.is_none(),
			"a failed dial must leave the stream unset for a redial"
		);
		assert!(
			state.cooldown_until.is_some(),
			"a dial failure must arm the reconnect cooldown"
		);
		assert_eq!(state.attempt, 1, "the failure attempt counter must advance");
		assert_eq!(counters.relayed(), 0);
	}

	#[tokio::test]
	async fn test_writer_cooldown_sheds_as_circuit_open() {
		let counters: Arc<IngressCounters> = Arc::new(IngressCounters::new("site-udp"));
		let writer: BackendWriter = make_writer(Arc::clone(&counters), breakers());
		let mut state: WriterState = WriterState::new();
		// First batch fails to dial and arms a long cooldown (fast_retry base is 10s).
		writer.write_batch(&mut state, vec![datagram(b"a")]).await;
		assert_eq!(counters.dropped(DropReason::Protocol), 1);
		// Second batch arrives inside the cooldown window: shed cheaply as circuit_open, no new dial.
		writer.write_batch(&mut state, vec![datagram(b"b")]).await;
		assert_eq!(
			counters.dropped(DropReason::CircuitOpen),
			1,
			"a batch inside the reconnect cooldown must be shed as circuit_open"
		);
		assert_eq!(
			counters.dropped(DropReason::Protocol),
			1,
			"no second dial attempt during cooldown"
		);
	}

	#[tokio::test]
	async fn test_writer_sheds_when_circuit_open() {
		let counters: Arc<IngressCounters> = Arc::new(IngressCounters::new("site-udp"));
		let circuit: Arc<CircuitBreakers> = breakers();
		// Drive the breaker open for this backend (default threshold is 5 failures).
		for _ in 0..5 {
			circuit.record_failure("ingest-a");
		}
		assert_eq!(circuit.state("ingest-a"), CircuitState::Open);
		let writer: BackendWriter = make_writer(Arc::clone(&counters), Arc::clone(&circuit));
		let mut state: WriterState = WriterState::new();
		writer
			.write_batch(&mut state, vec![datagram(b"a"), datagram(b"b")])
			.await;
		assert_eq!(
			counters.dropped(DropReason::CircuitOpen),
			2,
			"an open circuit sheds the batch without dialing"
		);
		assert_eq!(
			counters.dropped(DropReason::Protocol),
			0,
			"no dial attempt while the circuit is open"
		);
	}

	#[tokio::test]
	async fn test_writer_write_batch_empty_is_noop() {
		let counters: Arc<IngressCounters> = Arc::new(IngressCounters::new("site-udp"));
		let writer: BackendWriter = make_writer(Arc::clone(&counters), breakers());
		let mut state: WriterState = WriterState::new();
		writer.write_batch(&mut state, Vec::new()).await;
		assert_eq!(
			counters.dropped(DropReason::Protocol),
			0,
			"an empty batch never dials or counts"
		);
	}

	#[tokio::test]
	async fn test_writer_run_exits_on_shutdown() {
		let counters: Arc<IngressCounters> = Arc::new(IngressCounters::new("site-udp"));
		let writer: BackendWriter = make_writer(counters, breakers());
		let (_tx, rx): (mpsc::Sender<Vec<Datagram>>, mpsc::Receiver<Vec<Datagram>>) = mpsc::channel(1);
		let shutdown: CancellationToken = CancellationToken::new();
		shutdown.cancel();
		tokio::time::timeout(Duration::from_secs(2), writer.run(rx, shutdown))
			.await
			.expect("a cancelled writer must return promptly");
	}

	#[tokio::test]
	async fn test_writer_run_exits_when_channel_closed() {
		let counters: Arc<IngressCounters> = Arc::new(IngressCounters::new("site-udp"));
		let writer: BackendWriter = make_writer(counters, breakers());
		let (tx, rx): (mpsc::Sender<Vec<Datagram>>, mpsc::Receiver<Vec<Datagram>>) = mpsc::channel(1);
		drop(tx);
		tokio::time::timeout(Duration::from_secs(2), writer.run(rx, CancellationToken::new()))
			.await
			.expect("a closed batch channel must end the writer");
	}

	// ── spawn_udp_ingress wiring ──

}
