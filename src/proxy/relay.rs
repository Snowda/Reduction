use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, sleep_until};
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::error::{ReductionError, Result};

// Why the relay ended. Callers distinguish a clean EOF from an idle teardown or a cancellation
// (shutdown/revocation) when logging and counting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RelayEnd {
	Completed = 0,
	IdleTimeout = 1,
	Cancelled = 2,
}

pub struct RelayStats {
	pub bytes_a_to_b: u64,
	pub bytes_b_to_a: u64,
	pub duration: Duration,
	pub end: RelayEnd,
}

// Shared progress record updated inline by the TrackedIo wrappers as copy_bidirectional pumps:
// per-direction byte counts plus the most recent instant either direction moved data, so the idle
// watchdog measures true inactivity rather than total relay lifetime.
struct ActivityTracker {
	start: Instant,
	last_activity_ms: AtomicU64,
	a_to_b: AtomicU64,
	b_to_a: AtomicU64,
}

impl ActivityTracker {
	const fn new(start: Instant) -> Self {
		return Self {
			start,
			last_activity_ms: AtomicU64::new(0),
			a_to_b: AtomicU64::new(0),
			b_to_a: AtomicU64::new(0),
		};
	}

	fn touch(&self) {
		let elapsed_ms: u64 = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
		self.last_activity_ms.store(elapsed_ms, Ordering::Relaxed);
	}
}

// AsyncRead/AsyncWrite wrapper feeding the tracker: a successful read adds to this side's outbound
// byte count, and any successful read or write refreshes the idle clock.
struct TrackedIo<'t, S> {
	inner: S,
	tracker: &'t ActivityTracker,
	read_bytes: &'t AtomicU64,
}

impl<S: AsyncRead + Unpin> AsyncRead for TrackedIo<'_, S> {
	fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
		let this: &mut Self = self.get_mut();
		let before: usize = buf.filled().len();
		let poll: Poll<io::Result<()>> = Pin::new(&mut this.inner).poll_read(cx, buf);
		if let Poll::Ready(Ok(())) = &poll {
			let read: u64 = u64::try_from(buf.filled().len() - before).unwrap_or(u64::MAX);
			if read > 0 {
				this.read_bytes.fetch_add(read, Ordering::Relaxed);
				this.tracker.touch();
			}
		}
		return poll;
	}
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TrackedIo<'_, S> {
	fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
		let this: &mut Self = self.get_mut();
		let poll: Poll<io::Result<usize>> = Pin::new(&mut this.inner).poll_write(cx, buf);
		if let Poll::Ready(Ok(written)) = &poll
			&& *written > 0
		{
			this.tracker.touch();
		}
		return poll;
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		return Pin::new(&mut self.get_mut().inner).poll_flush(cx);
	}

	fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		return Pin::new(&mut self.get_mut().inner).poll_shutdown(cx);
	}

	fn poll_write_vectored(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		bufs: &[io::IoSlice<'_>],
	) -> Poll<io::Result<usize>> {
		let this: &mut Self = self.get_mut();
		let poll: Poll<io::Result<usize>> = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
		if let Poll::Ready(Ok(written)) = &poll
			&& *written > 0
		{
			this.tracker.touch();
		}
		return poll;
	}

	fn is_write_vectored(&self) -> bool {
		return self.inner.is_write_vectored();
	}
}

// Resolves only after a full idle_timeout passes with no tracker activity: sleeps to the deadline
// implied by the last recorded activity and re-arms whenever traffic moved in the meantime. This is
// what makes the timeout genuinely idle-based — an active transfer re-arms it indefinitely.
async fn idle_watchdog(tracker: &ActivityTracker, idle_timeout: Duration) {
	loop {
		let armed_at_ms: u64 = tracker.last_activity_ms.load(Ordering::Relaxed);
		let deadline: Instant = tracker.start + Duration::from_millis(armed_at_ms) + idle_timeout;
		sleep_until(deadline).await;
		if tracker.last_activity_ms.load(Ordering::Relaxed) == armed_at_ms {
			return;
		}
	}
}

pub async fn relay_bidirectional<A, B>(
	a: A,
	b: B,
	idle_timeout: Duration,
	shutdown: CancellationToken,
) -> Result<RelayStats>
where
	A: AsyncRead + AsyncWrite + Unpin,
	B: AsyncRead + AsyncWrite + Unpin,
{
	let start: Instant = Instant::now();
	let tracker: ActivityTracker = ActivityTracker::new(start);
	let mut tracked_a: TrackedIo<'_, A> = TrackedIo {
		inner: a,
		tracker: &tracker,
		read_bytes: &tracker.a_to_b,
	};
	let mut tracked_b: TrackedIo<'_, B> = TrackedIo {
		inner: b,
		tracker: &tracker,
		read_bytes: &tracker.b_to_a,
	};

	let outcome: io::Result<RelayEnd> = tokio::select! {
		result = tokio::io::copy_bidirectional(&mut tracked_a, &mut tracked_b) => {
			result.map(|_| RelayEnd::Completed)
		}
		_ = idle_watchdog(&tracker, idle_timeout) => {
			debug!("relay idle timeout reached");
			Ok(RelayEnd::IdleTimeout)
		}
		_ = shutdown.cancelled() => {
			debug!("relay cancelled by shutdown");
			Ok(RelayEnd::Cancelled)
		}
	};

	// Byte counts come from the tracker on every path, so an idle- or shutdown-terminated relay
	// still reports what it actually moved instead of zeros.
	return match outcome {
		Ok(end) => Ok(RelayStats {
			bytes_a_to_b: tracker.a_to_b.load(Ordering::Relaxed),
			bytes_b_to_a: tracker.b_to_a.load(Ordering::Relaxed),
			duration: start.elapsed(),
			end,
		}),
		Err(e) => Err(ReductionError::ConnectTunnel(format!("relay error: {e}"))),
	};
}

#[cfg(test)]
mod tests {
	use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
	use tokio::time::sleep;

	use super::*;

	#[tokio::test]
	async fn test_relay_bidirectional_basic() {
		let (client, proxy_client) = duplex(1024);
		let (proxy_backend, backend) = duplex(1024);
		let shutdown: CancellationToken = CancellationToken::new();

		let relay_handle = tokio::spawn(relay_bidirectional(
			proxy_client,
			proxy_backend,
			Duration::from_secs(5),
			shutdown,
		));

		let send_handle = tokio::spawn(async move {
			let (mut cr, mut cw) = tokio::io::split(client);
			let (mut br, mut bw) = tokio::io::split(backend);

			cw.write_all(b"hello backend").await.unwrap();
			cw.shutdown().await.unwrap();

			let mut buf: Vec<u8> = Vec::new();
			br.read_to_end(&mut buf).await.unwrap();
			assert_eq!(&buf, b"hello backend");

			bw.write_all(b"hello client").await.unwrap();
			bw.shutdown().await.unwrap();

			let mut buf2: Vec<u8> = Vec::new();
			cr.read_to_end(&mut buf2).await.unwrap();
			assert_eq!(&buf2, b"hello client");
		});

		send_handle.await.unwrap();
		let stats: RelayStats = relay_handle.await.unwrap().unwrap();
		assert_eq!(stats.bytes_a_to_b, 13);
		assert_eq!(stats.bytes_b_to_a, 12);
		assert_eq!(stats.end, RelayEnd::Completed);
	}

	#[tokio::test]
	async fn test_relay_cancelled_by_shutdown() {
		let (proxy_client, _client) = duplex(1024);
		let (proxy_backend, _backend) = duplex(1024);
		let shutdown: CancellationToken = CancellationToken::new();

		shutdown.cancel();

		let stats: RelayStats = relay_bidirectional(proxy_client, proxy_backend, Duration::from_secs(5), shutdown)
			.await
			.unwrap();

		assert_eq!(stats.bytes_a_to_b, 0);
		assert_eq!(stats.bytes_b_to_a, 0);
		assert_eq!(stats.end, RelayEnd::Cancelled);
	}

	#[tokio::test]
	async fn test_relay_idle_timeout() {
		let (proxy_client, _client) = duplex(1024);
		let (proxy_backend, _backend) = duplex(1024);
		let shutdown: CancellationToken = CancellationToken::new();

		let stats: RelayStats = relay_bidirectional(proxy_client, proxy_backend, Duration::from_millis(10), shutdown)
			.await
			.unwrap();

		assert_eq!(stats.bytes_a_to_b, 0);
		assert_eq!(stats.end, RelayEnd::IdleTimeout);
	}

	#[tokio::test]
	async fn test_relay_empty_streams() {
		let (client, proxy_client) = duplex(1024);
		let (proxy_backend, backend) = duplex(1024);
		let shutdown: CancellationToken = CancellationToken::new();

		drop(client);
		drop(backend);

		let stats: RelayStats = relay_bidirectional(proxy_client, proxy_backend, Duration::from_secs(5), shutdown)
			.await
			.unwrap();

		assert_eq!(stats.bytes_a_to_b, 0);
		assert_eq!(stats.bytes_b_to_a, 0);
		assert_eq!(stats.end, RelayEnd::Completed);
	}

	// The defining property of an IDLE timeout: an actively-transferring relay must outlive it.
	// Under the paused clock, 20 writes spaced 50ms apart total 1000ms of virtual time against a
	// 200ms idle timeout — a whole-transfer timeout (the old behavior) kills this at 200ms with
	// zeroed stats; a true idle timeout re-arms on every write and completes with all bytes.
	#[tokio::test(start_paused = true)]
	async fn test_active_transfer_outlives_idle_timeout() {
		const WRITES: u64 = 20;
		let (client, proxy_client) = duplex(1024);
		let (proxy_backend, backend) = duplex(1024);
		let shutdown: CancellationToken = CancellationToken::new();

		let relay_handle = tokio::spawn(relay_bidirectional(
			proxy_client,
			proxy_backend,
			Duration::from_millis(200),
			shutdown,
		));

		let send_handle = tokio::spawn(async move {
			let (mut br, _bw) = tokio::io::split(backend);
			let (_cr, mut cw) = tokio::io::split(client);
			let mut received: Vec<u8> = Vec::new();
			for _ in 0..WRITES {
				sleep(Duration::from_millis(50)).await;
				cw.write_all(b"x").await.unwrap();
			}
			cw.shutdown().await.unwrap();
			drop(cw);
			br.read_to_end(&mut received).await.unwrap();
			assert_eq!(received.len(), usize::try_from(WRITES).unwrap());
		});

		send_handle.await.unwrap();
		let stats: RelayStats = relay_handle.await.unwrap().unwrap();
		assert_eq!(
			stats.end,
			RelayEnd::Completed,
			"active transfer must not be severed by the idle timeout"
		);
		assert_eq!(stats.bytes_a_to_b, WRITES);
		assert!(
			stats.duration >= Duration::from_millis(900),
			"virtual duration proves it ran past the timeout"
		);
	}

	// An idle teardown must report the bytes that were actually relayed before going quiet, not
	// zeros — the bytes_relayed metric and completion log feed off these stats.
	#[tokio::test(start_paused = true)]
	async fn test_idle_timeout_reports_transferred_bytes() {
		let (client, proxy_client) = duplex(1024);
		let (proxy_backend, backend) = duplex(1024);
		let shutdown: CancellationToken = CancellationToken::new();

		let relay_handle = tokio::spawn(relay_bidirectional(
			proxy_client,
			proxy_backend,
			Duration::from_millis(200),
			shutdown,
		));

		let (mut cr, mut cw) = tokio::io::split(client);
		let (mut br, mut bw) = tokio::io::split(backend);
		cw.write_all(b"hello").await.unwrap();
		let mut buf: [u8; 5] = [0; 5];
		br.read_exact(&mut buf).await.unwrap();
		bw.write_all(b"hi").await.unwrap();
		let mut buf2: [u8; 2] = [0; 2];
		cr.read_exact(&mut buf2).await.unwrap();
		// All ends stay open and silent: only the idle watchdog can end the relay now.

		let stats: RelayStats = relay_handle.await.unwrap().unwrap();
		assert_eq!(stats.end, RelayEnd::IdleTimeout);
		assert_eq!(stats.bytes_a_to_b, 5, "idle stats must carry the real a->b count");
		assert_eq!(stats.bytes_b_to_a, 2, "idle stats must carry the real b->a count");
	}

	// Shutdown mid-relay likewise reports partial progress instead of zeros.
	#[tokio::test]
	async fn test_shutdown_reports_transferred_bytes() {
		let (client, proxy_client) = duplex(1024);
		let (proxy_backend, backend) = duplex(1024);
		let shutdown: CancellationToken = CancellationToken::new();

		let relay_handle = tokio::spawn(relay_bidirectional(
			proxy_client,
			proxy_backend,
			Duration::from_secs(60),
			shutdown.clone(),
		));

		let (_cr, mut cw) = tokio::io::split(client);
		let (mut br, _bw) = tokio::io::split(backend);
		cw.write_all(b"hello").await.unwrap();
		let mut buf: [u8; 5] = [0; 5];
		br.read_exact(&mut buf).await.unwrap();

		shutdown.cancel();
		let stats: RelayStats = relay_handle.await.unwrap().unwrap();
		assert_eq!(stats.end, RelayEnd::Cancelled);
		assert_eq!(stats.bytes_a_to_b, 5, "cancelled stats must carry the real byte count");
	}
}
