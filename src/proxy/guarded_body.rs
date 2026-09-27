use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use pin_project_lite::pin_project;
use tokio::time::{Instant, Sleep};

// Body-level failure surfaced to hyper: the inner body errored, or the backend stalled past the idle
// timeout. Both return as stream errors (never a clean end) so the client never gets a silent truncation.
#[derive(Debug)]
pub enum GuardedBodyError<E> {
	Inner(E),
	IdleTimeout(Duration),
}

impl<E: Display> Display for GuardedBodyError<E> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		return match self {
			Self::Inner(e) => write!(f, "body error: {e}"),
			Self::IdleTimeout(d) => {
				write!(f, "response body idle timeout after {}s", d.as_secs())
			}
		};
	}
}

impl<E: Error + 'static> Error for GuardedBodyError<E> {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		return match self {
			Self::Inner(e) => Some(e),
			Self::IdleTimeout(_) => None,
		};
	}
}

pin_project! {
	// Wraps a streaming response body so that (1) the response-accounting guards in `guards` are held
	// until true end-of-body (completion, error, disconnect, or idle timeout) rather than at
	// response-headers time, and (2) a backend stalling between frames past `idle_timeout` is aborted
	// instead of holding them forever. `guards` is opaque — owned only so its Drop runs at body end (see handler.rs).
	pub struct GuardedBody<B, G> {
		#[pin]
		inner: B,
		// Fires when no frame has arrived within `idle_timeout`; reset after every frame the inner body yields.
		#[pin]
		idle: Sleep,
		idle_timeout: Duration,
		// Held only to be dropped with the body; never read.
		_guards: G,
		done: bool,
	}
}

impl<B, G> GuardedBody<B, G> {
	pub fn new(inner: B, guards: G, idle_timeout: Duration) -> Self {
		return Self {
			inner,
			idle: tokio::time::sleep(idle_timeout),
			idle_timeout,
			_guards: guards,
			done: false,
		};
	}
}

impl<B, G> Body for GuardedBody<B, G>
where
	B: Body<Data = Bytes>,
{
	type Data = Bytes;
	type Error = GuardedBodyError<B::Error>;

	fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
		let mut this = self.project();

		if *this.done {
			return Poll::Ready(None);
		}

		match this.inner.poll_frame(cx) {
			Poll::Ready(Some(Ok(frame))) => {
				// Progress: re-arm the idle deadline so the timeout measures the gap *between* frames, not total transfer time.
				this.idle.as_mut().reset(Instant::now() + *this.idle_timeout);
				return Poll::Ready(Some(Ok(frame)));
			}
			Poll::Ready(Some(Err(e))) => {
				*this.done = true;
				return Poll::Ready(Some(Err(GuardedBodyError::Inner(e))));
			}
			Poll::Ready(None) => {
				*this.done = true;
				return Poll::Ready(None);
			}
			Poll::Pending => {
				// No frame yet — the idle timer decides whether the backend has stalled.
				match this.idle.as_mut().poll(cx) {
					Poll::Ready(()) => {
						*this.done = true;
						return Poll::Ready(Some(Err(GuardedBodyError::IdleTimeout(*this.idle_timeout))));
					}
					Poll::Pending => return Poll::Pending,
				}
			}
		}
	}

	fn is_end_stream(&self) -> bool {
		return self.done;
	}

	fn size_hint(&self) -> SizeHint {
		// Transparent about length so hyper frames the body as the unwrapped body would; an idle-timeout
		// abort surfaces as a stream error that resets the connection, never a clean short body.
		return self.inner.size_hint();
	}
}

#[cfg(test)]
mod tests {
	use std::collections::VecDeque;
	use std::convert::Infallible;
	use std::future::poll_fn;
	use std::sync::Arc;
	use std::sync::atomic::{AtomicBool, Ordering};

	use http_body_util::BodyExt;
	use tokio::sync::mpsc;

	use super::*;

	// A drop-sensing stand-in for the real guard bundle: flips its flag when the body (and guard) is dropped.
	struct DropSpy {
		dropped: Arc<AtomicBool>,
	}

	impl Drop for DropSpy {
		fn drop(&mut self) {
			self.dropped.store(true, Ordering::SeqCst);
		}
	}

	fn unheld_guard() -> DropSpy {
		return DropSpy {
			dropped: Arc::new(AtomicBool::new(false)),
		};
	}

	// Minimal multi-frame body that yields each queued chunk as a data frame then ends (never stalls).
	struct ChunkedBody {
		chunks: VecDeque<Bytes>,
	}

	impl Body for ChunkedBody {
		type Data = Bytes;
		type Error = Infallible;

		fn poll_frame(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
			return Poll::Ready(self.get_mut().chunks.pop_front().map(|c| Ok(Frame::data(c))));
		}
	}

	// Body over an mpsc channel: empty-but-open polls Pending (backend holding the connection open); all-senders-dropped ends cleanly.
	struct ChannelBody {
		rx: mpsc::Receiver<Bytes>,
	}

	impl Body for ChannelBody {
		type Data = Bytes;
		type Error = Infallible;

		fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
			return match self.get_mut().rx.poll_recv(cx) {
				Poll::Ready(Some(b)) => Poll::Ready(Some(Ok(Frame::data(b)))),
				Poll::Ready(None) => Poll::Ready(None),
				Poll::Pending => Poll::Pending,
			};
		}
	}

	#[tokio::test]
	async fn test_guarded_body_passes_frames_through_intact() {
		let inner: ChunkedBody = ChunkedBody {
			chunks: [Bytes::from_static(b"hello "), Bytes::from_static(b"world")]
				.into_iter()
				.collect(),
		};
		let body: GuardedBody<ChunkedBody, DropSpy> = GuardedBody::new(inner, unheld_guard(), Duration::from_secs(60));

		let collected: Bytes = body.collect().await.unwrap().to_bytes();
		assert_eq!(collected.as_ref(), b"hello world");
	}

	#[tokio::test]
	async fn test_guarded_body_releases_guard_only_at_end_of_body() {
		let inner: ChunkedBody = ChunkedBody {
			chunks: [Bytes::from_static(b"x")].into_iter().collect(),
		};
		let dropped: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
		let guard: DropSpy = DropSpy {
			dropped: Arc::clone(&dropped),
		};
		let mut body: Pin<Box<GuardedBody<ChunkedBody, DropSpy>>> =
			Box::pin(GuardedBody::new(inner, guard, Duration::from_secs(60)));

		// One frame consumed, body not yet dropped: the guard must still be held.
		let first: Frame<Bytes> = poll_fn(|cx| body.as_mut().poll_frame(cx)).await.unwrap().unwrap();
		assert_eq!(first.into_data().unwrap().as_ref(), b"x");
		assert!(
			!dropped.load(Ordering::SeqCst),
			"guard released before body was dropped"
		);

		drop(body);
		assert!(dropped.load(Ordering::SeqCst), "guard not released when body dropped");
	}

	#[tokio::test]
	async fn test_guarded_body_aborts_on_idle_timeout() {
		tokio::time::pause();
		// A backend that sends headers and one chunk, then stalls (channel stays open but empty).
		let (tx, rx) = mpsc::channel::<Bytes>(1);
		tx.send(Bytes::from_static(b"partial")).await.unwrap();
		let idle: Duration = Duration::from_secs(5);
		let mut body: Pin<Box<GuardedBody<ChannelBody, DropSpy>>> =
			Box::pin(GuardedBody::new(ChannelBody { rx }, unheld_guard(), idle));

		// First frame arrives immediately.
		let first: Frame<Bytes> = poll_fn(|cx| body.as_mut().poll_frame(cx)).await.unwrap().unwrap();
		assert_eq!(first.into_data().unwrap().as_ref(), b"partial");

		// No further frames; advancing past the idle window must produce a timeout error, not a hang.
		tokio::time::advance(idle + Duration::from_secs(1)).await;
		let err: GuardedBodyError<Infallible> = poll_fn(|cx| body.as_mut().poll_frame(cx)).await.unwrap().unwrap_err();
		assert!(matches!(err, GuardedBodyError::IdleTimeout(_)));
		// The stall was a genuine idle gap: the sender is still alive here.
		drop(tx);
	}

	#[tokio::test]
	async fn test_guarded_body_idle_timer_resets_between_frames() {
		tokio::time::pause();
		let (tx, rx) = mpsc::channel::<Bytes>(4);
		let idle: Duration = Duration::from_secs(5);
		let mut body: Pin<Box<GuardedBody<ChannelBody, DropSpy>>> =
			Box::pin(GuardedBody::new(ChannelBody { rx }, unheld_guard(), idle));

		// Frame 0 at T0 arms the deadline at T0+5.
		tx.send(Bytes::from_static(b"0")).await.unwrap();
		let f0: Frame<Bytes> = poll_fn(|cx| body.as_mut().poll_frame(cx)).await.unwrap().unwrap();
		assert_eq!(f0.into_data().unwrap().as_ref(), b"0");

		// At T3 (< T5) an empty poll is Pending — the timer has not fired.
		tokio::time::advance(Duration::from_secs(3)).await;
		let mid: Poll<_> = poll_fn(|cx| Poll::Ready(body.as_mut().poll_frame(cx))).await;
		assert!(matches!(mid, Poll::Pending));

		// Frame 1 at T3 must RESET the deadline to T3+5 = T8. If reset were broken (deadline stuck at
		// T5), the next poll at T7 would time out.
		tx.send(Bytes::from_static(b"1")).await.unwrap();
		let f1: Frame<Bytes> = poll_fn(|cx| body.as_mut().poll_frame(cx)).await.unwrap().unwrap();
		assert_eq!(f1.into_data().unwrap().as_ref(), b"1");

		tokio::time::advance(Duration::from_secs(4)).await; // T7 < T8
		let still_pending: Poll<_> = poll_fn(|cx| Poll::Ready(body.as_mut().poll_frame(cx))).await;
		assert!(matches!(still_pending, Poll::Pending), "reset deadline fired early");

		// Clean end once the backend closes the stream.
		drop(tx);
		let end: Option<_> = poll_fn(|cx| body.as_mut().poll_frame(cx)).await;
		assert!(end.is_none());
	}
}
