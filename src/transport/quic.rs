use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use quinn::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::tls::PeerIdentity;
// Re-exported so `transport::quic::*` paths keep working; the split lets lean clients get
// QuicStream without the listener's axum/tokio-util deps.
#[cfg(feature = "proxy")]
pub use crate::transport::quic_listener::{QuicListener, build_quic_server_config};

// Wire-protocol stream-type bytes: the client writes one as the first byte of every bidi
// stream and the listener routes on it. Core, not proxy-side.
pub const STREAM_TYPE_HTTP: u8 = 0x01;
pub const STREAM_TYPE_RAW: u8 = 0x02;

pub struct QuicStream {
	send: SendStream,
	recv: RecvStream,
	peer_identity: Option<PeerIdentity>,
}

impl QuicStream {
	#[must_use]
	pub const fn new(send: SendStream, recv: RecvStream) -> Self {
		return Self {
			send,
			recv,
			peer_identity: None,
		};
	}

	// Attach the connection's mTLS identity so the axum Connected impl can surface it downstream.
	#[must_use]
	pub const fn with_peer_identity(mut self, identity: Option<PeerIdentity>) -> Self {
		self.peer_identity = identity;
		return self;
	}

	#[must_use]
	pub const fn peer_identity(&self) -> Option<PeerIdentity> {
		return self.peer_identity;
	}

	// Signal end-of-stream so the peer's read completes cleanly. Ignores an already-closed stream —
	// finishing an ended stream is a no-op, not an error worth propagating.
	pub fn finish(&mut self) {
		let _ = self.send.finish();
	}
}

impl AsyncRead for QuicStream {
	fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
		return Pin::new(&mut self.recv).poll_read(cx, buf);
	}
}

impl AsyncWrite for QuicStream {
	fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
		return Pin::new(&mut self.send)
			.poll_write(cx, buf)
			.map(|r| r.map_err(io::Error::other));
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		return Pin::new(&mut self.send).poll_flush(cx);
	}

	fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		return Pin::new(&mut self.send).poll_shutdown(cx);
	}
}

impl Unpin for QuicStream {}
