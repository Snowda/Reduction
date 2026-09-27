use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use http_body::Frame;
use pin_project_lite::pin_project;
use tokio::task::{JoinError, JoinHandle};
use zstd::stream::raw::{Encoder as ZstdEncoder, InBuffer, Operation, OutBuffer};

const OUTPUT_BUF_SIZE: usize = 16_384;
// Chunks larger than this compress on the blocking pool, not inline: below it the thread-handoff cost
// dwarfs the work, above it inline zstd would monopolize a reactor worker.
const OFFLOAD_THRESHOLD_BYTES: usize = 32 * 1024;

// Body-level failure: inner body or zstd encoder, surfaced as stream errors so the client never sees a silent truncation.
#[derive(Debug)]
pub enum CompressError<E> {
	Inner(E),
	Zstd(io::Error),
}

impl<E: Display> Display for CompressError<E> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		return match self {
			Self::Inner(e) => write!(f, "body error: {e}"),
			Self::Zstd(e) => write!(f, "zstd compression error: {e}"),
		};
	}
}

impl<E: Error + 'static> Error for CompressError<E> {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		return match self {
			Self::Inner(e) => Some(e),
			Self::Zstd(e) => Some(e),
		};
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum CompressionPhase {
	Streaming = 0,
	// Awaiting the blocking task compressing an over-threshold chunk.
	Offloading = 1,
	Flushing = 2,
	Done = 3,
}

// The frame result `poll_frame` yields, parameterised by the inner body's error type.
type FramePoll<E> = Poll<Option<Result<Frame<Bytes>, CompressError<E>>>>;

// A phase handler either produced a poll result to return, or buffered its input and wants the loop to advance.
enum Step<E> {
	Ready(FramePoll<E>),
	Continue,
}

// The blocking task's output: the moved-out encoder plus the compressed bytes it produced.
type OffloadTask = JoinHandle<io::Result<(ZstdEncoder<'static>, Bytes)>>;

pin_project! {
	pub struct CompressedBody<B> {
		#[pin]
		inner: B,
		// The streaming encoder, held between chunks; moved into a blocking task (`None`) while an over-threshold chunk compresses, then back.
		encoder: Option<ZstdEncoder<'static>>,
		task: Option<JoinHandle<io::Result<(ZstdEncoder<'static>, Bytes)>>>,
		phase: CompressionPhase,
	}
}

impl<B> CompressedBody<B> {
	pub fn with_level(inner: B, level: i32) -> io::Result<Self> {
		let encoder: ZstdEncoder<'static> = ZstdEncoder::new(level)?;
		return Ok(Self {
			inner,
			encoder: Some(encoder),
			task: None,
			phase: CompressionPhase::Streaming,
		});
	}
}

impl<B> http_body::Body for CompressedBody<B>
where
	B: http_body::Body<Data = Bytes>,
{
	type Data = Bytes;
	type Error = CompressError<B::Error>;

	fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
		let mut this = self.project();

		loop {
			let step: Step<B::Error> = match *this.phase {
				CompressionPhase::Done => return Poll::Ready(None),
				CompressionPhase::Offloading => poll_offloading(this.task, this.encoder, this.phase, cx),
				CompressionPhase::Streaming => {
					poll_streaming(this.inner.as_mut(), this.encoder, this.task, this.phase, cx)
				}
				CompressionPhase::Flushing => poll_flushing(this.encoder, this.phase),
			};
			match step {
				Step::Ready(poll) => return poll,
				// A phase buffered its input and advanced `*this.phase`; loop into the next phase.
				Step::Continue => {}
			}
		}
	}

	fn is_end_stream(&self) -> bool {
		return self.phase == CompressionPhase::Done;
	}
}

// Compress one over-threshold chunk on a blocking thread, moving the encoder in and back so its state carries forward.
fn compress_chunk_owned(mut encoder: ZstdEncoder<'static>, input: &[u8]) -> io::Result<(ZstdEncoder<'static>, Bytes)> {
	let compressed: Bytes = compress_chunk(&mut encoder, input)?;
	return Ok((encoder, compressed));
}

// Collapse a JoinHandle result: a panicked/aborted task becomes an io error (a stream error, not a silent truncation).
fn flatten_join(
	result: Result<io::Result<(ZstdEncoder<'static>, Bytes)>, JoinError>,
) -> io::Result<(ZstdEncoder<'static>, Bytes)> {
	return match result {
		Ok(inner) => inner,
		Err(join_err) => Err(io::Error::other(format!("compression task join failed: {join_err}"))),
	};
}

// Internal-invariant failure: the encoder or its task went missing between phases, surfaced as a stream error.
fn encoder_missing<E>() -> Poll<Option<Result<Frame<Bytes>, CompressError<E>>>> {
	return Poll::Ready(Some(Err(CompressError::Zstd(io::Error::other(
		"compressor state lost",
	)))));
}

// Run the encoder until every input byte is consumed, growing the output buffer as needed (zstd may emit more than `input.len()` at once).
fn compress_chunk(encoder: &mut ZstdEncoder<'static>, input: &[u8]) -> io::Result<Bytes> {
	let mut output: BytesMut = BytesMut::zeroed(OUTPUT_BUF_SIZE.max(input.len()));
	let mut filled: usize = 0;
	let mut in_buf: InBuffer<'_> = InBuffer::around(input);

	while in_buf.pos() < input.len() {
		let consumed_before: usize = in_buf.pos();
		let written: usize = {
			let mut out_buf: OutBuffer<'_, [u8]> = OutBuffer::around(&mut output[filled..]);
			encoder.run(&mut in_buf, &mut out_buf)?;
			out_buf.pos()
		};
		filled += written;
		if written == 0 && in_buf.pos() == consumed_before {
			// Output space was available yet nothing moved — fail noisily rather than spin or
			// emit a truncated stream.
			return Err(io::Error::other("zstd encoder made no progress"));
		}
		if filled == output.len() {
			output.resize(output.len() + OUTPUT_BUF_SIZE, 0);
		}
	}

	output.truncate(filled);
	return Ok(output.freeze());
}

// Flush everything the encoder still holds, appending across passes (restarting at offset zero would overwrite earlier output).
fn finish_encoder(encoder: &mut ZstdEncoder<'static>) -> io::Result<Bytes> {
	let mut output: BytesMut = BytesMut::zeroed(OUTPUT_BUF_SIZE);
	let mut filled: usize = 0;
	loop {
		let (remaining, written): (usize, usize) = {
			let mut out_buf: OutBuffer<'_, [u8]> = OutBuffer::around(&mut output[filled..]);
			let remaining: usize = encoder.finish(&mut out_buf, true)?;
			(remaining, out_buf.pos())
		};
		filled += written;
		if remaining == 0 {
			break;
		}
		if written == 0 && filled < output.len() {
			return Err(io::Error::other("zstd encoder made no progress during finish"));
		}
		if filled == output.len() {
			output.resize(output.len() + OUTPUT_BUF_SIZE, 0);
		}
	}
	output.truncate(filled);
	return Ok(output.freeze());
}

// Poll the blocking task compressing an over-threshold chunk; on completion the encoder moves back and its output is emitted.
fn poll_offloading<E>(
	task: &mut Option<OffloadTask>,
	encoder: &mut Option<ZstdEncoder<'static>>,
	phase: &mut CompressionPhase,
	cx: &mut Context<'_>,
) -> Step<E> {
	let Some(handle) = task.as_mut() else {
		// Unreachable: Offloading is only entered with a task set.
		*phase = CompressionPhase::Done;
		return Step::Ready(encoder_missing());
	};
	return match Pin::new(handle).poll(cx) {
		Poll::Pending => Step::Ready(Poll::Pending),
		Poll::Ready(join_result) => {
			*task = None;
			match flatten_join(join_result) {
				Ok((enc, compressed)) => {
					*encoder = Some(enc);
					*phase = CompressionPhase::Streaming;
					if compressed.is_empty() {
						// Encoder buffered the input — pull the next frame.
						Step::Continue
					} else {
						Step::Ready(Poll::Ready(Some(Ok(Frame::data(compressed)))))
					}
				}
				Err(e) => {
					*phase = CompressionPhase::Done;
					Step::Ready(Poll::Ready(Some(Err(CompressError::Zstd(e)))))
				}
			}
		}
	};
}

// Pull the next inner frame and route it: stream end → Flushing, inner error → surfaced, data → compressed.
fn poll_streaming<B>(
	inner: Pin<&mut B>,
	encoder: &mut Option<ZstdEncoder<'static>>,
	task: &mut Option<OffloadTask>,
	phase: &mut CompressionPhase,
	cx: &mut Context<'_>,
) -> Step<B::Error>
where
	B: http_body::Body<Data = Bytes>,
{
	return match inner.poll_frame(cx) {
		Poll::Pending => Step::Ready(Poll::Pending),
		Poll::Ready(None) => {
			*phase = CompressionPhase::Flushing;
			Step::Continue
		}
		Poll::Ready(Some(Err(e))) => Step::Ready(Poll::Ready(Some(Err(CompressError::Inner(e))))),
		Poll::Ready(Some(Ok(frame))) => compress_frame(frame, encoder, task, phase),
	};
}

// Compress one data frame, offloading over-threshold chunks and passing non-data frames through.
fn compress_frame<E>(
	frame: Frame<Bytes>,
	encoder: &mut Option<ZstdEncoder<'static>>,
	task: &mut Option<OffloadTask>,
	phase: &mut CompressionPhase,
) -> Step<E> {
	let Some(data) = frame.data_ref() else {
		// Non-data frame (trailers) — pass through.
		return Step::Ready(Poll::Ready(Some(Ok(frame))));
	};
	if data.len() > OFFLOAD_THRESHOLD_BYTES {
		return offload_chunk(data.clone(), encoder, task, phase);
	}
	return compress_inline(data, encoder, phase);
}

// Large chunk: hand the streaming encoder to the blocking pool (see OFFLOAD_THRESHOLD_BYTES) so it can't monopolize a reactor worker.
fn offload_chunk<E>(
	input: Bytes,
	encoder: &mut Option<ZstdEncoder<'static>>,
	task: &mut Option<OffloadTask>,
	phase: &mut CompressionPhase,
) -> Step<E> {
	let Some(enc) = encoder.take() else {
		*phase = CompressionPhase::Done;
		return Step::Ready(encoder_missing());
	};
	*task = Some(tokio::task::spawn_blocking(move || compress_chunk_owned(enc, &input)));
	*phase = CompressionPhase::Offloading;
	return Step::Continue;
}

// Small chunk: compress inline; a thread handoff would cost more than the work.
fn compress_inline<E>(
	data: &[u8],
	encoder: &mut Option<ZstdEncoder<'static>>,
	phase: &mut CompressionPhase,
) -> Step<E> {
	let Some(enc) = encoder.as_mut() else {
		*phase = CompressionPhase::Done;
		return Step::Ready(encoder_missing());
	};
	let compressed: Bytes = match compress_chunk(enc, data) {
		Ok(c) => c,
		Err(e) => {
			*phase = CompressionPhase::Done;
			return Step::Ready(Poll::Ready(Some(Err(CompressError::Zstd(e)))));
		}
	};
	if compressed.is_empty() {
		// Encoder buffered the input — pull the next frame.
		return Step::Continue;
	}
	return Step::Ready(Poll::Ready(Some(Ok(Frame::data(compressed)))));
}

// Flush everything the encoder still holds; bounded by zstd's internal buffer, so it can't stall a worker.
fn poll_flushing<E>(encoder: &mut Option<ZstdEncoder<'static>>, phase: &mut CompressionPhase) -> Step<E> {
	let Some(enc) = encoder.as_mut() else {
		*phase = CompressionPhase::Done;
		return Step::Ready(encoder_missing());
	};
	let flushed: Bytes = match finish_encoder(enc) {
		Ok(f) => f,
		Err(e) => {
			*phase = CompressionPhase::Done;
			return Step::Ready(Poll::Ready(Some(Err(CompressError::Zstd(e)))));
		}
	};
	*phase = CompressionPhase::Done;
	if flushed.is_empty() {
		return Step::Ready(Poll::Ready(None));
	}
	return Step::Ready(Poll::Ready(Some(Ok(Frame::data(flushed)))));
}

#[cfg(test)]
mod tests {
	use std::collections::VecDeque;

	use http_body_util::BodyExt;

	use super::*;
	use crate::compression;

	// Generous ceiling for round-trip decodes: larger than any fixture below.
	const ROUND_TRIP_CAP: usize = 8 * 1024 * 1024;

	#[tokio::test]
	async fn test_compressed_body_round_trip() {
		let original: Vec<u8> = "streaming compression test data ".repeat(100).into_bytes();
		let inner: axum::body::Body = axum::body::Body::from(original.clone());
		let body: CompressedBody<axum::body::Body> =
			CompressedBody::with_level(inner, compression::DEFAULT_COMPRESSION_LEVEL).unwrap();
		let collected: Bytes = http_body_util::BodyExt::collect(body).await.unwrap().to_bytes();
		let decompressed: Vec<u8> = compression::decompress_bounded(&collected, ROUND_TRIP_CAP).unwrap();
		assert_eq!(decompressed, original);
	}

	#[tokio::test]
	async fn test_compressed_body_empty() {
		let inner: axum::body::Body = axum::body::Body::empty();
		let body: CompressedBody<axum::body::Body> =
			CompressedBody::with_level(inner, compression::DEFAULT_COMPRESSION_LEVEL).unwrap();
		let collected: Bytes = BodyExt::collect(body).await.unwrap().to_bytes();
		// Empty input still produces a valid zstd frame
		let decompressed: Vec<u8> = compression::decompress_bounded(&collected, ROUND_TRIP_CAP).unwrap();
		assert!(decompressed.is_empty());
	}

	#[tokio::test]
	async fn test_compressed_body_large_payload() {
		let original: Vec<u8> = vec![42u8; 200_000];
		let inner: axum::body::Body = axum::body::Body::from(original.clone());
		let body: CompressedBody<axum::body::Body> =
			CompressedBody::with_level(inner, compression::DEFAULT_COMPRESSION_LEVEL).unwrap();
		let collected: Bytes = BodyExt::collect(body).await.unwrap().to_bytes();
		let decompressed: Vec<u8> = compression::decompress_bounded(&collected, ROUND_TRIP_CAP).unwrap();
		assert_eq!(decompressed, original);
	}

	// Deterministic pseudo-random bytes: zstd cannot compress these, so worst-case output size
	// (input + frame/block overhead) is guaranteed.
	fn incompressible_bytes(len: usize) -> Vec<u8> {
		let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
		return (0..len)
			.map(|_| {
				state ^= state << 13;
				state ^= state >> 7;
				state ^= state << 17;
				state.to_le_bytes()[0]
			})
			.collect();
	}

	#[tokio::test]
	async fn test_compressed_body_incompressible_large_frame_round_trip() {
		// Regression: incompressible input makes zstd output slightly LARGER than the input-sized
		// output buffer. Every input byte must still be consumed — no silent truncation.
		let original: Vec<u8> = incompressible_bytes(1024 * 1024);
		let inner: axum::body::Body = axum::body::Body::from(original.clone());
		let body: CompressedBody<axum::body::Body> =
			CompressedBody::with_level(inner, compression::DEFAULT_COMPRESSION_LEVEL).unwrap();
		let collected: Bytes = BodyExt::collect(body).await.unwrap().to_bytes();
		let decompressed: Vec<u8> = compression::decompress_bounded(&collected, ROUND_TRIP_CAP).unwrap();
		assert_eq!(decompressed, original);
	}

	// Minimal multi-frame body: yields each chunk as its own data frame, like a streaming backend response.
	struct ChunkedBody {
		chunks: VecDeque<Bytes>,
	}

	impl http_body::Body for ChunkedBody {
		type Data = Bytes;
		type Error = std::convert::Infallible;

		fn poll_frame(
			self: std::pin::Pin<&mut Self>,
			_cx: &mut std::task::Context<'_>,
		) -> std::task::Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
			return std::task::Poll::Ready(self.get_mut().chunks.pop_front().map(|c| Ok(Frame::data(c))));
		}
	}

	#[tokio::test]
	async fn test_compressed_body_multi_frame_block_burst_round_trip() {
		// Regression: a 100KB first chunk sits buffered inside the encoder; a 40KB second chunk
		// completes a 128KB zstd block, which bursts out into an output buffer sized to the small
		// chunk. The overflow must not drop the unconsumed remainder of the input.
		let data: Vec<u8> = incompressible_bytes(140 * 1024);
		let (first, second) = data.split_at(100 * 1024);
		let inner: ChunkedBody = ChunkedBody {
			chunks: [Bytes::copy_from_slice(first), Bytes::copy_from_slice(second)]
				.into_iter()
				.collect(),
		};
		let body: CompressedBody<ChunkedBody> =
			CompressedBody::with_level(inner, compression::DEFAULT_COMPRESSION_LEVEL).unwrap();
		let collected: Bytes = BodyExt::collect(body).await.unwrap().to_bytes();
		let decompressed: Vec<u8> = compression::decompress_bounded(&collected, ROUND_TRIP_CAP).unwrap();
		assert_eq!(decompressed, data);
	}

	#[tokio::test]
	async fn test_compressed_body_mixed_inline_and_offloaded_chunks() {
		// Frames straddle OFFLOAD_THRESHOLD_BYTES: small compress inline, large on the blocking pool.
		// Encoder state must carry across the inline<->offload transitions, so the round-trip reproduces the exact input.
		let small_a: Vec<u8> = incompressible_bytes(1024);
		let large: Vec<u8> = incompressible_bytes(OFFLOAD_THRESHOLD_BYTES + 1024);
		let small_b: Vec<u8> = incompressible_bytes(2048);
		let mut expected: Vec<u8> = Vec::new();
		expected.extend_from_slice(&small_a);
		expected.extend_from_slice(&large);
		expected.extend_from_slice(&small_b);

		let inner: ChunkedBody = ChunkedBody {
			chunks: [
				Bytes::copy_from_slice(&small_a),
				Bytes::copy_from_slice(&large),
				Bytes::copy_from_slice(&small_b),
			]
			.into_iter()
			.collect(),
		};
		let body: CompressedBody<ChunkedBody> =
			CompressedBody::with_level(inner, compression::DEFAULT_COMPRESSION_LEVEL).unwrap();
		let collected: Bytes = BodyExt::collect(body).await.unwrap().to_bytes();
		let decompressed: Vec<u8> = compression::decompress_bounded(&collected, ROUND_TRIP_CAP).unwrap();
		assert_eq!(decompressed, expected);
	}

	#[tokio::test]
	async fn test_compressed_body_incompressible_flush_round_trip() {
		// Regression: 100KB incompressible input is smaller than a zstd block, so the encoder
		// buffers it all internally and emits it only at finish(). The flush buffer is 16KB, so
		// the flush loop must make several passes without overwriting earlier passes' output.
		let original: Vec<u8> = incompressible_bytes(100 * 1024);
		let inner: axum::body::Body = axum::body::Body::from(original.clone());
		let body: CompressedBody<axum::body::Body> =
			CompressedBody::with_level(inner, compression::DEFAULT_COMPRESSION_LEVEL).unwrap();
		let collected: Bytes = BodyExt::collect(body).await.unwrap().to_bytes();
		let decompressed: Vec<u8> = compression::decompress_bounded(&collected, ROUND_TRIP_CAP).unwrap();
		assert_eq!(decompressed, original);
	}
}
