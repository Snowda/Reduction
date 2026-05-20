use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use http_body::Frame;
use pin_project_lite::pin_project;
use zstd::stream::raw::{Encoder as ZstdEncoder, Operation};

use crate::compression::DEFAULT_COMPRESSION_LEVEL;

const OUTPUT_BUF_SIZE: usize = 16_384;

pin_project! {
    pub struct CompressedBody<B> {
        #[pin]
        inner: B,
        encoder: ZstdEncoder<'static>,
        finished_input: bool,
        finished_output: bool,
    }
}

impl<B> CompressedBody<B> {
    pub fn new(inner: B) -> Self {
        return Self::with_level(inner, DEFAULT_COMPRESSION_LEVEL);
    }

    pub fn with_level(inner: B, level: i32) -> Self {
        let encoder: ZstdEncoder<'static> =
            ZstdEncoder::new(level).expect("zstd encoder init");
        return Self {
            inner,
            encoder,
            finished_input: false,
            finished_output: false,
        };
    }
}

impl<B> http_body::Body for CompressedBody<B>
where
    B: http_body::Body<Data = Bytes>,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();

        if *this.finished_output {
            return Poll::Ready(None);
        }

        if !*this.finished_input {
            match this.inner.poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    *this.finished_input = true;
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(Some(Ok(frame))) => {
                    if let Some(data) = frame.data_ref() {
                        let compressed: Bytes = compress_chunk(this.encoder, data);
                        if !compressed.is_empty() {
                            return Poll::Ready(Some(Ok(Frame::data(compressed))));
                        }
                        // Encoder buffered the input — wake to poll next frame
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    // Non-data frame (trailers) — pass through
                    return Poll::Ready(Some(Ok(frame)));
                }
            }
        }

        // Inner body finished — flush the encoder
        let flushed: Bytes = finish_encoder(this.encoder);
        *this.finished_output = true;
        if flushed.is_empty() {
            return Poll::Ready(None);
        }
        return Poll::Ready(Some(Ok(Frame::data(flushed))));
    }

    fn is_end_stream(&self) -> bool {
        return self.finished_output;
    }
}

fn compress_chunk(encoder: &mut ZstdEncoder<'static>, input: &[u8]) -> Bytes {
    let mut output: BytesMut = BytesMut::zeroed(OUTPUT_BUF_SIZE.max(input.len()));
    let mut in_buf = zstd::stream::raw::InBuffer::around(input);
    let mut out_buf = zstd::stream::raw::OutBuffer::around(&mut *output);

    while in_buf.pos() < input.len() {
        encoder.run(&mut in_buf, &mut out_buf).expect("zstd compress");
        if out_buf.pos() == out_buf.capacity() {
            break;
        }
    }

    let written: usize = out_buf.pos();
    output.truncate(written);
    return output.freeze();
}

fn finish_encoder(encoder: &mut ZstdEncoder<'static>) -> Bytes {
    let mut output: BytesMut = BytesMut::zeroed(OUTPUT_BUF_SIZE);
    loop {
        let mut out_buf = zstd::stream::raw::OutBuffer::around(&mut *output);
        let remaining: usize = encoder.finish(&mut out_buf, true).expect("zstd finish");
        let written: usize = out_buf.pos();
        output.truncate(written);
        if remaining == 0 {
            break;
        }
        output.resize(output.len() + OUTPUT_BUF_SIZE, 0);
    }
    return output.freeze();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compression;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn test_compressed_body_round_trip() {
        let original: Vec<u8> = "streaming compression test data ".repeat(100).into_bytes();
        let inner: axum::body::Body = axum::body::Body::from(original.clone());
        let body: CompressedBody<axum::body::Body> = CompressedBody::new(inner);
        let collected: Bytes = http_body_util::BodyExt::collect(body)
            .await
            .unwrap()
            .to_bytes();
        let decompressed: Vec<u8> = compression::decompress(&collected).unwrap();
        assert_eq!(decompressed, original);
    }

    #[tokio::test]
    async fn test_compressed_body_empty() {
        let inner: axum::body::Body = axum::body::Body::empty();
        let body: CompressedBody<axum::body::Body> = CompressedBody::new(inner);
        let collected: Bytes = BodyExt::collect(body).await.unwrap().to_bytes();
        // Empty input still produces a valid zstd frame
        let decompressed: Vec<u8> = compression::decompress(&collected).unwrap();
        assert!(decompressed.is_empty());
    }

    #[tokio::test]
    async fn test_compressed_body_large_payload() {
        let original: Vec<u8> = vec![42u8; 200_000];
        let inner: axum::body::Body = axum::body::Body::from(original.clone());
        let body: CompressedBody<axum::body::Body> = CompressedBody::new(inner);
        let collected: Bytes = BodyExt::collect(body).await.unwrap().to_bytes();
        let decompressed: Vec<u8> = compression::decompress(&collected).unwrap();
        assert_eq!(decompressed, original);
    }
}
