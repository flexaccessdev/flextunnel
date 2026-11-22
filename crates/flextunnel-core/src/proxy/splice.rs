//! Splicing one tunnel stream with a local byte stream.
//!
//! This is the data path of a port forward on the client and of every target
//! connection on the server. The two directions run independently and neither
//! goes through a fixed copy buffer:
//!
//! - **local → tunnel**: each read lands in a [`BytesMut`] and is handed to
//!   the QUIC stream as an owned chunk, which the stream queues as it is
//!   instead of copying it into a buffer of its own. The read buffer grows
//!   while reads fill it and shrinks again when they stop, so a bulk transfer
//!   reads [`READ_MAX`] at a time and a quiet stream keeps about [`READ_MIN`].
//! - **tunnel → local**: the stream's received chunks are taken as they are,
//!   up to [`MAX_CHUNKS`] per call, and leave in one vectored write. Nothing
//!   is held while the stream is quiet.
//!
//! A half-close carries over in both directions — the local stream's EOF
//! finishes the tunnel stream, the tunnel stream's end shuts the local stream
//! down — and the splice ends once both have, or at the first error in either.

use bytes::{Buf, Bytes, BytesMut};
use iroh::endpoint::{RecvStream, SendStream};
use std::io::{self, IoSlice};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The read buffer of a stream that is idle or carries little.
const READ_MIN: usize = 8 * 1024;
/// The read buffer of a stream whose reads keep filling it. Larger reads were
/// measured to buy nothing, and the buffer stays allocated while the stream
/// waits for input.
const READ_MAX: usize = 64 * 1024;
/// Tunnel chunks taken per read and written per vectored write. A chunk is at
/// most one QUIC packet's worth of stream data, so this is about 90 KiB.
const MAX_CHUNKS: usize = 64;

/// Splice `local` with the tunnel stream `recv`/`send` until both directions
/// have ended.
pub(crate) async fn splice<L>(local: L, recv: RecvStream, send: SendStream) -> io::Result<()>
where
    L: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, writer) = tokio::io::split(local);
    tokio::try_join!(local_to_tunnel(reader, send), tunnel_to_local(recv, writer))?;
    Ok(())
}

async fn local_to_tunnel<R>(mut reader: R, mut send: SendStream) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut buf = BytesMut::new();
    let mut want = READ_MIN;
    loop {
        // What is left of the last allocation serves the next read unless it
        // is short for it, or far more than a stream gone quiet should keep.
        // The chunks already cut from an allocation keep it alive themselves.
        if buf.capacity() < want / 2 || buf.capacity() > want * 2 {
            buf = BytesMut::with_capacity(want);
        }
        let room = buf.capacity();
        let n = reader.read_buf(&mut buf).await?;
        if n == 0 {
            break;
        }
        want = next_read_size(want, n, room);
        send.write_chunk(buf.split().freeze()).await?;
    }
    send.finish().map_err(io::Error::other)
}

/// The buffer size to offer the next read, after one that returned `n` bytes
/// into `room`: twice as much when the read filled its buffer, half when it
/// used less than a quarter of what was asked for.
fn next_read_size(want: usize, n: usize, room: usize) -> usize {
    if n == room {
        (want * 2).min(READ_MAX)
    } else if n < want / 4 {
        (want / 2).max(READ_MIN)
    } else {
        want
    }
}

async fn tunnel_to_local<W>(mut recv: RecvStream, mut writer: W) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut chunks: [Bytes; MAX_CHUNKS] = std::array::from_fn(|_| Bytes::new());
    while let Some(n) = recv.read_many_chunks(&mut chunks).await? {
        write_chunks(&mut writer, &mut chunks[..n]).await?;
        writer.flush().await?;
    }
    writer.shutdown().await
}

/// Write every chunk, leaving each one empty. A writer without vectored
/// writes would take only the first slice of each call, so it gets the chunks
/// one by one.
async fn write_chunks<W>(writer: &mut W, mut chunks: &mut [Bytes]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if !writer.is_write_vectored() {
        for chunk in chunks {
            writer.write_all(chunk).await?;
            chunk.clear();
        }
        return Ok(());
    }
    loop {
        let spent = chunks.iter().take_while(|chunk| chunk.is_empty()).count();
        chunks = &mut std::mem::take(&mut chunks)[spent..];
        if chunks.is_empty() {
            return Ok(());
        }
        let mut slices = [IoSlice::new(&[]); MAX_CHUNKS];
        for (slice, chunk) in slices.iter_mut().zip(chunks.iter()) {
            *slice = IoSlice::new(chunk);
        }
        let mut written = writer.write_vectored(&slices[..chunks.len()]).await?;
        if written == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        for chunk in chunks.iter_mut() {
            let taken = written.min(chunk.len());
            chunk.advance(taken);
            written -= taken;
            if written == 0 {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    #[test]
    fn read_size_follows_how_full_the_reads_are() {
        // A read that fills its buffer doubles the next one, up to the cap.
        assert_eq!(next_read_size(READ_MIN, READ_MIN, READ_MIN), 2 * READ_MIN);
        assert_eq!(next_read_size(READ_MAX, READ_MAX, READ_MAX), READ_MAX);
        // Leftover room larger than what was asked for counts as it is.
        assert_eq!(next_read_size(READ_MIN, READ_MIN, READ_MAX), READ_MIN);
        // A read well short of what was asked for halves it, down to the floor.
        assert_eq!(next_read_size(READ_MAX, 100, READ_MAX), READ_MAX / 2);
        assert_eq!(next_read_size(READ_MIN, 1, READ_MIN), READ_MIN);
        // Anything in between leaves it alone.
        assert_eq!(next_read_size(READ_MAX, READ_MAX / 2, READ_MAX), READ_MAX);
    }

    /// A vectored writer that takes at most `limit` bytes per call, so a call
    /// can end in the middle of a chunk.
    struct Stingy {
        limit: usize,
        vectored: bool,
        out: Vec<u8>,
        vectored_calls: usize,
    }

    impl Stingy {
        fn new(limit: usize, vectored: bool) -> Self {
            Self {
                limit,
                vectored,
                out: Vec::new(),
                vectored_calls: 0,
            }
        }
    }

    impl AsyncWrite for Stingy {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let n = buf.len().min(self.limit);
            self.out.extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }

        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            self.vectored_calls += 1;
            let mut left = self.limit;
            for buf in bufs {
                let n = buf.len().min(left);
                self.out.extend_from_slice(&buf[..n]);
                left -= n;
            }
            Poll::Ready(Ok(self.limit - left))
        }

        fn is_write_vectored(&self) -> bool {
            self.vectored
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn sample_chunks() -> (Vec<Bytes>, Vec<u8>) {
        let chunks: Vec<Bytes> = [5usize, 0, 1200, 3, 0, 700]
            .iter()
            .enumerate()
            .map(|(i, len)| Bytes::from(vec![i as u8 + 1; *len]))
            .collect();
        let all = chunks.iter().flat_map(|c| c.iter().copied()).collect();
        (chunks, all)
    }

    #[tokio::test]
    async fn partial_vectored_writes_lose_and_repeat_nothing() {
        for limit in [1, 7, 1200, 1205, 4096] {
            let (mut chunks, all) = sample_chunks();
            let mut writer = Stingy::new(limit, true);
            write_chunks(&mut writer, &mut chunks).await.unwrap();
            assert_eq!(writer.out, all, "limit {limit}");
            assert!(writer.vectored_calls > 0);
            assert!(chunks.iter().all(Bytes::is_empty), "chunks are spent");
        }
    }

    #[tokio::test]
    async fn a_writer_without_vectored_writes_gets_every_chunk() {
        for limit in [1, 7, 4096] {
            let (mut chunks, all) = sample_chunks();
            let mut writer = Stingy::new(limit, false);
            write_chunks(&mut writer, &mut chunks).await.unwrap();
            assert_eq!(writer.out, all, "limit {limit}");
            assert_eq!(writer.vectored_calls, 0);
            assert!(chunks.iter().all(Bytes::is_empty), "chunks are spent");
        }
    }
}
