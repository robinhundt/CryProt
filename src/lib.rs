use pin_project_lite::pin_project;
use s2n_quic::connection::{Handle, StreamAcceptor as QuicStreamAcceptor};
use s2n_quic::stream::ReceiveStream as QuicRecvStream;
use s2n_quic::stream::SendStream as QuicSendStream;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashMap;
use std::future::Future;
use std::io::{Error, IoSlice};
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use tokio::{io, select};
use tokio_serde::formats::{Bincode, SymmetricalBincode};
use tokio_serde::SymmetricallyFramed;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use tracing::{event, Level};

#[cfg(feature = "metrics")]
pub mod metrics;

#[doc(hidden)]
#[cfg(any(test, feature = "__bench"))]
pub mod testing;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct Id(pub(crate) u64);

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct ConnectionId(pub(crate) u32);

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
struct UniqueId {
    cid: ConnectionId,
    id: Id,
}

type StreamSend = oneshot::Sender<QuicRecvStream>;
type StreamRecv = oneshot::Receiver<QuicRecvStream>;

pub struct StreamManager {
    acceptor: QuicStreamAcceptor,
    cmd_send: mpsc::UnboundedSender<Cmd>,
    cmd_recv: mpsc::UnboundedReceiver<Cmd>,
    pending: HashMap<UniqueId, StreamSend>,
    accepted: HashMap<UniqueId, QuicRecvStream>,
}

// TODO provide safer way of cloning or creating a "sub-connection" with less potential
//  for Id collisions
#[cfg_attr(any(test, feature = "__bench"), derive(Clone))]
pub struct Connection {
    cid: ConnectionId,
    next_cid: Arc<AtomicU32>,
    handle: Handle,
    cmd: mpsc::UnboundedSender<Cmd>,
}

pin_project! {
    pub struct SendStreamBytes {
        #[pin]
        inner: QuicSendStream
    }
}

pin_project! {
    pub struct ReceiveStreamBytes {
        #[pin]
        inner: ReceiveStreamWrapper
    }
}

pub type SendStream<T> = SymmetricallyFramed<
    FramedWrite<SendStreamBytes, LengthDelimitedCodec>,
    T,
    SymmetricalBincode<T>,
>;
pub type ReceiveStream<T> = SymmetricallyFramed<
    FramedRead<ReceiveStreamBytes, LengthDelimitedCodec>,
    T,
    SymmetricalBincode<T>,
>;

pin_project! {
    #[project = ReceiveStreamWrapperProj]
    enum ReceiveStreamWrapper {
        Channel { #[pin] stream_recv: StreamRecv },
        Stream { #[pin] recv_stream: QuicRecvStream }
    }
}

enum Cmd {
    NewStream {
        uid: UniqueId,
        stream_return: StreamSend,
    },
    AcceptedStream {
        uid: UniqueId,
        stream: QuicRecvStream,
    },
}

impl StreamManager {
    pub fn new(acceptor: QuicStreamAcceptor) -> Self {
        let (cmd_send, cmd_recv) = mpsc::unbounded_channel();
        Self {
            acceptor,
            cmd_send,
            cmd_recv,
            pending: Default::default(),
            accepted: Default::default(),
        }
    }
    
    pub async fn start(mut self) {
        loop {
            select! {
                res = self.acceptor.accept_receive_stream() => {
                    match res {
                        Ok(Some(mut stream)) => {
                            let cmd_send = self.cmd_send.clone();
                            tokio::spawn(async move {
                                let mut buf = [0; 12];
                                stream.read_exact(&mut buf).await.unwrap();
                                let uid = UniqueId::from_bytes(buf);
                                cmd_send.send(Cmd::AcceptedStream {uid, stream}).unwrap()
                            });
                        }
                        Ok(None) => {
                            // connection is closed
                            return;
                        }
                        Err(err) => {
                            panic!("{:?}", err);
                        }
                    }
                }
                Some(cmd) = self.cmd_recv.recv() => {
                    match cmd {
                        Cmd::NewStream {uid, stream_return} => {
                            if let Some(accepted) = self.accepted.remove(&uid) {
                                stream_return.send(accepted).unwrap()
                            } else if self.pending.insert(uid, stream_return).is_some() {
                                panic!("Id collision for {uid:?}");
                            }
                        }
                        Cmd::AcceptedStream {uid, stream} => {
                            if let Some(stream_ret) = self.pending.remove(&uid) {
                               stream_ret.send(stream).unwrap()
                            } else {
                                self.accepted.insert(uid, stream);
                            }
                        }
                    }
                }
            }
        }
    }
}

impl Connection {
    pub fn new(quic_conn: s2n_quic::Connection) -> (Self, StreamManager) {
        let (handle, acceptor) = quic_conn.split();
        let stream_manager = StreamManager::new(acceptor);
        let conn = Self {
            cid: ConnectionId(0),
            next_cid: Arc::new(AtomicU32::new(1)),
            handle,
            cmd: stream_manager.cmd_send.clone(),
        };
        (conn, stream_manager)
    }

    /// Create a sub-connection. The n'th call to sub_connection on **any** `Connection`
    /// is paired with the n'th call of the other party. Internally, all Connections share
    /// an incrementing id.
    pub fn sub_connection(&self) -> Self {
        let cid = self.next_cid.fetch_add(1, Ordering::Relaxed);
        Self {
            cid: ConnectionId(cid),
            next_cid: self.next_cid.clone(),
            handle: self.handle.clone(),
            cmd: self.cmd.clone(),
        }
    }

    pub async fn byte_sub_stream(&mut self, id: Id) -> (SendStreamBytes, ReceiveStreamBytes) {
        let uid = UniqueId::new(self.cid, id);
        let mut snd = self.handle.open_send_stream().await.unwrap();
        snd.write_all(&uid.to_bytes()).await.unwrap();
        event!(target: "seec_metrics", Level::TRACE, bytes_written = UniqueId::BYTE_LEN);
        let (stream_return, stream_recv) = oneshot::channel();
        self.cmd
            .send(Cmd::NewStream { uid, stream_return })
            .unwrap();
        let snd = SendStreamBytes { inner: snd };
        let recv = ReceiveStreamBytes {
            inner: ReceiveStreamWrapper::Channel { stream_recv },
        };
        (snd, recv)
    }

    pub async fn sub_stream<T: Serialize + DeserializeOwned>(
        &mut self,
        id: Id,
    ) -> (SendStream<T>, ReceiveStream<T>) {
        let (send_bytes, recv_bytes) = self.byte_sub_stream(id).await;
        let mut ld_codec = LengthDelimitedCodec::builder();
        // TODO what is a sensible max length?
        const MB: usize = 1024 * 1024;
        ld_codec.max_frame_length(256 * MB);
        let framed_send = ld_codec.new_write(send_bytes);
        let framed_read = ld_codec.new_read(recv_bytes);
        let serde_send = SymmetricallyFramed::new(framed_send, Bincode::default());
        let serde_read = SymmetricallyFramed::new(framed_read, Bincode::default());
        (serde_send, serde_read)
    }
}

impl Id {
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    pub fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(u64::from_be_bytes(bytes))
    }

    pub fn to_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
}

impl UniqueId {
    const BYTE_LEN: usize = 12;
    fn new(cid: ConnectionId, id: Id) -> Self {
        Self { cid, id }
    }

    fn from_bytes(bytes: [u8; Self::BYTE_LEN]) -> Self {
        // Panics are optimized out with constant indices
        let cid = u32::from_be_bytes(bytes[..4].try_into().unwrap());
        let id = u64::from_be_bytes(bytes[4..Self::BYTE_LEN].try_into().unwrap());
        Self {
            cid: ConnectionId(cid),
            id: Id(id),
        }
    }

    fn to_bytes(self) -> [u8; Self::BYTE_LEN] {
        let mut ret = [0; Self::BYTE_LEN];
        let cid = self.cid.0.to_be_bytes();
        ret[..4].copy_from_slice(&cid);
        let id = self.id.to_bytes();
        ret[4..].copy_from_slice(&id);
        ret
    }
}

impl AsyncWrite for SendStreamBytes {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let this = self.project();
        trace_poll(this.inner.poll_write(cx, buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let this = self.project();
        AsyncWrite::poll_flush(this.inner, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let this = self.project();
        this.inner.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, Error>> {
        let this = self.project();
        trace_poll(this.inner.poll_write_vectored(cx, bufs))
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

fn trace_poll(p: Poll<io::Result<usize>>) -> Poll<io::Result<usize>> {
    if let Poll::Ready(Ok(bytes)) = p {
        event!(target: "seec_metrics", Level::TRACE, bytes_written = bytes);
    }
    p
}

// Implement AsyncRead for ReceiveStream to poll the oneshot Receiver first if there is not
// already a channel.
impl AsyncRead for ReceiveStreamBytes {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.as_mut().project();
        let this_inner = this.inner.as_mut().project();
        match this_inner {
            ReceiveStreamWrapperProj::Channel { stream_recv } => match stream_recv.poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(recv_stream)) => {
                    // We know we read those bytes in the StreamManager, so we emit
                    // the corresponding event here.
                    event!(target: "seec_metrics", Level::TRACE, bytes_read = UniqueId::BYTE_LEN);
                    *this.inner = ReceiveStreamWrapper::Stream { recv_stream };
                    self.poll_read(cx, buf)
                }
                Poll::Ready(Err(err)) => Poll::Ready(Err(std::io::Error::other(Box::new(err)))),
            },
            ReceiveStreamWrapperProj::Stream { recv_stream } => {
                let len = buf.filled().len();
                let poll = recv_stream.poll_read(cx, buf);
                if let Poll::Ready(Ok(())) = poll {
                    let bytes = buf.filled().len() - len;
                    if bytes > 0 {
                        event!(target: "seec_metrics", Level::TRACE, bytes_read = bytes);
                    }
                }
                poll
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::testing::local_conn;
    use crate::Id;
    use anyhow::{Context, Result};
    use futures::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn create_local_conn() -> Result<()> {
        let _ = local_conn().await?;
        Ok(())
    }

    #[tokio::test]
    async fn sub_stream() -> Result<()> {
        let (mut s, mut c) = local_conn().await?;
        let (mut s_send, _) = s.byte_sub_stream(Id::new(0)).await;
        let (_, mut c_recv) = c.byte_sub_stream(Id::new(0)).await;
        let send_buf = b"hello there";
        s_send.write_all(send_buf).await?;
        let mut buf = [0; 11];
        c_recv.read_exact(&mut buf).await?;
        assert_eq!(send_buf, &buf);
        Ok(())
    }

    #[tokio::test]
    async fn sub_stream_different_order() -> Result<()> {
        let (mut s, mut c) = local_conn().await?;
        let (mut s_send, mut s_recv) = s.byte_sub_stream(Id::new(0)).await;
        let s_send_buf = b"hello there";
        s_send.write_all(s_send_buf).await?;
        let mut s_recv_buf = [0; 2];
        // By already spawning the read task before the client calls c._new_byte_stream we
        // check that the switch from channel to s2n stream works
        let jh = tokio::spawn(async move {
            s_recv.read_exact(&mut s_recv_buf).await.unwrap();
            s_recv_buf
        });
        let (mut c_send, mut c_recv) = c.byte_sub_stream(Id::new(0)).await;
        let mut c_recv_buf = [0; 11];
        c_recv.read_exact(&mut c_recv_buf).await?;
        assert_eq!(s_send_buf, &c_recv_buf);
        let c_send_buf = b"42";
        c_send.write_all(c_send_buf).await?;
        let s_recv_buf = jh.await?;
        assert_eq!(c_send_buf, &s_recv_buf);
        Ok(())
    }

    #[tokio::test]
    async fn serde_sub_stream() -> Result<()> {
        let (mut s, mut c) = local_conn().await?;
        let (mut snd, _) = s.sub_stream::<Vec<i32>>(Id::new(0)).await;
        let (_, mut recv) = c.sub_stream::<Vec<i32>>(Id::new(0)).await;
        snd.send(vec![1, 2, 3]).await?;
        let ret = recv.next().await.context("recv")??;
        assert_eq!(vec![1, 2, 3], ret);
        Ok(())
    }

    #[tokio::test]
    async fn sub_connection() -> Result<()> {
        let (mut s1, mut c1) = local_conn().await?;
        let mut s2 = s1.sub_connection();
        let mut c2 = c1.sub_connection();
        let _ = s1.byte_sub_stream(Id::new(0));
        let _ = c1.byte_sub_stream(Id::new(0));
        let (mut snd, _) = s2.sub_stream::<Vec<i32>>(Id::new(0)).await;
        let (_, mut recv) = c2.sub_stream::<Vec<i32>>(Id::new(0)).await;

        snd.send(vec![1, 2, 3]).await?;
        let ret = recv.next().await.context("recv")??;
        assert_eq!(vec![1, 2, 3], ret);
        Ok(())
    }
}
