use std::{
    collections::{hash_map::Entry, HashMap},
    future::Future,
    io::{Error, IoSlice},
    pin::Pin,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

use pin_project_lite::pin_project;
use s2n_quic::{
    connection::{Handle, StreamAcceptor as QuicStreamAcceptor},
    stream::{ReceiveStream as QuicRecvStream, SendStream as QuicSendStream},
};
use serde::{de::DeserializeOwned, Serialize};
use tokio::{
    io,
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    select,
    sync::{mpsc, oneshot},
};
use tokio_serde::{
    formats::{Bincode, SymmetricalBincode},
    SymmetricallyFramed,
};
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use tracing::{debug, error, event, Level};

#[cfg(feature = "metrics")]
pub mod metrics;

#[doc(hidden)]
#[cfg(any(test, feature = "__testing"))]
pub mod testing;

/// Explicit Id provided by the user for a stream for a specific [`Connection`].
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct Id(pub(crate) u64);

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
enum StreamId {
    Implicit(u64),
    Explicit(u64),
}

/// Id of a [`Connection`]. Does not include parent Ids of this connection.
/// It is only unique with respect to its sibling connections created by
/// [`Connection::sub_connection`].
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
struct ConnectionId(pub(crate) u32);

/// Unique id of a stream and all its parent [`ConnectionId`]s.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
struct UniqueId {
    cids: Vec<ConnectionId>,
    id: StreamId,
}

type StreamSend = oneshot::Sender<(QuicRecvStream, usize)>;
type StreamRecv = oneshot::Receiver<(QuicRecvStream, usize)>;

/// Manages accepting of new streams.
pub struct StreamManager {
    acceptor: QuicStreamAcceptor,
    cmd_send: mpsc::UnboundedSender<Cmd>,
    cmd_recv: mpsc::UnboundedReceiver<Cmd>,
    pending: HashMap<UniqueId, StreamSend>,
    accepted: HashMap<UniqueId, (QuicRecvStream, usize)>,
}

/// Used to create grouped sub-streams.
///
/// Connections can have sub-connections. Streams created via
/// [`Connection::byte_stream`] and [`Connection::stream`] are tied to their
/// connection. Streams created with the same [`Id`] but for different
/// connections will not conflict with each other.
#[derive(Debug)]
pub struct Connection {
    cids: Vec<ConnectionId>,
    next_cid: Arc<AtomicU32>,
    handle: Handle,
    cmd: mpsc::UnboundedSender<Cmd>,
    next_implicit_id: u64,
}

pin_project! {
    /// Send part of the bytes stream.
    // TODO provide a way to temporarily use a byte stream as a typed stream,
    //  useful for protocols with different serde compatible msg types to
    // prevent unnecessary stream creation
    pub struct SendStreamBytes {
        #[pin]
        inner: QuicSendStream
    }
}

pin_project! {
    /// Receive part of the bytes stream.
    pub struct ReceiveStreamBytes {
        #[pin]
        inner: ReceiveStreamWrapper
    }
}

/// Send part of the serialized stream.
pub type SendStream<T> = SymmetricallyFramed<
    FramedWrite<SendStreamBytes, LengthDelimitedCodec>,
    T,
    SymmetricalBincode<T>,
>;

pub type TempSendStream<'a, T> = SymmetricallyFramed<
    FramedWrite<&'a mut SendStreamBytes, LengthDelimitedCodec>,
    T,
    SymmetricalBincode<T>,
>;

/// Receive part of the serialized stream.
pub type ReceiveStream<T> = SymmetricallyFramed<
    FramedRead<ReceiveStreamBytes, LengthDelimitedCodec>,
    T,
    SymmetricalBincode<T>,
>;

pub type ReceiveStreamTemp<'a, T> = SymmetricallyFramed<
    FramedRead<&'a mut ReceiveStreamBytes, LengthDelimitedCodec>,
    T,
    SymmetricalBincode<T>,
>;

pin_project! {
    #[project = ReceiveStreamWrapperProj]
    enum ReceiveStreamWrapper {
        Channel { #[pin] stream_recv: StreamRecv},
        Stream { #[pin] recv_stream: QuicRecvStream }
    }
}

#[derive(Debug)]
enum Cmd {
    NewStream {
        uid: UniqueId,
        stream_return: StreamSend,
    },
    AcceptedStream {
        uid: UniqueId,
        stream: QuicRecvStream,
        bytes_read: usize,
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

    /// Start the StreamManager to accept streams.
    ///
    /// This method needs to be continually polled to establish new streams.
    #[tracing::instrument(skip_all)]
    pub async fn start(mut self) {
        loop {
            select! {
                res = self.acceptor.accept_receive_stream() => {
                    debug!("accepted stream");
                    match res {
                        Ok(Some(mut stream)) => {
                            let cmd_send = self.cmd_send.clone();
                            tokio::spawn(async move {
                                let mut buf = [0; 2];
                                if let Err(err) = stream.read_exact(&mut buf).await {
                                    error!(%err, "reading unique id size");
                                    return;
                                }
                                let len = u16::from_be_bytes(buf);
                                let mut buf = vec![0; len as usize];
                                if let Err(err) = stream.read_exact(&mut buf).await {
                                    error!(%err, "reading unique ids");
                                    return;
                                }
                                let uid = match UniqueId::from_bytes(&buf) {
                                    Ok(uid) => uid,
                                    Err(err) => {
                                        error!(%err, "parsing unique ids");
                                        return;
                                    }
                                };
                                cmd_send.send(Cmd::AcceptedStream {uid, stream, bytes_read: 2 + buf.len()}).expect("cmd_rcv is owned by StreamManager")
                            });
                        }
                        Ok(None) => {
                            debug!("remote closed");
                            return;
                        }
                        Err(err) => {
                            error!(%err, "unable to accept stream");
                            return;
                        }
                    }
                }
                Some(cmd) = self.cmd_recv.recv() => {
                    debug!(?cmd, "received cmd");
                    match cmd {
                        Cmd::NewStream {uid, stream_return} => {
                            if let Some(accepted) = self.accepted.remove(&uid) {
                                if stream_return.send(accepted).is_err() {
                                    debug!("accepted remote stream but local receiver is closed");
                                }
                                debug!("sending new stream to receiver");
                                continue;
                            }
                            match self.pending.entry(uid) {
                                Entry::Occupied(occupied_entry) => {
                                    panic!("Duplicate unique id: {:?}", occupied_entry.key())
                                },
                                Entry::Vacant(vacant_entry) => {vacant_entry.insert(stream_return);},
                            }
                        }
                        Cmd::AcceptedStream {uid, stream, bytes_read} => {
                            if let Some(stream_ret) = self.pending.remove(&uid) {
                               if stream_ret.send((stream, bytes_read)).is_err() {
                                debug!("accepted remote stream but local receiver is closed");
                               }
                            } else {
                                debug!("accepted stream but no pending");
                                self.accepted.insert(uid, (stream, bytes_read));
                            }
                        }
                    }
                }
            }
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ConnectionError {
    #[error("Unable to open stream")]
    OpenStream(#[source] s2n_quic::connection::Error),
    #[error("io error during stream establishment")]
    IoError(#[source] io::Error),
    #[error("StreamManager is dropped and not accepting connections")]
    StreamManagerDropped,
}

impl Connection {
    pub fn new(quic_conn: s2n_quic::Connection) -> (Self, StreamManager) {
        let (handle, acceptor) = quic_conn.split();
        let stream_manager = StreamManager::new(acceptor);
        let conn = Self {
            cids: vec![],
            next_cid: Arc::new(AtomicU32::new(0)),
            handle,
            cmd: stream_manager.cmd_send.clone(),
            next_implicit_id: 0,
        };
        (conn, stream_manager)
    }

    /// Create a sub-connection. The n'th call to sub_connection
    /// is paired with the n'th call to `sub_connection` on the corresponding
    /// [`Connection`] of the other party. Creating a sub-connection results
    /// in no immediate communication and is a fast synchronous operation.
    #[tracing::instrument(level = Level::DEBUG, skip(self), ret)]
    pub fn sub_connection(&mut self) -> Self {
        let cid = self.next_cid.fetch_add(1, Ordering::Relaxed);
        let mut cids = self.cids.clone();
        cids.push(ConnectionId(cid));
        Self {
            cids,
            next_cid: Arc::new(AtomicU32::new(0)),
            handle: self.handle.clone(),
            cmd: self.cmd.clone(),
            next_implicit_id: 0,
        }
    }

    async fn internal_byte_stream(
        &mut self,
        stream_id: StreamId,
    ) -> Result<(SendStreamBytes, ReceiveStreamBytes), ConnectionError> {
        let uid = UniqueId::new(self.cids.clone(), stream_id);
        let mut snd = self
            .handle
            .open_send_stream()
            .await
            .map_err(ConnectionError::OpenStream)?;
        let uid_bytes = uid.to_bytes();
        snd.write_all(&(uid_bytes.len() as u16).to_be_bytes())
            .await
            .map_err(ConnectionError::IoError)?;
        snd.write_all(&uid_bytes)
            .await
            .map_err(ConnectionError::IoError)?;
        event!(target: "seec_metrics", Level::TRACE, bytes_written = 2 + uid_bytes.len());
        let (stream_return, stream_recv) = oneshot::channel();
        self.cmd
            .send(Cmd::NewStream { uid, stream_return })
            .map_err(|_| ConnectionError::StreamManagerDropped)?;
        let snd = SendStreamBytes { inner: snd };
        let recv = ReceiveStreamBytes {
            inner: ReceiveStreamWrapper::Channel { stream_recv },
        };
        Ok((snd, recv))
    }

    /// Establish a byte stream over this connection with the provided Id.
    pub async fn byte_stream(
        &mut self,
    ) -> Result<(SendStreamBytes, ReceiveStreamBytes), ConnectionError> {
        self.next_implicit_id += 1;
        self.internal_byte_stream(StreamId::Implicit(self.next_implicit_id - 1))
            .await
    }

    /// Establish a byte stream over this connection with the provided Id.
    pub async fn byte_stream_with_id(
        &mut self,
        id: Id,
    ) -> Result<(SendStreamBytes, ReceiveStreamBytes), ConnectionError> {
        self.internal_byte_stream(StreamId::Explicit(id.0)).await
    }

    /// Establish a typed stream over this connection.
    async fn internal_stream<T: Serialize + DeserializeOwned>(
        &mut self,
        id: StreamId,
    ) -> Result<(SendStream<T>, ReceiveStream<T>), ConnectionError> {
        let (send_bytes, recv_bytes) = self.internal_byte_stream(id).await?;
        let mut ld_codec = LengthDelimitedCodec::builder();
        // TODO what is a sensible max length?
        const MB: usize = 1024 * 1024;
        ld_codec.max_frame_length(256 * MB);
        let framed_send = ld_codec.new_write(send_bytes);
        let framed_read = ld_codec.new_read(recv_bytes);
        let serde_send = SymmetricallyFramed::new(framed_send, Bincode::default());
        let serde_read = SymmetricallyFramed::new(framed_read, Bincode::default());
        Ok((serde_send, serde_read))
    }

    /// Establish a typed stream over this connection.
    pub async fn stream<T: Serialize + DeserializeOwned>(
        &mut self,
    ) -> Result<(SendStream<T>, ReceiveStream<T>), ConnectionError> {
        self.next_implicit_id += 1;
        self.internal_stream(StreamId::Implicit(self.next_implicit_id - 1))
            .await
    }

    /// Establish a typed stream over this connection with the provided explicit
    /// Id.
    pub async fn stream_with_id<T: Serialize + DeserializeOwned>(
        &mut self,
        id: Id,
    ) -> Result<(SendStream<T>, ReceiveStream<T>), ConnectionError> {
        self.internal_stream(StreamId::Explicit(id.0)).await
    }

    async fn internal_request_response_stream<T: Serialize, S: DeserializeOwned>(
        &mut self,
        id: StreamId,
    ) -> Result<(SendStream<T>, ReceiveStream<S>), ConnectionError> {
        let (send_bytes, recv_bytes) = self.internal_byte_stream(id).await?;
        let mut ld_codec = LengthDelimitedCodec::builder();
        // TODO what is a sensible max length?
        const MB: usize = 1024 * 1024;
        ld_codec.max_frame_length(256 * MB);
        let framed_send = ld_codec.new_write(send_bytes);
        let framed_read = ld_codec.new_read(recv_bytes);
        let serde_send = SymmetricallyFramed::new(framed_send, Bincode::default());
        let serde_read = SymmetricallyFramed::new(framed_read, Bincode::default());
        Ok((serde_send, serde_read))
    }

    /// Establish a typed request-response stream over this connection with
    /// differing types for the request and response.
    pub async fn request_response_stream<T: Serialize, S: DeserializeOwned>(
        &mut self,
    ) -> Result<(SendStream<T>, ReceiveStream<S>), ConnectionError> {
        self.next_implicit_id += 1;
        self.internal_request_response_stream(StreamId::Implicit(self.next_implicit_id - 1))
            .await
    }

    /// Establish a typed request-response stream over this connection with
    /// differing types for the request and response.
    pub async fn request_response_stream_with_id<T: Serialize, S: DeserializeOwned>(
        &mut self,
        id: Id,
    ) -> Result<(SendStream<T>, ReceiveStream<S>), ConnectionError> {
        self.internal_request_response_stream(StreamId::Explicit(id.0))
            .await
    }
}

impl Id {
    pub fn new(id: u64) -> Self {
        Self(id)
    }
}

impl StreamId {
    const SERIALIZED_SIZE: usize = 9;

    fn from_bytes(bytes: [u8; 9]) -> Self {
        let id = u64::from_be_bytes(bytes[1..].try_into().expect("slice has size 8"));
        match bytes[0] {
            0 => Self::Explicit(id),
            _ => Self::Implicit(id),
        }
    }

    fn to_bytes(self) -> [u8; 9] {
        let mut ret = [0; 9];
        match self {
            Self::Explicit(id) => {
                ret[1..].copy_from_slice(&id.to_be_bytes());
            }
            Self::Implicit(id) => {
                ret[0] = 1;
                ret[1..].copy_from_slice(&id.to_be_bytes());
            }
        }
        ret
    }
}

impl ConnectionId {
    pub fn from_bytes(bytes: [u8; 4]) -> Self {
        Self(u32::from_be_bytes(bytes))
    }

    pub fn to_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ParseUniqueIdError {
    #[error("insufficient data to parse UniqueId")]
    InsufficientData,
    #[error("unused remaining data. Remaining bytes: {0}")]
    RemainingData(usize),
}

impl UniqueId {
    fn new(cids: Vec<ConnectionId>, id: StreamId) -> Self {
        Self { cids, id }
    }

    fn from_bytes(mut bytes: &[u8]) -> Result<Self, ParseUniqueIdError> {
        if bytes.len() < StreamId::SERIALIZED_SIZE {
            return Err(ParseUniqueIdError::InsufficientData);
        }
        let id = StreamId::from_bytes(
            bytes[..StreamId::SERIALIZED_SIZE]
                .try_into()
                .expect("len checked before"),
        );
        bytes = &bytes[StreamId::SERIALIZED_SIZE..];

        // 4 bytes in u32
        let mut chunks_iter = bytes.chunks_exact(4);
        let cids = chunks_iter
            .by_ref()
            .map(|chunk| ConnectionId::from_bytes(chunk.try_into().unwrap()))
            .collect();

        if !chunks_iter.remainder().is_empty() {
            return Err(ParseUniqueIdError::RemainingData(
                chunks_iter.remainder().len(),
            ));
        }

        Ok(Self { cids, id })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut ret = Vec::with_capacity(8 + self.cids.len() * 4);
        let id = self.id.to_bytes();
        ret.extend_from_slice(&id);
        for cid in &self.cids {
            ret.extend_from_slice(&cid.to_bytes());
        }
        ret
    }
}

#[derive(thiserror::Error, Debug)]
pub enum StreamError {
    #[error("unable to flush stream")]
    Flush(#[source] s2n_quic::stream::Error),
    #[error("unable to close stream")]
    Close(#[source] s2n_quic::stream::Error),
    #[error("unable to finish stream")]
    Finish(#[source] s2n_quic::stream::Error),
}

impl SendStreamBytes {
    pub async fn flush(&mut self) -> Result<(), StreamError> {
        self.inner.flush().await.map_err(StreamError::Flush)
    }

    pub fn finish(&mut self) -> Result<(), StreamError> {
        self.inner.finish().map_err(StreamError::Finish)
    }

    pub async fn close(&mut self) -> Result<(), StreamError> {
        self.inner.close().await.map_err(StreamError::Close)
    }

    pub fn as_stream<T: Serialize>(&mut self) -> TempSendStream<T> {
        let mut ld_codec = LengthDelimitedCodec::builder();
        // TODO what is a sensible max length?
        const MB: usize = 1024 * 1024;
        ld_codec.max_frame_length(256 * MB);
        let framed_send = ld_codec.new_write(self);
        SymmetricallyFramed::new(framed_send, Bincode::default())
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

impl ReceiveStreamBytes {
    pub fn as_stream<T: DeserializeOwned>(&mut self) -> ReceiveStreamTemp<T> {
        let mut ld_codec = LengthDelimitedCodec::builder();
        // TODO what is a sensible max length?
        const MB: usize = 1024 * 1024;
        ld_codec.max_frame_length(256 * MB);
        let framed_read = ld_codec.new_read(self);
        SymmetricallyFramed::new(framed_read, Bincode::default())
    }
}

// Implement AsyncRead for ReceiveStream to poll the oneshot Receiver first if
// there is not already a channel.
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
                Poll::Ready(Ok((recv_stream, bytes_read))) => {
                    // We know we read those bytes in the StreamManager, so we emit
                    // the corresponding event here in the correct span.
                    event!(target: "seec_metrics", Level::TRACE, bytes_read);
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
    use std::{time::Duration, u8};

    use anyhow::{Context, Result};
    use futures::{SinkExt, StreamExt};
    use seec_core::test_utils::init_tracing;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        task::JoinSet,
        time::{sleep, Sleep},
    };
    use tracing::debug;

    use crate::{testing::local_conn, Id};

    #[tokio::test]
    async fn create_local_conn() -> Result<()> {
        let _ = local_conn().await?;
        Ok(())
    }

    #[tokio::test]
    async fn byte_stream() -> Result<()> {
        let (mut s, mut c) = local_conn().await?;
        let (mut s_send, _) = s.byte_stream_with_id(Id::new(0)).await?;
        let (_, mut c_recv) = c.byte_stream_with_id(Id::new(0)).await?;
        let send_buf = b"hello there";
        s_send.write_all(send_buf).await?;
        let mut buf = [0; 11];
        c_recv.read_exact(&mut buf).await?;
        assert_eq!(send_buf, &buf);
        Ok(())
    }

    #[tokio::test]
    async fn byte_stream_explicit_implicit_id() -> Result<()> {
        let (mut s, mut c) = local_conn().await?;
        let (mut s_send1, _) = s.byte_stream_with_id(Id::new(0)).await?;
        let (mut s_send2, _) = s.byte_stream().await?;
        let (_, mut c_recv1) = c.byte_stream_with_id(Id::new(0)).await?;
        let (_, mut c_recv2) = c.byte_stream().await?;
        let send_buf1 = b"hello there";
        s_send1.write_all(send_buf1).await?;
        let mut buf = [0; 11];
        c_recv1.read_exact(&mut buf).await?;
        assert_eq!(send_buf1, &buf);

        let send_buf2 = b"general kenobi";
        s_send2.write_all(send_buf2).await?;
        let mut buf = [0; 14];
        c_recv2.read_exact(&mut buf).await?;
        assert_eq!(send_buf2, &buf);
        Ok(())
    }

    #[tokio::test]
    async fn byte_stream_different_order() -> Result<()> {
        let (mut s, mut c) = local_conn().await?;
        let (mut s_send, mut s_recv) = s.byte_stream_with_id(Id::new(0)).await?;
        let s_send_buf = b"hello there";
        s_send.write_all(s_send_buf).await?;
        let mut s_recv_buf = [0; 2];
        // By already spawning the read task before the client calls c._new_byte_stream
        // we check that the switch from channel to s2n stream works
        let jh = tokio::spawn(async move {
            s_recv.read_exact(&mut s_recv_buf).await.unwrap();
            s_recv_buf
        });
        let (mut c_send, mut c_recv) = c.byte_stream_with_id(Id::new(0)).await?;
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
    async fn many_parallel_byte_streams() -> Result<()> {
        let _g = init_tracing();
        let (mut c1, mut c2) = local_conn().await?;
        let mut jhs = JoinSet::new();
        for i in 0..10 {
            let ((mut s, _), (_, mut r)) =
                tokio::try_join!(c1.byte_stream(), c2.byte_stream()).unwrap();

            let jh = tokio::spawn(async move {
                let buf = vec![0; 200 * 1024 * 1024];
                s.write_all(&buf).await.unwrap();
                debug!("wrote buf {i}");
            });
            jhs.spawn(jh);
            let jh = tokio::spawn(async move {
                let mut buf = vec![0; 200 * 1024 * 1024];
                r.read_exact(&mut buf).await.unwrap();
                debug!("received buf {i}");
            });
            jhs.spawn(jh);
        }
        let res = jhs.join_all().await;
        for res in res {
            res.unwrap();
        }
        Ok(())
    }

    #[tokio::test]
    async fn serde_stream() -> Result<()> {
        let (mut s, mut c) = local_conn().await?;
        let (mut snd, _) = s.stream_with_id::<Vec<i32>>(Id::new(0)).await?;
        let (_, mut recv) = c.stream_with_id::<Vec<i32>>(Id::new(0)).await?;
        snd.send(vec![1, 2, 3]).await?;
        let ret = recv.next().await.context("recv")??;
        assert_eq!(vec![1, 2, 3], ret);
        drop(snd);
        let ret = recv.next().await.map(|res| res.map_err(|_| ()));
        assert_eq!(None, ret);
        Ok(())
    }

    #[tokio::test]
    async fn serde_stream_block() -> Result<()> {
        let (mut s, mut c) = local_conn().await?;
        let (mut snd, _) = s.stream_with_id(Id::new(0)).await?;
        let (_, mut recv) = c.stream_with_id(Id::new(0)).await?;
        snd.send(vec![u8::MAX; 16]).await?;
        let ret: Vec<_> = recv.next().await.context("recv")??;
        assert_eq!(vec![u8::MAX; 16], ret);
        Ok(())
    }

    #[tokio::test]
    async fn serde_byte_stream_as_stream() -> Result<()> {
        let (mut s, mut c) = local_conn().await?;
        let (mut s_send, _) = s.byte_stream_with_id(Id::new(0)).await?;
        let (_, mut c_recv) = c.byte_stream_with_id(Id::new(0)).await?;
        {
            let mut send_ser1 = s_send.as_stream::<i32>();
            let mut recv_ser1 = c_recv.as_stream::<i32>();
            send_ser1.send(42).await?;
            let ret = recv_ser1.next().await.context("recv")??;
            assert_eq!(42, ret);
        }
        {
            let mut send_ser2 = s_send.as_stream::<Vec<i32>>();
            let mut recv_ser2 = c_recv.as_stream::<Vec<i32>>();
            send_ser2.send(vec![1, 2, 3]).await?;
            let ret = recv_ser2.next().await.context("recv")??;
            assert_eq!(vec![1, 2, 3], ret);
        }
        Ok(())
    }

    #[tokio::test]
    async fn serde_request_response_stream() -> Result<()> {
        let (mut s, mut c) = local_conn().await?;
        let (mut snd1, mut recv1) = s
            .request_response_stream_with_id::<Vec<i32>, String>(Id::new(0))
            .await?;
        let (mut snd2, mut recv2) = c
            .request_response_stream_with_id::<String, Vec<i32>>(Id::new(0))
            .await?;
        snd1.send(vec![1, 2, 3]).await?;
        let ret = recv2.next().await.context("recv")??;
        assert_eq!(vec![1, 2, 3], ret);
        snd2.send("hello there".to_string()).await?;
        let ret = recv1.next().await.context("recv2")??;
        assert_eq!("hello there", &ret);
        Ok(())
    }

    #[tokio::test]
    async fn sub_connection() -> Result<()> {
        let (mut s1, mut c1) = local_conn().await?;
        let mut s2 = s1.sub_connection();
        let mut c2 = c1.sub_connection();
        let _ = s1.byte_stream_with_id(Id::new(0));
        let _ = c1.byte_stream_with_id(Id::new(0));
        let (mut snd, _) = s2.stream_with_id::<Vec<i32>>(Id::new(0)).await?;
        let (_, mut recv) = c2.stream_with_id::<Vec<i32>>(Id::new(0)).await?;

        snd.send(vec![1, 2, 3]).await?;
        let ret = recv.next().await.context("recv")??;
        assert_eq!(vec![1, 2, 3], ret);
        Ok(())
    }

    #[tokio::test]
    async fn sub_sub_connection() -> Result<()> {
        let (mut s1, mut c1) = local_conn().await?;
        let mut s2 = s1.sub_connection();
        let mut c2 = c1.sub_connection();
        let mut s3 = s2.sub_connection();
        let mut c3 = c2.sub_connection();
        let _ = s1.byte_stream_with_id(Id::new(0));
        let _ = c1.byte_stream_with_id(Id::new(0));
        let _ = s2.byte_stream_with_id(Id::new(1));
        let _ = c2.byte_stream_with_id(Id::new(1));
        let (mut snd, _) = s3.stream_with_id::<Vec<i32>>(Id::new(0)).await?;
        let (_, mut recv) = c3.stream_with_id::<Vec<i32>>(Id::new(0)).await?;

        snd.send(vec![1, 2, 3]).await?;
        let ret = recv.next().await.context("recv")??;
        assert_eq!(vec![1, 2, 3], ret);
        Ok(())
    }
}
