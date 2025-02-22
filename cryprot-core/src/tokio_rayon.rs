//! Tokio-Rayon integration to spawn compute tasks in async contexts.

use std::{
    future::Future,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    pin::Pin,
    task::{Context, Poll},
    thread,
};

use tokio::sync::oneshot;

pub struct TokioRayonJoinHandle<T: Send> {
    rx: oneshot::Receiver<thread::Result<T>>,
}

/// Spawns a compute intensive task on the [`rayon`] global threadpool and
/// returns a future that can be awaited without blocking the async task.
pub fn spawn_compute<F, T>(func: F) -> TokioRayonJoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = oneshot::channel();
    rayon::spawn(|| {
        let res = catch_unwind(AssertUnwindSafe(func));

        if let Err(Err(err)) = tx.send(res) {
            // if sending fails and func panicked, propagate panic to rayon panic handler
            resume_unwind(err);
        }
    });
    TokioRayonJoinHandle { rx }
}

impl<T: Send + 'static> Future for TokioRayonJoinHandle<T> {
    type Output = thread::Result<T>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let rx = Pin::new(&mut self.rx);
        match rx.poll(cx) {
            Poll::Ready(res) => {
                Poll::Ready(res.expect("oneshot::Sender is not dropped before send"))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
