use std::{
    future::Future,
    panic::{catch_unwind, resume_unwind, AssertUnwindSafe},
    pin::Pin,
    task::{ready, Context, Poll},
    thread,
};

use tokio::sync::oneshot;

pub struct TokioRayonJoinHandle<T: Send> {
    rx: oneshot::Receiver<thread::Result<T>>,
}

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
    type Output = T;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let rx = Pin::new(&mut self.rx);
        let res = ready!(rx.poll(cx)).expect("oneshot::Sender is not dropped before send");
        match res {
            Ok(ret) => Poll::Ready(ret),
            Err(err) => resume_unwind(err),
        }
    }
}
