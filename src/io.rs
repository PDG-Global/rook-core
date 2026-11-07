use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use hyper::rt::{Read, ReadBufCursor, Write};
use pin_project_lite::pin_project;
use tokio::time::{Instant, Sleep};

pin_project! {
    pub struct WriteTimeoutIo<T> {
        #[pin]
        inner: T,
        #[pin]
        timer: Sleep,
        idle: Duration,
        write_blocked: bool,
    }
}

impl<T> WriteTimeoutIo<T> {
    pub fn new(inner: T, idle: Duration) -> Self {
        Self {
            inner,
            timer: tokio::time::sleep(idle),
            idle,
            write_blocked: false,
        }
    }
}

impl<T: Read> Read for WriteTimeoutIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_read(context, buffer)
    }
}

impl<T: Write> Write for WriteTimeoutIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let mut this = self.project();
        match this.inner.poll_write(context, buffer) {
            Poll::Ready(Ok(written)) => {
                if written > 0 {
                    this.timer.reset(Instant::now() + *this.idle);
                    *this.write_blocked = false;
                }
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => match poll_blocked_timer(
                this.timer.as_mut(),
                *this.idle,
                this.write_blocked,
                context,
            ) {
                Poll::Ready(()) => Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "connection write idle timeout",
                ))),
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let mut this = self.project();
        match this.inner.poll_flush(context) {
            Poll::Ready(Ok(())) => {
                this.timer.reset(Instant::now() + *this.idle);
                *this.write_blocked = false;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => match poll_blocked_timer(
                this.timer.as_mut(),
                *this.idle,
                this.write_blocked,
                context,
            ) {
                Poll::Ready(()) => Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "connection flush idle timeout",
                ))),
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_shutdown(context)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        let mut this = self.project();
        match this.inner.poll_write_vectored(context, buffers) {
            Poll::Ready(Ok(written)) => {
                if written > 0 {
                    this.timer.reset(Instant::now() + *this.idle);
                    *this.write_blocked = false;
                }
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => match poll_blocked_timer(
                this.timer.as_mut(),
                *this.idle,
                this.write_blocked,
                context,
            ) {
                Poll::Ready(()) => Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "connection vectored write idle timeout",
                ))),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

fn poll_blocked_timer(
    mut timer: Pin<&mut Sleep>,
    idle: Duration,
    blocked: &mut bool,
    context: &mut Context<'_>,
) -> Poll<()> {
    if !*blocked {
        *blocked = true;
        timer.as_mut().reset(Instant::now() + idle);
    }
    timer.poll(context)
}
