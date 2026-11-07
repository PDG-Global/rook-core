use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use hyper::body::{Body, Frame};
use pin_project_lite::pin_project;
use tokio::time::{Instant, Sleep};

use self::activity::{ActivityGuard, UploadTracker};
use crate::limit::{ClientUpstreamPermit, UpstreamPermit};

#[path = "activity.rs"]
pub mod activity;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

pin_project! {
    pub struct IdleBody<B> {
        #[pin]
        inner: B,
        #[pin]
        timer: Sleep,
        idle: Duration,
        _upstream_permit: Option<UpstreamPermit>,
        _client_upstream_permit: Option<ClientUpstreamPermit>,
        activity: Option<ActivityGuard>,
        upload_tracker: Option<UploadTracker>,
    }
}

impl<B> IdleBody<B> {
    pub fn new(inner: B, idle: Duration) -> Self {
        Self {
            inner,
            timer: tokio::time::sleep(idle),
            idle,
            _upstream_permit: None,
            _client_upstream_permit: None,
            activity: None,
            upload_tracker: None,
        }
    }

    pub fn with_upstream_permit(mut self, permit: UpstreamPermit) -> Self {
        self._upstream_permit = Some(permit);
        self
    }

    pub fn with_client_upstream_permit(mut self, permit: ClientUpstreamPermit) -> Self {
        self._client_upstream_permit = Some(permit);
        self
    }

    pub fn with_activity(mut self, guard: ActivityGuard) -> Self {
        self.activity = Some(guard);
        self
    }

    pub fn with_upload_tracker(mut self, tracker: UploadTracker) -> Self {
        self.upload_tracker = Some(tracker);
        self
    }
}

impl<B> Body for IdleBody<B>
where
    B: Body,
    B::Error: Into<BoxError>,
{
    type Data = B::Data;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();
        match this.inner.as_mut().poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(activity) = this.activity {
                    activity.touch();
                }
                if let Some(tracker) = this.upload_tracker {
                    tracker.touch();
                    if this.inner.is_end_stream() {
                        tracker.finish();
                    }
                }
                this.timer.reset(Instant::now() + *this.idle);
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                if let Some(tracker) = this.upload_tracker {
                    tracker.finish();
                }
                Poll::Ready(Some(Err(error.into())))
            }
            Poll::Ready(None) => {
                if let Some(tracker) = this.upload_tracker {
                    tracker.finish();
                }
                Poll::Ready(None)
            }
            Poll::Pending => match this.timer.poll(context) {
                Poll::Ready(()) => {
                    if let Some(tracker) = this.upload_tracker {
                        tracker.finish();
                    }
                    Poll::Ready(Some(Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "body idle timeout",
                    )
                    .into())))
                }
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Empty, Full};

    use super::*;

    #[tokio::test]
    async fn ready_frames_touch_activity_and_body_drop_releases_guard() {
        let activity = activity::ConnectionActivity::default();
        let guard = activity.begin();
        let mut body = Box::pin(
            IdleBody::new(
                Full::new(Bytes::from_static(b"data")),
                Duration::from_secs(60),
            )
            .with_activity(guard),
        );

        tokio::time::sleep(Duration::from_millis(20)).await;
        let before_frame = activity.idle_for();
        assert!(before_frame >= Duration::from_millis(20));

        let frame = body.frame().await.unwrap().unwrap();
        assert!(frame.is_data());
        assert!(activity.idle_for() < before_frame);
        assert_eq!(activity.active(), 1);

        assert!(body.frame().await.is_none());
        assert_eq!(activity.active(), 1);
        drop(body);
        assert_eq!(activity.active(), 0);
    }

    #[tokio::test]
    async fn body_end_finishes_upload_tracker() {
        let tracker = UploadTracker::new(false);
        let mut body = Box::pin(
            IdleBody::new(Empty::<Bytes>::new(), Duration::from_secs(60))
                .with_upload_tracker(tracker.clone()),
        );
        let waiter =
            tokio::spawn(async move { tracker.wait_for_timeout(Duration::from_millis(20)).await });

        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!waiter.is_finished());

        assert!(body.frame().await.is_none());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), waiter)
                .await
                .unwrap()
                .unwrap(),
            Err(activity::UploadTimeout)
        );
    }

    #[tokio::test]
    async fn final_frame_finishes_upload_without_end_of_body_poll() {
        let tracker = UploadTracker::new(false);
        let mut body = Box::pin(
            IdleBody::new(
                Full::new(Bytes::from_static(b"data")),
                Duration::from_secs(60),
            )
            .with_upload_tracker(tracker.clone()),
        );
        let idle_waiter = {
            let tracker = tracker.clone();
            tokio::spawn(async move {
                tracker
                    .wait_for_idle_timeout(Duration::from_millis(60))
                    .await
            })
        };
        let completion_waiter =
            tokio::spawn(async move { tracker.wait_for_timeout(Duration::from_millis(20)).await });

        let frame = body.frame().await.unwrap().unwrap();
        assert!(frame.is_data());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), idle_waiter)
                .await
                .unwrap()
                .unwrap(),
            Ok(())
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), completion_waiter)
                .await
                .unwrap()
                .unwrap(),
            Err(activity::UploadTimeout)
        );
    }

    #[tokio::test]
    async fn upload_idle_timeout_does_not_require_body_polls() {
        let tracker = UploadTracker::new(false);
        let _body = Box::pin(
            IdleBody::new(
                Full::new(Bytes::from_static(b"data")),
                Duration::from_secs(60),
            )
            .with_upload_tracker(tracker.clone()),
        );

        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(1),
                tracker.wait_for_idle_timeout(Duration::from_millis(20)),
            )
            .await
            .unwrap(),
            Err(activity::UploadTimeout)
        );
    }
}
