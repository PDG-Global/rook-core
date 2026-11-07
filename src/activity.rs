use std::{
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use tokio::{sync::watch, time::Instant};

#[derive(Clone, Debug, Default)]
pub struct ConnectionActivity {
    inner: Arc<ActivityInner>,
}

#[derive(Debug)]
struct ActivityInner {
    active: AtomicUsize,
    waiting: AtomicUsize,
    last_activity: Mutex<Instant>,
}

impl Default for ActivityInner {
    fn default() -> Self {
        Self {
            active: AtomicUsize::new(0),
            waiting: AtomicUsize::new(0),
            last_activity: Mutex::new(Instant::now()),
        }
    }
}

#[derive(Debug)]
pub struct ActivityGuard {
    activity: ConnectionActivity,
}

#[derive(Debug)]
pub struct UpstreamWaitGuard {
    activity: ConnectionActivity,
}

impl ConnectionActivity {
    pub fn begin(&self) -> ActivityGuard {
        self.inner.active.fetch_add(1, Ordering::Relaxed);
        self.touch();
        ActivityGuard {
            activity: self.clone(),
        }
    }

    pub fn begin_upstream_wait(&self) -> UpstreamWaitGuard {
        self.inner.waiting.fetch_add(1, Ordering::Relaxed);
        self.touch();
        UpstreamWaitGuard {
            activity: self.clone(),
        }
    }

    pub fn touch(&self) {
        *lock_recover(&self.inner.last_activity) = Instant::now();
    }

    pub fn idle_for(&self) -> Duration {
        Instant::now().saturating_duration_since(*lock_recover(&self.inner.last_activity))
    }

    pub fn active(&self) -> usize {
        self.inner.active.load(Ordering::Relaxed)
    }
}

impl ActivityGuard {
    pub(crate) fn touch(&self) {
        self.activity.touch();
    }
}

impl Drop for ActivityGuard {
    fn drop(&mut self) {
        self.activity.inner.active.fetch_sub(1, Ordering::Relaxed);
        self.activity.touch();
    }
}

impl Drop for UpstreamWaitGuard {
    fn drop(&mut self) {
        self.activity.inner.waiting.fetch_sub(1, Ordering::Relaxed);
        self.activity.touch();
    }
}

pub async fn wait_for_idle_timeout(activity: &ConnectionActivity, duration: Duration) {
    loop {
        let idle_for = activity.idle_for();
        if activity.inner.waiting.load(Ordering::Relaxed) == 0 && idle_for >= duration {
            return;
        }
        tokio::time::sleep(
            duration
                .saturating_sub(idle_for)
                .max(Duration::from_millis(1)),
        )
        .await;
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct UploadTimeout;

#[derive(Clone, Debug)]
pub struct UploadTracker {
    inner: Arc<UploadInner>,
}

#[derive(Debug)]
struct UploadInner {
    state: Mutex<UploadState>,
    completed: watch::Sender<()>,
}

#[derive(Debug)]
struct UploadState {
    finished_at: Option<Instant>,
    last_progress: Instant,
}

impl UploadTracker {
    pub fn new(finished: bool) -> Self {
        let (completed, _) = watch::channel(());
        let now = Instant::now();
        Self {
            inner: Arc::new(UploadInner {
                state: Mutex::new(UploadState {
                    finished_at: finished.then_some(now),
                    last_progress: now,
                }),
                completed,
            }),
        }
    }

    pub fn finish(&self) {
        let mut state = lock_recover(&self.inner.state);
        if state.finished_at.is_some() {
            return;
        }
        state.finished_at = Some(Instant::now());
        drop(state);
        self.inner.completed.send_replace(());
    }

    pub(crate) fn touch(&self) {
        lock_recover(&self.inner.state).last_progress = Instant::now();
    }

    pub async fn wait_for_timeout(&self, duration: Duration) -> Result<(), UploadTimeout> {
        let mut completed = self.inner.completed.subscribe();
        let finished_at = loop {
            if let Some(finished_at) = lock_recover(&self.inner.state).finished_at {
                break finished_at;
            }
            completed.changed().await.unwrap();
        };
        tokio::time::sleep_until(finished_at + duration).await;
        Err(UploadTimeout)
    }

    pub async fn wait_for_idle_timeout(&self, duration: Duration) -> Result<(), UploadTimeout> {
        let mut completed = self.inner.completed.subscribe();
        loop {
            let remaining = {
                let state = lock_recover(&self.inner.state);
                if state.finished_at.is_some() {
                    return Ok(());
                }
                let idle_for = Instant::now().saturating_duration_since(state.last_progress);
                if idle_for >= duration {
                    return Err(UploadTimeout);
                }
                duration - idle_for
            };

            tokio::select! {
                () = tokio::time::sleep(remaining) => {}
                result = completed.changed() => result.unwrap(),
            }
        }
    }
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_count_tracks_guards_and_clones_share_state() {
        let activity = ConnectionActivity::default();
        let clone = activity.clone();
        assert_eq!(activity.active(), 0);

        let first = activity.begin();
        let second = clone.begin();
        assert_eq!(activity.active(), 2);
        assert_eq!(clone.active(), 2);

        drop(first);
        assert_eq!(activity.active(), 1);
        drop(second);
        assert_eq!(clone.active(), 0);
    }

    #[tokio::test]
    async fn touch_records_progress_and_guard_drop_releases_and_touches() {
        let activity = ConnectionActivity::default();
        let guard = activity.begin();

        tokio::time::sleep(Duration::from_millis(20)).await;
        let before_touch = activity.idle_for();
        assert!(before_touch >= Duration::from_millis(20));
        activity.touch();
        assert!(activity.idle_for() < before_touch);

        tokio::time::sleep(Duration::from_millis(10)).await;
        let before_drop = activity.idle_for();
        drop(guard);
        assert_eq!(activity.active(), 0);
        assert!(activity.idle_for() < before_drop);
    }

    #[tokio::test]
    async fn idle_wait_returns_for_silent_connection() {
        let activity = ConnectionActivity::default();
        let waiter = {
            let activity = activity.clone();
            tokio::spawn(async move {
                wait_for_idle_timeout(&activity, Duration::from_millis(40)).await;
            })
        };

        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished());

        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn idle_wait_restarts_after_progress_with_stalled_request_active() {
        let activity = ConnectionActivity::default();
        let _guard = activity.begin();
        let waiter = {
            let activity = activity.clone();
            tokio::spawn(async move {
                wait_for_idle_timeout(&activity, Duration::from_millis(60)).await;
            })
        };

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(30)).await;
        activity.touch();
        tokio::time::advance(Duration::from_millis(30)).await;
        assert!(!waiter.is_finished());

        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn upstream_waits_suppress_idle_timeout_until_all_guards_drop() {
        let activity = ConnectionActivity::default();
        let first = activity.begin_upstream_wait();
        let second = activity.begin_upstream_wait();
        let waiter = {
            let activity = activity.clone();
            tokio::spawn(async move {
                wait_for_idle_timeout(&activity, Duration::from_millis(40)).await;
            })
        };

        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(!waiter.is_finished());

        drop(first);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished());

        drop(second);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished());
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn upload_timeout_starts_when_shared_tracker_finishes() {
        let tracker = UploadTracker::new(false);
        let waiter = {
            let tracker = tracker.clone();
            tokio::spawn(async move { tracker.wait_for_timeout(Duration::from_millis(40)).await })
        };

        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(!waiter.is_finished());

        tracker.finish();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), waiter)
                .await
                .unwrap()
                .unwrap(),
            Err(UploadTimeout)
        );

        let finished = UploadTracker::new(true);
        assert_eq!(
            finished.wait_for_timeout(Duration::from_millis(10)).await,
            Err(UploadTimeout)
        );
    }
}
