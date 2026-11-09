use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

const IDLE_RATE_ENTRY_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum ClientKey {
    Ipv4(std::net::Ipv4Addr),
    Ipv6Network(Ipv6Addr),
}

impl From<IpAddr> for ClientKey {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => Self::Ipv4(ip),
            IpAddr::V6(ip) => {
                let network = ip.to_bits() & (u128::MAX << 64);
                Self::Ipv6Network(Ipv6Addr::from(network))
            }
        }
    }
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

pub struct ConnectionLimiter {
    inner: Arc<ConnectionInner>,
}

struct ConnectionInner {
    max_connections: usize,
    max_connections_per_ip: usize,
    max_tracked_clients: usize,
    state: Mutex<ConnectionState>,
}

#[derive(Default)]
struct ConnectionState {
    active: usize,
    clients: HashMap<ClientKey, usize>,
}

pub struct ConnectionPermit {
    inner: Arc<ConnectionInner>,
    client: ClientKey,
}

impl ConnectionLimiter {
    pub fn new(
        max_connections: usize,
        max_connections_per_ip: usize,
        max_tracked_clients: usize,
    ) -> Self {
        Self {
            inner: Arc::new(ConnectionInner {
                max_connections,
                max_connections_per_ip,
                max_tracked_clients,
                state: Mutex::new(ConnectionState::default()),
            }),
        }
    }

    pub fn acquire(&self, ip: IpAddr) -> Option<ConnectionPermit> {
        let client = ClientKey::from(ip);
        let mut state = lock_recover(&self.inner.state);

        if state.active >= self.inner.max_connections {
            return None;
        }

        match state.clients.get(&client) {
            Some(&count) if count >= self.inner.max_connections_per_ip => return None,
            Some(_) => {}
            None if state.clients.len() >= self.inner.max_tracked_clients => return None,
            None => {}
        }

        *state.clients.entry(client).or_insert(0) += 1;
        state.active += 1;

        Some(ConnectionPermit {
            inner: Arc::clone(&self.inner),
            client,
        })
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        let mut state = lock_recover(&self.inner.state);
        state.active -= 1;

        let remove = match state.clients.get_mut(&self.client) {
            Some(count) => {
                *count -= 1;
                *count == 0
            }
            None => false,
        };
        if remove {
            state.clients.remove(&self.client);
        }
    }
}

pub struct UpstreamLimiter {
    inner: Arc<UpstreamInner>,
}

struct UpstreamInner {
    max_per_upstream: usize,
    max_tracked_upstreams: usize,
    active: Mutex<HashMap<(usize, usize), usize>>,
}

pub struct UpstreamPermit {
    inner: Arc<UpstreamInner>,
    upstream: (usize, usize),
}

impl UpstreamLimiter {
    pub fn new(max_per_upstream: usize, max_tracked_upstreams: usize) -> Self {
        Self {
            inner: Arc::new(UpstreamInner {
                max_per_upstream,
                max_tracked_upstreams,
                active: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn acquire(&self, route_id: usize, upstream_index: usize) -> Option<UpstreamPermit> {
        let upstream = (route_id, upstream_index);
        let mut active = lock_recover(&self.inner.active);

        match active.get(&upstream) {
            Some(&count) if count >= self.inner.max_per_upstream => return None,
            Some(_) => {}
            None if active.len() >= self.inner.max_tracked_upstreams => return None,
            None => {}
        }

        *active.entry(upstream).or_insert(0) += 1;
        Some(UpstreamPermit {
            inner: Arc::clone(&self.inner),
            upstream,
        })
    }
}

impl Drop for UpstreamPermit {
    fn drop(&mut self) {
        let mut active = lock_recover(&self.inner.active);
        let remove = match active.get_mut(&self.upstream) {
            Some(count) => {
                *count -= 1;
                *count == 0
            }
            None => false,
        };
        if remove {
            active.remove(&self.upstream);
        }
    }
}

pub struct ClientUpstreamLimiter {
    inner: Arc<ClientUpstreamInner>,
}

struct ClientUpstreamInner {
    max_per_client: usize,
    max_tracked: usize,
    active: Mutex<HashMap<ClientKey, usize>>,
}

pub struct ClientUpstreamPermit {
    inner: Arc<ClientUpstreamInner>,
    client: ClientKey,
}

impl ClientUpstreamLimiter {
    pub fn new(max_per_client: usize, max_tracked: usize) -> Self {
        Self {
            inner: Arc::new(ClientUpstreamInner {
                max_per_client,
                max_tracked,
                active: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn acquire(
        &self,
        ip: IpAddr,
        _route_id: usize,
        _upstream_index: usize,
    ) -> Option<ClientUpstreamPermit> {
        let client = ClientKey::from(ip.to_canonical());
        let mut active = lock_recover(&self.inner.active);

        match active.get(&client) {
            Some(&count) if count >= self.inner.max_per_client => return None,
            Some(_) => {}
            None if active.len() >= self.inner.max_tracked => return None,
            None => {}
        }

        *active.entry(client).or_insert(0) += 1;
        Some(ClientUpstreamPermit {
            inner: Arc::clone(&self.inner),
            client,
        })
    }
}

impl Drop for ClientUpstreamPermit {
    fn drop(&mut self) {
        let mut active = lock_recover(&self.inner.active);
        let remove = match active.get_mut(&self.client) {
            Some(count) => {
                *count -= 1;
                *count == 0
            }
            None => false,
        };
        if remove {
            active.remove(&self.client);
        }
    }
}

pub struct RateLimiter {
    max_entries: usize,
    state: Mutex<RateState>,
}

struct RateState {
    buckets: HashMap<(ClientKey, usize), TokenBucket>,
    last_cleanup: Instant,
}

impl RateState {
    fn cleanup(&mut self, now: Instant) {
        self.buckets.retain(|_, bucket| {
            now.saturating_duration_since(bucket.last_used) < IDLE_RATE_ENTRY_TIMEOUT
        });
        self.last_cleanup = now;
    }
}

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    last_used: Instant,
}

impl RateLimiter {
    pub fn new(max_entries: usize) -> Self {
        Self {
            max_entries,
            state: Mutex::new(RateState {
                buckets: HashMap::new(),
                last_cleanup: Instant::now(),
            }),
        }
    }

    pub fn check(&self, ip: IpAddr, route_id: usize, requests_per_second: u32, burst: u32) -> bool {
        let key = (ClientKey::from(ip), route_id);
        let now = Instant::now();
        let mut state = lock_recover(&self.state);

        if now.saturating_duration_since(state.last_cleanup) >= IDLE_RATE_ENTRY_TIMEOUT {
            state.cleanup(now);
        }

        if let Some(bucket) = state.buckets.get_mut(&key) {
            let elapsed = now.saturating_duration_since(bucket.last_refill);
            bucket.tokens = (bucket.tokens
                + elapsed.as_secs_f64() * f64::from(requests_per_second))
            .min(f64::from(burst));
            bucket.last_refill = now;
            bucket.last_used = now;

            if bucket.tokens >= 1.0 {
                bucket.tokens -= 1.0;
                return true;
            }
            return false;
        }

        if state.buckets.len() >= self.max_entries {
            state.cleanup(now);
        }
        if state.buckets.len() >= self.max_entries
            && let Some(&oldest_key) = state
                .buckets
                .iter()
                .min_by_key(|(_, bucket)| bucket.last_used)
                .map(|(key, _)| key)
        {
            state.buckets.remove(&oldest_key);
        }

        state.buckets.insert(
            key,
            TokenBucket {
                tokens: f64::from(burst) - 1.0,
                last_refill: now,
                last_used: now,
            },
        );
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn connection_limits_and_raii_release() {
        let limiter = ConnectionLimiter::new(2, 1, 4);
        let first_ip = ip("192.0.2.1");
        let second_ip = ip("192.0.2.2");

        let first = limiter.acquire(first_ip).unwrap();
        assert_eq!(limiter.inner.state.lock().unwrap().active, 1);
        assert!(limiter.acquire(first_ip).is_none());

        let second = limiter.acquire(second_ip).unwrap();
        assert_eq!(limiter.inner.state.lock().unwrap().active, 2);
        assert!(limiter.acquire(ip("192.0.2.3")).is_none());

        drop(first);
        {
            let state = limiter.inner.state.lock().unwrap();
            assert_eq!(state.active, 1);
            assert!(!state.clients.contains_key(&ClientKey::from(first_ip)));
        }

        let replacement = limiter.acquire(first_ip).unwrap();
        assert_eq!(limiter.inner.state.lock().unwrap().active, 2);
        drop(second);
        drop(replacement);

        let state = limiter.inner.state.lock().unwrap();
        assert_eq!(state.active, 0);
        assert!(state.clients.is_empty());
    }

    #[test]
    fn connection_table_rejects_new_clients_when_full() {
        let limiter = ConnectionLimiter::new(10, 10, 2);
        let first_ip = ip("192.0.2.1");
        let second_ip = ip("192.0.2.2");
        let third_ip = ip("192.0.2.3");

        let first = limiter.acquire(first_ip).unwrap();
        let second = limiter.acquire(second_ip).unwrap();
        assert!(limiter.acquire(third_ip).is_none());
        assert!(limiter.acquire(first_ip).is_some());

        drop(first);
        assert!(limiter.acquire(third_ip).is_some());
        drop(second);
    }

    #[test]
    fn ipv6_connections_are_aggregated_by_network() {
        let limiter = ConnectionLimiter::new(10, 1, 4);
        let first = limiter.acquire(ip("2001:db8:1:2::1")).unwrap();

        assert!(limiter.acquire(ip("2001:db8:1:2:ffff::2")).is_none());
        assert!(limiter.acquire(ip("2001:db8:1:3::1")).is_some());
        drop(first);
    }

    #[test]
    fn rate_limit_enforces_burst_and_refills() {
        let limiter = RateLimiter::new(4);
        let client = ip("192.0.2.1");
        let key = (ClientKey::from(client), 7);

        assert!(limiter.check(client, 7, 1, 2));
        assert!(limiter.check(client, 7, 1, 2));
        assert!(!limiter.check(client, 7, 1, 2));

        lock_recover(&limiter.state)
            .buckets
            .get_mut(&key)
            .unwrap()
            .last_refill -= Duration::from_secs(1);
        assert!(limiter.check(client, 7, 1, 2));
        assert!(!limiter.check(client, 7, 1, 2));
    }

    #[test]
    fn rate_limits_are_separate_per_route() {
        let limiter = RateLimiter::new(4);
        let client = ip("192.0.2.1");

        assert!(limiter.check(client, 1, 1, 1));
        assert!(!limiter.check(client, 1, 1, 1));
        assert!(limiter.check(client, 2, 1, 1));
        assert!(!limiter.check(client, 2, 1, 1));
    }

    #[test]
    fn ipv6_rate_limits_are_aggregated_by_network() {
        let limiter = RateLimiter::new(4);

        assert!(limiter.check(ip("2001:db8:1:2::1"), 1, 1, 1));
        assert!(!limiter.check(ip("2001:db8:1:2:ffff::2"), 1, 1, 1));
        assert!(limiter.check(ip("2001:db8:1:3::1"), 1, 1, 1));
    }

    #[test]
    fn rate_table_expires_and_evicts_old_entries() {
        let limiter = RateLimiter::new(2);
        let first_ip = ip("192.0.2.1");
        let second_ip = ip("192.0.2.2");
        let first = (ClientKey::from(first_ip), 1);
        let second = (ClientKey::from(second_ip), 1);
        let third_ip = ip("192.0.2.3");

        assert!(limiter.check(first_ip, 1, 1, 1));
        assert!(limiter.check(second_ip, 1, 1, 1));
        lock_recover(&limiter.state)
            .buckets
            .get_mut(&first)
            .unwrap()
            .last_used -= IDLE_RATE_ENTRY_TIMEOUT;

        assert!(limiter.check(third_ip, 1, 1, 1));
        let mut state = lock_recover(&limiter.state);
        assert!(!state.buckets.contains_key(&first));
        assert_eq!(state.buckets.len(), 2);
        state.buckets.get_mut(&second).unwrap().last_used -= Duration::from_secs(1);
        state
            .buckets
            .get_mut(&(ClientKey::from(third_ip), 1))
            .unwrap()
            .last_used -= Duration::from_secs(2);
        drop(state);

        assert!(limiter.check(ip("192.0.2.4"), 1, 1, 1));
        let state = lock_recover(&limiter.state);
        assert_eq!(state.buckets.len(), 2);
        assert!(!state.buckets.contains_key(&(ClientKey::from(third_ip), 1)));
        assert!(state.buckets.contains_key(&second));
    }

    #[test]
    fn rate_cleanup_is_periodic_when_below_capacity() {
        let limiter = RateLimiter::new(4);
        let first_ip = ip("192.0.2.1");
        let first = (ClientKey::from(first_ip), 1);

        assert!(limiter.check(first_ip, 1, 1, 1));
        lock_recover(&limiter.state)
            .buckets
            .get_mut(&first)
            .unwrap()
            .last_used -= IDLE_RATE_ENTRY_TIMEOUT;

        assert!(limiter.check(ip("192.0.2.2"), 1, 1, 1));
        assert!(lock_recover(&limiter.state).buckets.contains_key(&first));

        lock_recover(&limiter.state).last_cleanup -= IDLE_RATE_ENTRY_TIMEOUT;
        assert!(limiter.check(ip("192.0.2.3"), 1, 1, 1));
        let state = lock_recover(&limiter.state);
        assert!(!state.buckets.contains_key(&first));
        assert_eq!(state.buckets.len(), 2);
    }

    #[test]
    fn upstream_permit_releases_and_removes_zero_count_entry() {
        let limiter = UpstreamLimiter::new(1, 2);
        let permit = limiter.acquire(3, 4).unwrap();

        assert!(limiter.acquire(3, 4).is_none());
        assert_eq!(lock_recover(&limiter.inner.active).len(), 1);
        drop(permit);
        assert!(lock_recover(&limiter.inner.active).is_empty());
        assert!(limiter.acquire(3, 4).is_some());
    }

    #[test]
    fn upstream_limits_are_independent_per_route_and_index() {
        let limiter = UpstreamLimiter::new(1, 4);
        let _first = limiter.acquire(1, 0).unwrap();
        let _second = limiter.acquire(1, 1).unwrap();
        let _third = limiter.acquire(2, 0).unwrap();

        assert!(limiter.acquire(1, 0).is_none());
        assert!(limiter.acquire(1, 1).is_none());
        assert!(limiter.acquire(2, 0).is_none());
    }

    #[test]
    fn upstream_table_rejects_new_keys_when_full() {
        let limiter = UpstreamLimiter::new(10, 2);
        let first = limiter.acquire(1, 0).unwrap();
        let _second = limiter.acquire(2, 0).unwrap();

        assert!(limiter.acquire(3, 0).is_none());
        assert!(limiter.acquire(1, 0).is_some());
        drop(first);
        let _third = limiter.acquire(3, 0).unwrap();
        assert_eq!(lock_recover(&limiter.inner.active).len(), 2);
    }

    #[test]
    fn client_upstream_permit_releases_and_removes_zero_count_entry() {
        let limiter = ClientUpstreamLimiter::new(1, 2);
        let client = ip("192.0.2.1");
        let permit = limiter.acquire(client, 3, 4).unwrap();

        assert!(limiter.acquire(client, 3, 4).is_none());
        assert_eq!(lock_recover(&limiter.inner.active).len(), 1);
        drop(permit);
        assert!(lock_recover(&limiter.inner.active).is_empty());
        assert!(limiter.acquire(client, 3, 4).is_some());
    }

    #[test]
    fn client_upstream_limit_is_total_per_client() {
        let limiter = ClientUpstreamLimiter::new(1, 4);
        let first_client = ip("192.0.2.1");
        let second_client = ip("192.0.2.2");
        let _first = limiter.acquire(first_client, 1, 0).unwrap();
        let _second = limiter.acquire(second_client, 1, 0).unwrap();

        assert!(limiter.acquire(first_client, 1, 1).is_none());
        assert!(limiter.acquire(first_client, 2, 0).is_none());
        assert!(limiter.acquire(second_client, 1, 1).is_none());
        assert!(limiter.acquire(second_client, 2, 0).is_none());
    }

    #[test]
    fn client_upstream_table_rejects_new_keys_when_full() {
        let limiter = ClientUpstreamLimiter::new(10, 2);
        let first = limiter.acquire(ip("192.0.2.1"), 1, 0).unwrap();
        let _second = limiter.acquire(ip("192.0.2.2"), 1, 0).unwrap();

        assert!(limiter.acquire(ip("192.0.2.3"), 1, 0).is_none());
        assert!(limiter.acquire(ip("192.0.2.1"), 1, 0).is_some());
        drop(first);
        let _third = limiter.acquire(ip("192.0.2.3"), 1, 0).unwrap();
        assert_eq!(lock_recover(&limiter.inner.active).len(), 2);
    }

    #[test]
    fn client_upstream_mapped_ipv6_shares_ipv4_limit() {
        let limiter = ClientUpstreamLimiter::new(1, 2);
        let mapped = limiter.acquire(ip("::ffff:192.0.2.1"), 1, 0).unwrap();

        assert!(limiter.acquire(ip("192.0.2.1"), 1, 0).is_none());
        drop(mapped);
        assert!(limiter.acquire(ip("192.0.2.1"), 1, 0).is_some());
    }
}
