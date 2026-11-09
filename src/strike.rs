//! Bounded, expiring strike and ban rules (plan §6).
//!
//! Rook limits observable abusive behavior; it does not guess intent.
//! A client collects strikes for malformed requests, repeated unknown
//! hosts, failed TLS handshakes (direct connections only — behind
//! Cloudflare a failed handshake cannot be attributed to a visitor) and
//! configured trap paths. Past the threshold the client is banned for a
//! bounded time. (Trap-path and reason wiring into the request path
//! lands with the server integration commit; this module is the tracker.)
//! Failed-handshake strikes apply only to direct connections: behind a
//! trusted proxy a failed handshake cannot be attributed to a visitor.
//!
//! Everything about a rule is safe by default:
//!
//! - Rules start **log-only** per site: strikes and would-be bans are
//!   logged and counted, nothing is rejected, until the operator flips
//!   the site to enforcing.
//! - The tables are fixed-memory: at most `max_tracked` clients, idle
//!   entries expire, and a full table evicts the oldest-idle entry
//!   rather than growing.
//! - Allowlisted clients and the trusted-proxy ranges themselves are
//!   never struck or banned.
//! - Every strike and ban logs its reason; every decision is counted in
//!   metrics.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

use ipnet::IpNet;

use crate::limit::ClientKey;

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What a client did. The reason goes into the log line and metrics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum StrikeReason {
    /// A request that failed framing or header validation.
    MalformedRequest,
    /// A Host/SNI that names no configured site, repeatedly.
    UnknownHost,
    /// A TLS handshake that failed on a direct connection.
    FailedHandshake,
    /// A request to a configured trap path.
    TrapPath,
}

impl StrikeReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MalformedRequest => "malformed-request",
            Self::UnknownHost => "unknown-host",
            Self::FailedHandshake => "failed-handshake",
            Self::TrapPath => "trap-path",
        }
    }
}

/// One site's strike rules.
#[derive(Clone, Debug)]
pub struct StrikeRules {
    /// Whether the tracker acts at all. Carried here, not left to the
    /// call site: a parsed switch that silently does nothing looks wired
    /// for months. A disabled set neither strikes nor bans.
    pub enabled: bool,
    /// Log and count only; nothing is rejected.
    pub log_only: bool,
    /// Strikes within `window` that trigger a ban.
    pub threshold: u32,
    /// How long strikes live.
    pub window: Duration,
    /// How long a ban lasts.
    pub ban_for: Duration,
    /// Paths that strike on contact (exact match after normalization).
    pub trap_paths: Vec<String>,
}

impl Default for StrikeRules {
    fn default() -> Self {
        Self {
            enabled: true,
            log_only: true,
            threshold: 10,
            window: Duration::from_secs(600),
            ban_for: Duration::from_secs(3600),
            trap_paths: Vec::new(),
        }
    }
}

struct ClientStrikes {
    /// When each live strike was taken.
    strikes: Vec<(Instant, StrikeReason)>,
    banned_until: Option<Instant>,
    last_seen: Instant,
}

#[derive(Default)]
struct State {
    clients: HashMap<ClientKey, ClientStrikes>,
}

/// Counters for the metrics endpoint.
#[derive(Default)]
pub struct StrikeMetrics {
    /// Strikes recorded, by reason.
    pub strikes: HashMap<&'static str, u64>,
    /// Bans applied (enforcing mode).
    pub bans: u64,
    /// Bans that log-only mode would have applied.
    pub would_ban: u64,
    /// Requests a ban rejected.
    pub rejected: u64,
}

/// The per-site strike tracker. Cloning shares the state.
#[derive(Clone)]
pub struct StrikeTracker {
    inner: Arc<Inner>,
}

struct Inner {
    rules: StrikeRules,
    max_tracked: usize,
    idle_expiry: Duration,
    /// Never struck, never banned. The caller builds this from the
    /// operator allowlist **plus the trusted-proxy ranges** — a proxy in
    /// front of a site must never ban itself and take the site down.
    exempt: Vec<IpNet>,
    state: Mutex<State>,
    metrics: Mutex<StrikeMetrics>,
}

/// What a strike did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StrikeOutcome {
    /// Recorded; below the threshold.
    Noted,
    /// The threshold was crossed, but the site is log-only: logged and
    /// counted, nothing rejected.
    WouldBan,
    /// The threshold was crossed; the client is banned until the time
    /// the rules say.
    Banned,
}

impl From<&crate::config::StrikeRulesConfig> for StrikeRules {
    fn from(c: &crate::config::StrikeRulesConfig) -> Self {
        Self {
            enabled: c.enabled,
            log_only: c.log_only,
            threshold: c.threshold,
            window: Duration::from_secs(c.window_secs),
            ban_for: Duration::from_secs(c.ban_secs),
            trap_paths: c.trap_paths.clone(),
        }
    }
}

impl StrikeTracker {
    pub fn new(
        rules: StrikeRules,
        max_tracked: usize,
        idle_expiry: Duration,
        exempt: Vec<IpNet>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                rules,
                max_tracked,
                idle_expiry,
                exempt,
                state: Mutex::new(State::default()),
                metrics: Mutex::new(StrikeMetrics::default()),
            }),
        }
    }

    fn is_exempt(&self, ip: &IpAddr) -> bool {
        self.inner.exempt.iter().any(|n| n.contains(ip))
    }

    /// Is this client currently banned? Call on connection accept and on
    /// each request; a banned client's request is dropped with the ban
    /// logged and counted.
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        if !self.inner.rules.enabled || self.is_exempt(&ip) {
            return false;
        }
        let now = Instant::now();
        let mut st = lock_recover(&self.inner.state);
        let Some(c) = st.clients.get_mut(&ClientKey::from(ip)) else {
            return false;
        };
        match c.banned_until {
            Some(until) if until > now => {
                c.last_seen = now;
                lock_recover(&self.inner.metrics).rejected += 1;
                true
            }
            Some(_) => {
                // Ban expired: the client starts clean.
                c.banned_until = None;
                c.strikes.clear();
                c.last_seen = now;
                false
            }
            None => false,
        }
    }

    /// Records a strike. Returns what it did.
    pub fn strike(&self, ip: IpAddr, reason: StrikeReason) -> StrikeOutcome {
        if !self.inner.rules.enabled || self.is_exempt(&ip) {
            return StrikeOutcome::Noted;
        }
        *lock_recover(&self.inner.metrics)
            .strikes
            .entry(reason.as_str())
            .or_insert(0) += 1;
        let now = Instant::now();
        let rules = &self.inner.rules;
        let mut st = lock_recover(&self.inner.state);
        // Per-client expiry happens on access below; a whole-map sweep
        // runs only when a new client meets a full table, so a hot path
        // the attacker controls stays O(1) per strike.
        let key = ClientKey::from(ip);
        if !st.clients.contains_key(&key) && st.clients.len() >= self.inner.max_tracked {
            st.clients.retain(|_, c| {
                now.duration_since(c.last_seen) < self.inner.idle_expiry
                    || c.banned_until.is_some_and(|u| u > now)
            });
        }
        if !st.clients.contains_key(&key) && st.clients.len() >= self.inner.max_tracked {
            if let Some(oldest) = st
                .clients
                .iter()
                .filter(|(_, c)| c.banned_until.is_none_or(|u| u <= now))
                .min_by_key(|(_, c)| c.last_seen)
                .map(|(k, _)| *k)
            {
                st.clients.remove(&oldest);
            } else {
                // Everyone tracked is banned; drop the strike.
                return StrikeOutcome::Noted;
            }
        }
        let c = st.clients.entry(key).or_insert_with(|| ClientStrikes {
            strikes: Vec::new(),
            banned_until: None,
            last_seen: now,
        });
        c.last_seen = now;
        if c.banned_until.is_some_and(|u| u > now) {
            return StrikeOutcome::Banned; // already banned; keep counting
        }
        c.strikes
            .retain(|(at, _)| now.duration_since(*at) < rules.window);
        // Only the count matters, so the vec never grows past the
        // threshold: in log-only mode nothing else bounds it, and an
        // attacker must not turn the defence into memory exhaustion.
        if c.strikes.len() < rules.threshold as usize {
            c.strikes.push((now, reason));
        }
        if (c.strikes.len() as u32) < rules.threshold {
            return StrikeOutcome::Noted;
        }
        if rules.log_only {
            lock_recover(&self.inner.metrics).would_ban += 1;
            return StrikeOutcome::WouldBan;
        }
        c.banned_until = Some(now + rules.ban_for);
        c.strikes.clear();
        lock_recover(&self.inner.metrics).bans += 1;
        StrikeOutcome::Banned
    }

    /// A snapshot of the counters, for the metrics endpoint.
    pub fn metrics(&self) -> (HashMap<&'static str, u64>, u64, u64, u64) {
        let m = lock_recover(&self.inner.metrics);
        (m.strikes.clone(), m.bans, m.would_ban, m.rejected)
    }
}

#[cfg(test)]
mod tests {
    //! The integration tests cannot see the per-client strike vec, so the
    //! cap's pin lives here: delete the guard and this test fails.

    use super::*;

    #[test]
    fn the_strike_vec_stops_at_the_threshold() {
        let t = StrikeTracker::new(
            StrikeRules {
                enabled: true,
                log_only: true,
                threshold: 3,
                ..StrikeRules::default()
            },
            8,
            Duration::from_secs(60),
            Vec::new(),
        );
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        for _ in 0..10_000 {
            t.strike(ip, StrikeReason::MalformedRequest);
        }
        let st = lock_recover(&t.inner.state);
        let c = st.clients.get(&ClientKey::from(ip)).expect("tracked");
        assert_eq!(c.strikes.len(), 3);
    }
}
