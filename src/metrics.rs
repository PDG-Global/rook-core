//! Operational metrics (plan §8): counters and gauges rendered in
//! Prometheus text format for the loopback-only metrics endpoint.
//!
//! Two invariants keep the registry fixed-memory:
//!
//! - **Labels come only from closed sets.** Listener (`http`/`https`),
//!   response class (`1xx`–`5xx`), strike reason (the enum's static
//!   string), and strike scope (`global` or a site host from the
//!   configuration). Nothing request-derived — no paths, client
//!   addresses, or upstream URLs — ever becomes a label value, so a
//!   client cannot mint new series (the same failure shape as an
//!   unbounded strike vec, in a different map).
//! - **Counters are plain atomics**, so a scrape never allocates per
//!   request; only registering a strike tracker allocates, and that
//!   happens once per site at startup.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::strike::StrikeTracker;

/// The listeners metrics are counted for. The metrics listener itself
/// is deliberately not one: scrapes are operational traffic, not
/// requests, and counting them would let a scraper move the numbers it
/// is reading.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Listener {
    Http,
    Https,
}

const LISTENERS: [(&str, Listener); 2] = [("http", Listener::Http), ("https", Listener::Https)];

impl Listener {
    fn index(self) -> usize {
        match self {
            Self::Http => 0,
            Self::Https => 1,
        }
    }
}

/// The shared registry. Cloning shares the counters.
#[derive(Clone, Default)]
pub struct Metrics {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    connections_accepted: [AtomicU64; 2],
    connections_rejected: [AtomicU64; 2],
    connections_active: [AtomicU64; 2],
    requests: AtomicU64,
    responses_by_class: [AtomicU64; 5],
    tls_handshake_failures: AtomicU64,
    upstream_failures: AtomicU64,
    acme_renewals_ok: AtomicU64,
    acme_renewals_failed: AtomicU64,
    /// Strike trackers to pull counters from at scrape time, labelled
    /// by scope (`global` or a site host). Registered once per tracker
    /// at startup.
    strike_trackers: Mutex<Vec<(String, StrikeTracker)>>,
}

/// Keeps the active-connection gauge balanced with the connection's
/// lifetime.
pub struct ConnectionGauge {
    metrics: Metrics,
    listener: Listener,
}

impl Drop for ConnectionGauge {
    fn drop(&mut self) {
        self.metrics.inner.connections_active[self.listener.index()]
            .fetch_sub(1, Ordering::Relaxed);
    }
}

impl Metrics {
    /// A connection was accepted. The returned gauge holds the active
    /// count until it is dropped.
    pub fn connection_accepted(&self, listener: Listener) -> ConnectionGauge {
        self.inner.connections_accepted[listener.index()].fetch_add(1, Ordering::Relaxed);
        self.inner.connections_active[listener.index()].fetch_add(1, Ordering::Relaxed);
        ConnectionGauge {
            metrics: self.clone(),
            listener,
        }
    }

    /// A connection was refused before service (limit, ban).
    pub fn connection_rejected(&self, listener: Listener) {
        self.inner.connections_rejected[listener.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// A client request entered the proxy.
    pub fn request(&self) {
        self.inner.requests.fetch_add(1, Ordering::Relaxed);
    }

    /// A response went out; counted by status class.
    pub fn response(&self, status: u16) {
        let class = usize::from(status / 100).saturating_sub(1).min(4);
        self.inner.responses_by_class[class].fetch_add(1, Ordering::Relaxed);
    }

    pub fn tls_handshake_failed(&self) {
        self.inner
            .tls_handshake_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    /// An upstream connect/request failed or timed out.
    pub fn upstream_failed(&self) {
        self.inner.upstream_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// An ACME issuance/renewal attempt finished.
    pub fn acme_renewal(&self, success: bool) {
        let counter = if success {
            &self.inner.acme_renewals_ok
        } else {
            &self.inner.acme_renewals_failed
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Pull this tracker's strike/ban counters into every scrape under
    /// `scope` (`global` or a site host from the configuration).
    pub fn register_strikes(&self, scope: String, tracker: StrikeTracker) {
        lock_recover(&self.inner.strike_trackers).push((scope, tracker));
    }

    /// Render every counter and gauge in Prometheus text format.
    /// `tunnels_active` lives in `AppState` (the drain logic owns it),
    /// so it is passed in rather than duplicated here.
    pub fn render(&self, tunnels_active: usize) -> String {
        let mut out = String::with_capacity(2048);
        let inner = &self.inner;

        out.push_str("# HELP rook_connections_accepted_total Connections accepted, by listener.\n");
        out.push_str("# TYPE rook_connections_accepted_total counter\n");
        for (name, listener) in LISTENERS {
            let value = inner.connections_accepted[listener.index()].load(Ordering::Relaxed);
            let _ = writeln!(
                out,
                "rook_connections_accepted_total{{listener=\"{name}\"}} {value}"
            );
        }

        out.push_str("# HELP rook_connections_rejected_total Connections refused before service, by listener.\n");
        out.push_str("# TYPE rook_connections_rejected_total counter\n");
        for (name, listener) in LISTENERS {
            let value = inner.connections_rejected[listener.index()].load(Ordering::Relaxed);
            let _ = writeln!(
                out,
                "rook_connections_rejected_total{{listener=\"{name}\"}} {value}"
            );
        }

        out.push_str("# HELP rook_connections_active Open connections, by listener.\n");
        out.push_str("# TYPE rook_connections_active gauge\n");
        for (name, listener) in LISTENERS {
            let value = inner.connections_active[listener.index()].load(Ordering::Relaxed);
            let _ = writeln!(
                out,
                "rook_connections_active{{listener=\"{name}\"}} {value}"
            );
        }

        let _ = writeln!(
            out,
            "# HELP rook_requests_total Client requests that entered the proxy.\n# TYPE rook_requests_total counter\nrook_requests_total {}",
            inner.requests.load(Ordering::Relaxed)
        );

        out.push_str("# HELP rook_responses_total Responses sent, by status class.\n");
        out.push_str("# TYPE rook_responses_total counter\n");
        for (index, value) in inner.responses_by_class.iter().enumerate() {
            let value = value.load(Ordering::Relaxed);
            let _ = writeln!(
                out,
                "rook_responses_total{{class=\"{}xx\"}} {value}",
                index + 1
            );
        }

        let _ = writeln!(
            out,
            "# HELP rook_tls_handshake_failures_total TLS handshakes that failed or timed out.\n# TYPE rook_tls_handshake_failures_total counter\nrook_tls_handshake_failures_total {}",
            inner.tls_handshake_failures.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "# HELP rook_upstream_failures_total Upstream requests that failed or timed out.\n# TYPE rook_upstream_failures_total counter\nrook_upstream_failures_total {}",
            inner.upstream_failures.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "# HELP rook_acme_renewals_total ACME issuance/renewal attempts, by result.\n# TYPE rook_acme_renewals_total counter\nrook_acme_renewals_total{{result=\"success\"}} {}\nrook_acme_renewals_total{{result=\"failure\"}} {}",
            inner.acme_renewals_ok.load(Ordering::Relaxed),
            inner.acme_renewals_failed.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP rook_tunnels_active Open WebSocket tunnels.\n# TYPE rook_tunnels_active gauge\nrook_tunnels_active {tunnels_active}"
        );

        out.push_str("# HELP rook_strikes_total Strikes recorded, by scope and reason.\n");
        out.push_str("# TYPE rook_strikes_total counter\n");
        out.push_str("# HELP rook_bans_total Bans applied (enforcing mode), by scope.\n");
        out.push_str("# TYPE rook_bans_total counter\n");
        out.push_str(
            "# HELP rook_would_ban_total Bans log-only mode would have applied, by scope.\n",
        );
        out.push_str("# TYPE rook_would_ban_total counter\n");
        out.push_str("# HELP rook_ban_rejected_total Requests a ban rejected, by scope.\n");
        out.push_str("# TYPE rook_ban_rejected_total counter\n");
        let trackers = lock_recover(&inner.strike_trackers);
        let mut snapshots = Vec::with_capacity(trackers.len());
        for (scope, tracker) in trackers.iter() {
            snapshots.push((scope.clone(), tracker.metrics()));
        }
        drop(trackers);
        for (scope, (strikes, bans, would_ban, rejected)) in &snapshots {
            let scope = escape_label(scope);
            for (reason, count) in strikes {
                let _ = writeln!(
                    out,
                    "rook_strikes_total{{scope=\"{scope}\",reason=\"{reason}\"}} {count}"
                );
            }
            let _ = writeln!(out, "rook_bans_total{{scope=\"{scope}\"}} {bans}");
            let _ = writeln!(out, "rook_would_ban_total{{scope=\"{scope}\"}} {would_ban}");
            let _ = writeln!(
                out,
                "rook_ban_rejected_total{{scope=\"{scope}\"}} {rejected}"
            );
        }

        out
    }
}

/// Label values come from configuration, not requests, but escaping is
/// cheap insurance against a config string ever containing a quote.
fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strike::{StrikeRules, StrikeTracker};

    #[test]
    fn counters_render_with_closed_label_sets() {
        let metrics = Metrics::default();
        {
            let _guard = metrics.connection_accepted(Listener::Http);
            let _guard = metrics.connection_accepted(Listener::Http);
            let _guard = metrics.connection_accepted(Listener::Https);
            metrics.connection_rejected(Listener::Https);
            metrics.request();
            metrics.request();
            metrics.response(200);
            metrics.response(404);
            metrics.response(502);
            metrics.tls_handshake_failed();
            metrics.upstream_failed();
            metrics.acme_renewal(true);
            metrics.acme_renewal(false);

            let rendered = metrics.render(3);
            assert!(rendered.contains("rook_connections_accepted_total{listener=\"http\"} 2"));
            assert!(rendered.contains("rook_connections_active{listener=\"http\"} 2"));
            assert!(rendered.contains("rook_connections_active{listener=\"https\"} 1"));
            assert!(rendered.contains("rook_connections_rejected_total{listener=\"https\"} 1"));
            assert!(rendered.contains("rook_requests_total 2"));
            assert!(rendered.contains("rook_responses_total{class=\"2xx\"} 1"));
            assert!(rendered.contains("rook_responses_total{class=\"4xx\"} 1"));
            assert!(rendered.contains("rook_responses_total{class=\"5xx\"} 1"));
            assert!(rendered.contains("rook_tls_handshake_failures_total 1"));
            assert!(rendered.contains("rook_upstream_failures_total 1"));
            assert!(rendered.contains("rook_acme_renewals_total{result=\"success\"} 1"));
            assert!(rendered.contains("rook_acme_renewals_total{result=\"failure\"} 1"));
            assert!(rendered.contains("rook_tunnels_active 3"));
        }
        // Gauges drop with their guards.
        assert!(
            metrics
                .render(0)
                .contains("rook_connections_active{listener=\"http\"} 0")
        );
    }

    #[test]
    fn strike_counters_render_per_scope() {
        let metrics = Metrics::default();
        let tracker = StrikeTracker::new(
            StrikeRules {
                enabled: true,
                log_only: true,
                threshold: 1,
                ..StrikeRules::default()
            },
            8,
            std::time::Duration::from_secs(60),
            Vec::new(),
        );
        metrics.register_strikes("example.com".to_owned(), tracker.clone());
        tracker.strike(
            std::net::IpAddr::from(std::net::Ipv4Addr::new(203, 0, 113, 1)),
            crate::strike::StrikeReason::UnknownHost,
        );
        let rendered = metrics.render(0);
        assert!(
            rendered
                .contains("rook_strikes_total{scope=\"example.com\",reason=\"unknown-host\"} 1")
        );
        assert!(rendered.contains("rook_would_ban_total{scope=\"example.com\"} 1"));
        assert!(rendered.contains("rook_bans_total{scope=\"example.com\"} 0"));
    }

    #[test]
    fn labels_are_escaped() {
        assert_eq!(escape_label("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }
}
