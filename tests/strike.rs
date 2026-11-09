//! Strike/ban rules (plan §6): log-only first, bounded bans, expiring
//! strikes, fixed-memory tables, exempt allowlists.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use rookd::strike::{StrikeOutcome, StrikeReason, StrikeRules, StrikeTracker};

fn ip(n: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(203, 0, 113, n))
}

fn tracker(rules: StrikeRules) -> StrikeTracker {
    StrikeTracker::new(rules, 8, Duration::from_secs(60), Vec::new())
}

#[test]
fn log_only_counts_but_never_bans() {
    let t = tracker(StrikeRules {
        log_only: true,
        threshold: 2,
        ..StrikeRules::default()
    });
    assert_eq!(
        t.strike(ip(1), StrikeReason::MalformedRequest),
        StrikeOutcome::Noted
    );
    assert_eq!(
        t.strike(ip(1), StrikeReason::MalformedRequest),
        StrikeOutcome::WouldBan
    );
    assert!(!t.is_banned(ip(1)));
    let (strikes, bans, would_ban, _) = t.metrics();
    assert_eq!(strikes.get("malformed-request"), Some(&2));
    assert_eq!(bans, 0);
    assert_eq!(would_ban, 1);
}

#[test]
fn enforcing_bans_at_the_threshold_and_the_ban_expires() {
    let t = tracker(StrikeRules {
        enabled: true,
        log_only: false,
        threshold: 3,
        window: Duration::from_secs(600),
        ban_for: Duration::from_millis(120),
        trap_paths: Vec::new(),
    });
    assert_eq!(
        t.strike(ip(1), StrikeReason::UnknownHost),
        StrikeOutcome::Noted
    );
    assert_eq!(
        t.strike(ip(1), StrikeReason::UnknownHost),
        StrikeOutcome::Noted
    );
    assert_eq!(
        t.strike(ip(1), StrikeReason::UnknownHost),
        StrikeOutcome::Banned
    );
    assert!(t.is_banned(ip(1)));
    // Other clients are unaffected.
    assert!(!t.is_banned(ip(2)));
    std::thread::sleep(Duration::from_millis(150));
    assert!(!t.is_banned(ip(1)));
    // The expired ban cleared the client's record: it starts clean.
    assert_eq!(
        t.strike(ip(1), StrikeReason::UnknownHost),
        StrikeOutcome::Noted
    );
}

#[test]
fn strikes_older_than_the_window_do_not_count() {
    let t = tracker(StrikeRules {
        enabled: true,
        log_only: false,
        threshold: 2,
        window: Duration::from_millis(100),
        ..StrikeRules::default()
    });
    assert_eq!(
        t.strike(ip(1), StrikeReason::TrapPath),
        StrikeOutcome::Noted
    );
    std::thread::sleep(Duration::from_millis(130));
    // The first strike has expired: this is the first live strike, not
    // the second.
    assert_eq!(
        t.strike(ip(1), StrikeReason::TrapPath),
        StrikeOutcome::Noted
    );
    assert!(!t.is_banned(ip(1)));
}

#[test]
fn exempt_ranges_are_never_struck_or_banned() {
    let exempt: Vec<ipnet::IpNet> = vec!["203.0.113.0/24".parse().unwrap()];
    let t = StrikeTracker::new(
        StrikeRules {
            enabled: true,
            log_only: false,
            threshold: 1,
            ..StrikeRules::default()
        },
        8,
        Duration::from_secs(60),
        exempt,
    );
    assert_eq!(
        t.strike(ip(1), StrikeReason::MalformedRequest),
        StrikeOutcome::Noted
    );
    assert!(!t.is_banned(ip(1)));
}

#[test]
fn a_full_table_evicts_the_oldest_idle_entry_instead_of_growing() {
    let t = tracker(StrikeRules {
        enabled: true,
        log_only: false,
        threshold: 2,
        ..StrikeRules::default()
    });
    for n in 0..8 {
        t.strike(ip(n), StrikeReason::UnknownHost);
    }
    // A ninth client is tracked by evicting the oldest idle one; a tenth
    // strike on the evicted client starts from zero.
    t.strike(ip(9), StrikeReason::UnknownHost);
    assert_eq!(
        t.strike(ip(0), StrikeReason::UnknownHost),
        StrikeOutcome::Noted
    );
    assert!(!t.is_banned(ip(0)));
}

#[test]
fn config_round_trip_and_validation() {
    let cfg = rookd::config::Config::parse(
        r#"
[server]
listen = "127.0.0.1:8080"
https_listen = "127.0.0.1:8443"

[[sites]]
hosts = ["example.com"]
tls_cert = "cert.pem"
tls_key = "key.pem"
[sites.strikes]
enabled = true
threshold = 5
trap_paths = ["/wp-admin", "/.git"]
[[sites.routes]]
prefix = "/"
upstreams = ["http://127.0.0.1:9000"]
"#,
    )
    .unwrap();
    let rules = &cfg.sites[0].strikes;
    assert!(rules.enabled);
    assert!(rules.log_only); // default stays log-only
    assert_eq!(rules.threshold, 5);
    assert_eq!(rules.trap_paths, vec!["/wp-admin", "/.git"]);

    // A trap path that is not an absolute path is rejected.
    let bad = rookd::config::Config::parse(
        r#"
[server]
listen = "127.0.0.1:8080"
https_listen = "127.0.0.1:8443"
[[sites]]
hosts = ["example.com"]
tls_cert = "cert.pem"
tls_key = "key.pem"
[sites.strikes]
trap_paths = ["wp-admin"]
[[sites.routes]]
prefix = "/"
upstreams = ["http://127.0.0.1:9000"]
"#,
    );
    assert!(bad.is_err());
}

#[test]
fn disabled_rules_are_inert() {
    let t = tracker(StrikeRules {
        enabled: false,
        log_only: false,
        threshold: 1,
        ..StrikeRules::default()
    });
    assert_eq!(
        t.strike(ip(1), StrikeReason::MalformedRequest),
        StrikeOutcome::Noted
    );
    assert!(!t.is_banned(ip(1)));
    // And it stays out of the metrics entirely.
    let (strikes, bans, would_ban, _) = t.metrics();
    assert!(strikes.is_empty());
    assert_eq!(bans + would_ban, 0);
}

#[test]
fn the_strike_vec_never_outgrows_the_threshold() {
    // In log-only mode (the default), thousands of strikes from one
    // client stay a bounded counter, not an unbounded vec.
    let t = tracker(StrikeRules {
        log_only: true,
        threshold: 3,
        ..StrikeRules::default()
    });
    for _ in 0..10_000 {
        t.strike(ip(1), StrikeReason::MalformedRequest);
    }
    let (strikes, _, would_ban, _) = t.metrics();
    assert_eq!(strikes.get("malformed-request"), Some(&10_000));
    assert!(would_ban > 0);
}
