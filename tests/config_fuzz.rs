//! Configuration and TOML parser fuzzing (plan §9): `Config::parse`
//! must never panic and never hang, no matter the input. Two layers:
//!
//! - a deterministic mutation corpus: a known-valid config mutated by a
//!   seeded xorshift (truncations, char swaps, token insertions) — every
//!   outcome must be `Ok` or `Err`, never a panic, and every accepted
//!   (`Ok`) config must still satisfy the security invariants validation
//!   promises (loopback-only metrics, non-zero limits and timeouts,
//!   per-site strike rules that can actually count);
//! - an adversarial list of hand-picked inputs (deep nesting, huge
//!   numbers, null bytes, bidi controls, duplicate keys, megabyte
//!   values) with a per-input wall-clock bound.
//!
//! Deterministic on purpose: a failure reproduces from the seed in the
//! test output, no fuzzing infrastructure required. The framing fuzzer
//! in `fuzz/` covers the byte-stream side; this file covers the config
//! side.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use rookd::config::Config;

/// Wall-clock budget for a single parse. Generous for a debug build;
/// the mutation corpus parses in microseconds, so 5s means "hung",
/// not "slow".
const PARSE_BUDGET: Duration = Duration::from_secs(5);

/// One parse, observed from the outside.
enum Outcome {
    /// The parser answered: `Ok(config)` or a normal `Err` — both fine.
    /// Boxed: `Config` is large and `Panicked` is a unit, and clippy
    /// rightly refuses the size asymmetry.
    Parsed(Result<Box<Config>, String>),
    /// The parser panicked; the worker already printed the seed.
    Panicked,
}

/// Parse `input` on a worker thread with a wall-clock budget, so the
/// two failure modes this file exists for are both caught: a panic
/// (caught in the worker, reported with its seed, failed on the main
/// thread) and a hang (the stopwatch lives here, so it fires even when
/// the parse never returns). A genuinely hung worker leaks and keeps
/// the process alive — CI's own per-test timeout is the backstop, and
/// the panic message names the seed either way.
fn parse_bounded(label: &str, seed: u64, input: String) -> Result<Box<Config>, String> {
    let (tx, rx) = mpsc::channel();
    let label = label.to_string();
    let worker_label = label.clone();
    thread::spawn(move || {
        let outcome = match catch_unwind(AssertUnwindSafe(|| {
            Config::parse(&input)
                .map(Box::new)
                .map_err(|e| e.to_string())
        })) {
            Ok(result) => Outcome::Parsed(result),
            Err(_) => {
                // The seed must be visible even if the harness output
                // is lost: stderr first, then the main thread panics.
                eprintln!("config_fuzz: parser panicked (label={worker_label}, seed={seed})");
                Outcome::Panicked
            }
        };
        // If the main thread already timed out, nobody is listening;
        // the eprintln above still records the seed.
        let _ = tx.send(outcome);
    });
    match rx.recv_timeout(PARSE_BUDGET) {
        Ok(Outcome::Parsed(result)) => result,
        Ok(Outcome::Panicked) => {
            panic!(
                "config_fuzz: parser panicked (label={label}, seed={seed}) — rerun reproduces exactly"
            )
        }
        Err(mpsc::RecvTimeoutError::Timeout) => panic!(
            "config_fuzz: parse exceeded {PARSE_BUDGET:?} (label={label}, seed={seed}) — a parse must never hang"
        ),
        Err(e) => {
            panic!("config_fuzz: worker died without reporting (label={label}, seed={seed}): {e}")
        }
    }
}

/// The invariants `Config::parse` validation promises. A mutation that
/// is ACCEPTED (`Ok`) must still uphold every one of them; otherwise
/// the mutator found a validation hole a panic would never reveal.
fn assert_accepted_invariants(label: &str, seed: u64, config: &Config) {
    let ctx = || format!("(label={label}, seed={seed})");
    let s = &config.server;
    // Metrics never binds off-loopback.
    assert!(
        config.metrics.listen.ip().is_loopback(),
        "metrics.listen escaped loopback {}",
        ctx()
    );
    // Non-zero limits.
    assert!(s.max_connections > 0, "max_connections {}", ctx());
    assert!(
        s.max_connections_per_ip > 0,
        "max_connections_per_ip {}",
        ctx()
    );
    assert!(
        s.max_connections_per_upstream > 0,
        "max_connections_per_upstream {}",
        ctx()
    );
    assert!(s.max_upstream_per_ip > 0, "max_upstream_per_ip {}", ctx());
    assert!(s.max_tracked_clients > 0, "max_tracked_clients {}", ctx());
    assert!(s.requests_per_second > 0, "requests_per_second {}", ctx());
    assert!(s.request_burst > 0, "request_burst {}", ctx());
    assert!(
        s.max_request_body_bytes > 0,
        "max_request_body_bytes {}",
        ctx()
    );
    assert!(
        (8192..=16 * 1024 * 1024).contains(&s.max_header_bytes),
        "max_header_bytes {}",
        ctx()
    );
    assert!(
        s.request_burst >= s.requests_per_second,
        "burst >= rps {}",
        ctx()
    );
    // Non-zero timeouts.
    for (name, t) in [
        ("header_read_timeout", s.header_read_timeout),
        ("request_timeout", s.request_timeout),
        ("upstream_connect_timeout", s.upstream_connect_timeout),
        ("idle_timeout", s.idle_timeout),
        ("websocket_idle_timeout", s.websocket_idle_timeout),
        ("websocket_max_lifetime", s.websocket_max_lifetime),
        ("shutdown_drain", s.shutdown_drain),
    ] {
        assert!(t > Duration::ZERO, "{name} non-zero {}", ctx());
    }
    // HSTS preload implies its prerequisites.
    if s.hsts_preload {
        assert!(
            s.hsts_include_subdomains,
            "preload needs subdomains {}",
            ctx()
        );
        assert!(
            s.hsts_max_age >= 31_536_000,
            "preload needs max-age {}",
            ctx()
        );
    }
    // Sites: at least one, each with hosts and routes.
    assert!(!config.sites.is_empty(), "at least one site {}", ctx());
    let mut all_hosts = std::collections::HashSet::new();
    for site in &config.sites {
        assert!(!site.hosts.is_empty(), "site hosts non-empty {}", ctx());
        for host in &site.hosts {
            // Host matching is the routing boundary: normalized
            // lowercase, no wildcard, no port, no whitespace or
            // control characters.
            assert!(!host.is_empty(), "host non-empty {}", ctx());
            assert_eq!(host, &host.to_lowercase(), "host lowercase {}", ctx());
            assert!(!host.contains('*'), "host has no wildcard {}", ctx());
            assert!(
                !host.contains(':') && !host.contains('[') && !host.contains(']'),
                "host carries no port/brackets {}",
                ctx()
            );
            assert!(
                !host.chars().any(|c| c.is_whitespace() || c.is_control()),
                "host free of whitespace/control {}",
                ctx()
            );
            assert!(all_hosts.insert(host), "duplicate host {host:?} {}", ctx());
        }
        // TLS material comes in pairs: both or neither.
        assert_eq!(
            site.tls_cert.is_some(),
            site.tls_key.is_some(),
            "tls_cert/tls_key both or neither {}",
            ctx()
        );
        assert!(!site.routes.is_empty(), "site routes non-empty {}", ctx());
        let mut prefixes = std::collections::HashSet::new();
        for route in &site.routes {
            assert!(route.prefix.starts_with('/'), "absolute prefix {}", ctx());
            assert!(prefixes.insert(&route.prefix), "duplicate prefix {}", ctx());
            assert!(
                !route.upstreams.is_empty(),
                "route upstreams non-empty {}",
                ctx()
            );
            // Without allow_remote_http, every upstream stays loopback
            // (mirrors config::is_loopback_host, which is private).
            if !route.allow_remote_http {
                for upstream in &route.upstreams {
                    let host = upstream.host().unwrap_or_default();
                    let unbracketed = host
                        .strip_prefix('[')
                        .and_then(|h| h.strip_suffix(']'))
                        .unwrap_or(host);
                    let loopback = unbracketed
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
                        || unbracketed
                            .strip_suffix('.')
                            .unwrap_or(unbracketed)
                            .eq_ignore_ascii_case("localhost")
                        || unbracketed
                            .rsplit_once('.')
                            .is_some_and(|(_, suffix)| suffix.eq_ignore_ascii_case("localhost"));
                    assert!(loopback, "upstream {upstream} loopback {}", ctx());
                }
            }
        }
        // Strike rules, when present, can actually count and ban.
        if site.strikes.enabled {
            assert!(site.strikes.threshold >= 1, "strike threshold {}", ctx());
            assert!(site.strikes.window_secs > 0, "strike window {}", ctx());
            assert!(site.strikes.ban_secs > 0, "strike ban {}", ctx());
            for path in &site.strikes.trap_paths {
                assert!(
                    path.starts_with('/') && !path.contains('?') && !path.contains('#'),
                    "trap path shape {}",
                    ctx()
                );
            }
        }
    }
}

/// A valid baseline config, exercising every section.
const VALID: &str = r#"
[server]
listen = "127.0.0.1:8080"
https_listen = "127.0.0.1:8443"
max_connections = 1000
max_connections_per_ip = 50
requests_per_second = 20
request_burst = 40
max_header_bytes = 16384
max_request_body_bytes = 2097152
header_read_timeout = 11
request_timeout = 31
upstream_connect_timeout = 6
idle_timeout = 61
websocket_idle_timeout = 301
websocket_max_lifetime = 3601
shutdown_drain = 16
trusted_proxies = ["10.0.0.0/8", "2001:db8::/32"]
cloudflare_ranges = ["203.0.113.0/24"]
strikes = { enabled = true, log_only = true, threshold = 5, window_secs = 600, ban_secs = 3600, trap_paths = ["/wp-admin"] }
strike_allowlist = ["192.0.2.10/32"]

[metrics]
enabled = true
listen = "127.0.0.1:9188"

[[sites]]
hosts = ["example.com", "www.example.com"]

[sites.acme]
contact = "mailto:ops@example.com"
directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
state_dir = "/tmp/rookd-acme"
trusted_root = "/etc/ssl/certs/ca-certificates.crt"
renew_before_days = 30

[[sites.routes]]
prefix = "/"
upstreams = ["http://127.0.0.1:9000", "http://127.0.0.1:9002"]
websocket = true
origins = ["https://example.com"]
allow_remote_http = false

[[sites.routes]]
prefix = "/api"
upstreams = ["http://127.0.0.1:9001"]
"#;

/// Insertable fragments chosen to maximally confuse a TOML parser.
const TOKENS: &[&str] = &[
    "[",
    "]",
    "[[",
    "]]",
    "{",
    "}",
    "=",
    ",",
    ".",
    "\"",
    "'",
    "\\",
    "\n",
    "\r\n",
    "#",
    "[[sites]]",
    "\"\"",
    "key = ",
    "= \"\"",
    "0",
    "-1",
    "18446744073709551616",
    "99999999999999999999999",
    "1e999",
    "0.0.0.0",
    "127.0.0.1:99999",
    "::1",
    "true",
    "false",
    "1979-05-27T07:32:00Z",
    "💣",
    "\u{202e}",
    "\u{200b}",
    "\0",
    "é",
];

/// A tiny deterministic xorshift so failures reproduce from the seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// One seeded mutation of `input`: truncate at a char boundary, swap a
/// char for a token, or insert a token — applied 1-3 times.
fn mutate(input: &str, seed: u64) -> String {
    let mut rng = Rng(seed | 1);
    let mut text = input.to_string();
    for _ in 0..1 + rng.below(3) {
        if text.is_empty() {
            text.push_str(TOKENS[rng.below(TOKENS.len())]);
            continue;
        }
        match rng.below(3) {
            0 => {
                // Truncate at a char boundary.
                let mut at = rng.below(text.len() + 1);
                while !text.is_char_boundary(at) {
                    at -= 1;
                }
                text.truncate(at);
            }
            1 => {
                // Insert a token at a char boundary.
                let mut at = rng.below(text.len() + 1);
                while !text.is_char_boundary(at) {
                    at -= 1;
                }
                text.insert_str(at, TOKENS[rng.below(TOKENS.len())]);
            }
            _ => {
                // Replace one char with a token.
                let mut at = rng.below(text.len());
                while !text.is_char_boundary(at) {
                    at -= 1;
                }
                let mut end = at + 1;
                while !text.is_char_boundary(end) {
                    end += 1;
                }
                text.replace_range(at..end, TOKENS[rng.below(TOKENS.len())]);
            }
        }
    }
    text
}

#[test]
fn parse_never_panics_across_a_seeded_mutation_corpus() {
    // A panic or hang anywhere in here fails the test with the seed in
    // the assertion output; re-running that seed reproduces it exactly.
    for seed in 0..4096u64 {
        let input = mutate(VALID, seed);
        if let Ok(config) = parse_bounded("mutated-valid", seed, input) {
            assert_accepted_invariants("mutated-valid", seed, &config);
        }
    }
    // Mutating the empty string and pure whitespace too.
    for seed in 0..256u64 {
        let _ = parse_bounded("mutated-empty", seed, mutate("", seed));
        let _ = parse_bounded("mutated-whitespace", seed, mutate("\n  \n", seed));
    }
}

#[test]
fn parse_handles_adversarial_inputs_without_panicking_or_hanging() {
    let deep_brackets = "[".repeat(10_000);
    let deep_inline = format!("x = {}", "{".repeat(1_000));
    let huge_number = format!("x = {}", "9".repeat(100_000));
    let megabyte_value = format!("key = \"{}\"", "A".repeat(1_000_000));
    let many_sites = "[[sites]]\nhosts = [\"example.com\"]\n".repeat(5_000);
    let inputs: Vec<(&str, String)> = vec![
        (
            "null bytes everywhere",
            "\0\0\0\0[server]\0listen = \0".into(),
        ),
        (
            "bidi override in host",
            VALID.replace("example.com", "ex\u{202e}ample.com"),
        ),
        (
            "zero-width joiner host",
            VALID.replace("example.com", "exa\u{200b}mple.com"),
        ),
        ("duplicate keys", "x = 1\nx = 2\n".into()),
        ("duplicate tables", "[server]\n[server]\n".into()),
        ("deep brackets", deep_brackets),
        ("deep inline table", deep_inline),
        ("huge number literal", huge_number),
        ("megabyte string value", megabyte_value),
        ("thousands of sites", many_sites),
        ("only a BOM", "\u{feff}".into()),
        (
            "CRLF/CR/LF mix",
            "[server]\r\nlisten\n=\r\"127.0.0.1:80\"\r".into(),
        ),
        ("unterminated string", "key = \"never ends".into()),
        (
            "valid config with trailing junk",
            format!("{VALID}\n\u{0}garbage{{{{["),
        ),
    ];
    for (i, (name, input)) in inputs.into_iter().enumerate() {
        // Same worker-thread budget as the mutation corpus: the old
        // stopwatch-after-return could never fire on a true hang.
        if let Ok(config) = parse_bounded(name, i as u64, input) {
            assert_accepted_invariants(name, i as u64, &config);
        }
    }
}

/// The baseline itself must parse, or the mutation corpus proves nothing.
#[test]
fn baseline_config_is_valid() {
    Config::parse(VALID).expect("the mutation-corpus baseline must parse");
}
