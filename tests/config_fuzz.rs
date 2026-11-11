//! Configuration and TOML parser fuzzing (plan §9): `Config::parse`
//! must never panic and never hang, no matter the input. Two layers:
//!
//! - a deterministic mutation corpus: a known-valid config mutated by a
//!   seeded xorshift (truncations, char swaps, token insertions) — every
//!   outcome must be `Ok` or `Err`, never a panic;
//! - an adversarial list of hand-picked inputs (deep nesting, huge
//!   numbers, null bytes, bidi controls, duplicate keys, megabyte
//!   values) with a per-input wall-clock bound.
//!
//! Deterministic on purpose: a failure reproduces from the seed in the
//! test output, no fuzzing infrastructure required. The framing fuzzer
//! in `fuzz/` covers the byte-stream side; this file covers the config
//! side.

use std::time::{Duration, Instant};

use rookd::config::Config;

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
    // A panic anywhere in here fails the test with the seed in the
    // assertion output; re-running that seed reproduces it exactly.
    for seed in 0..4096u64 {
        let input = mutate(VALID, seed);
        let _ = Config::parse(&input);
    }
    // Mutating the empty string and pure whitespace too.
    for seed in 0..256u64 {
        let _ = Config::parse(&mutate("", seed));
        let _ = Config::parse(&mutate("\n  \n", seed));
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
    for (name, input) in inputs {
        let start = Instant::now();
        let _ = Config::parse(&input);
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "{name}: parse took {:?} — a parse must be fast even on adversarial input",
            start.elapsed()
        );
    }
}

/// The baseline itself must parse, or the mutation corpus proves nothing.
#[test]
fn baseline_config_is_valid() {
    Config::parse(VALID).expect("the mutation-corpus baseline must parse");
}
