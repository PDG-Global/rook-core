# Rook

Rook is a security-first Rust HTTP reverse proxy and load balancer. The daemon and crate are named `rookd`.

**Status:** Phase 2 development. This build supports HTTP/1.1 plaintext, HTTP/1.1 and HTTP/2 over TLS, supplied certificates with hot reload, and ACME HTTP-01 issuance and renewal. ACME has not yet been validated against a public Let's Encrypt endpoint. Do not deploy this build in production.

## Build and verify

Requires Rust 1.88 or later.

```sh
cargo build --release
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo audit
cargo deny check
```

### Direct framing fuzzing

The dependency-free `framing-fuzz` target drives `FramingGuardIo` directly, including randomized read/write fragmentation and pending polls. It combines structured HTTP framing seeds with random bytes, truncation, mutation, and request splicing. Inputs are capped at 16 KiB, every poll loop has a finite budget, and pass-through output must remain an exact prefix of the input. The seed corpus covers CL+TE, duplicate and invalid Content-Length, non-exact Transfer-Encoding, chunk and trailer boundaries, keep-alive transitions, bare LF, and request-like headers inside bodies.

Run a campaign bounded by either 60 seconds or 250,000 iterations, whichever comes first:

```sh
cargo run --release --bin framing-fuzz -- --duration-seconds 60 --max-iterations 250000 --seed 1296421559844135539
```

The target prints the actual iteration count, elapsed time, case mix, and rejection count. Change `--seed` to explore another deterministic sequence; a failure prints the seed, iteration, case kind, and input needed to reproduce it.

Validate configuration and local certificate, key, blocklist, ACME trust, and state-directory permissions without opening listeners or contacting ACME:

```sh
rookd --config rookd.toml --check
```

Run with the default `./rookd.toml` or an explicit path:

```sh
rookd
rookd --config /usr/local/etc/rook/rookd.toml
```

Set `RUST_LOG` to adjust logging; the default is `info`. SIGINT and SIGTERM trigger bounded graceful draining.

## Minimal HTTP configuration

```toml
[server]
listen = "127.0.0.1:8080"

[[sites]]
hosts = ["example.com"]

[[sites.routes]]
prefix = "/"
upstreams = ["http://127.0.0.1:9000"]
websocket = true
```

The complete development example is in `rookd.example.toml`.

## Supplied-certificate HTTPS configuration

```toml
[server]
listen = "0.0.0.0:80"
https_listen = "0.0.0.0:443"

[[sites]]
hosts = ["example.com"]
tls_cert = "/usr/local/etc/rook/example.com-cert.pem"
tls_key = "/usr/local/etc/rook/example.com-key.pem"

[[sites.routes]]
prefix = "/"
upstreams = ["http://127.0.0.1:9000"]
websocket = true
```

Private keys must have no group or other permissions on Unix (mode `0600` or `0400`). RSA keys must be at least 2048 bits. Rook checks the certificate/key pair, uses TLS 1.3 unless TLS 1.2 is explicitly enabled, and has no default certificate for unknown SNI. Valid files are reloaded every two seconds; failed reloads keep the last valid certificate. An invalid or expired supplied pair leaves only that site's handshakes failing while other sites and ACME recovery continue. `--check` rejects the same files strictly.

## ACME configuration

```toml
[server]
listen = "0.0.0.0:80"
https_listen = "0.0.0.0:443"
blocklist_file = "/usr/local/etc/rook/blocked-hashes.txt"

[[sites]]
hosts = ["example.com"]

[sites.acme]
contact = "mailto:admin@example.com"
directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
state_dir = "./rookd-acme"
trusted_root = "/usr/local/etc/rook/isrg-root-x1.pem"
renew_before_days = 30

[[sites.routes]]
prefix = "/"
upstreams = ["http://127.0.0.1:9000"]
```

ACME orders cover only configured hosts and use HTTP-01. Account credentials are stored in `state_dir/account.json`. Validated certificate/key pairs are staged in `state_dir/<first-host>/versions/<id>/` and published by atomically replacing the `<first-host>/current` symlink. Only the active version and one previous version are retained, and publication directories are fsynced. State directories use mode `0700` and files `0600` on Unix; existing directories with looser permissions are rejected. A supplied certificate/key pair is used only while no valid ACME pair exists. HTTP challenges are served before configured-host HTTP-to-HTTPS redirects. Renewals use daily expiry and exact-SAN checks, a five-minute attempt deadline, and capped jittered backoff; failures keep the last valid certificate.

The default directory is Let's Encrypt production. Use the staging URL above for tests. `trusted_root` is required and is the only root set used for that ACME connection; no public roots are compiled into Rook. Document how this file is updated when the CA changes roots.

## Configuration reference

### `[server]`

All fields are optional and have these defaults:

| Field | Default | Meaning |
| --- | --- | --- |
| `listen` | `"0.0.0.0:80"` | HTTP/1.1 listener socket address. |
| `https_listen` | disabled | HTTPS listener with HTTP/1.1 and HTTP/2 ALPN. |
| `allow_tls12` | `false` | Enables TLS 1.2 as the only fallback; TLS 1.3 remains default. |
| `hsts_max_age` | `31536000` | HSTS max-age in seconds; `0` disables HSTS. |
| `hsts_include_subdomains` | `false` | Adds `includeSubDomains` to HSTS. |
| `hsts_preload` | `false` | Adds `preload`; requires subdomains and a one-year max-age. |
| `blocklist_file` | disabled | Runtime certificate/public-key SHA-256 blocklist. |
| `max_connections` | `4096` | Maximum simultaneous client connections. |
| `max_connections_per_ip` | `256` | Maximum connections per IPv4 address or IPv6 /64. |
| `max_connections_per_upstream` | `1024` | Maximum in-flight requests or WebSocket tunnels per configured upstream. |
| `max_upstream_per_ip` | `64` | Maximum in-flight upstream slots per verified client IP. |
| `max_tracked_clients` | `10000` | Bound for connection and rate-limit tables. |
| `requests_per_second` | `100` | Default sustained request rate per client and route. |
| `request_burst` | `200` | Default request burst; must be at least the sustained rate. |
| `max_header_bytes` | `32768` | HTTP header buffer limit, from 8192 through 16777216 bytes. |
| `max_request_body_bytes` | `1048576` | Maximum streamed request body size. |
| `header_read_timeout` | `10` | Seconds allowed for first bytes, headers, and TLS handshakes. |
| `request_timeout` | `30` | Seconds allowed for upstream response headers after the request body has been sent. |
| `upstream_connect_timeout` | `5` | Seconds allowed to connect to an upstream. |
| `idle_timeout` | `60` | Seconds without body progress or connection writes before closing. |
| `websocket_idle_timeout` | `300` | Seconds without WebSocket traffic before closing. |
| `websocket_max_lifetime` | `3600` | Maximum WebSocket tunnel lifetime in seconds. |
| `shutdown_drain` | `15` | Seconds allowed for graceful connection and tunnel draining. |
| `trusted_proxies` | `[]` | CIDRs of proxies we run, whose `X-Forwarded-For` Rook believes. |
| `cloudflare_ranges` | `[]` | Cloudflare edge CIDRs — the only peers permitted to supply `CF-Connecting-IP`; also trusted for `X-Forwarded-For`. |

Unknown fields are rejected. Durations are integer seconds and all limits/timeouts must be nonzero except `hsts_max_age`, which may be zero.

### `[[sites]]`

- `hosts` (required): nonempty list of DNS names or IPv4 literals. Names are case-insensitive, normalized to lowercase, and cannot contain ports or wildcards. Every host must be unique across the configuration.
- `routes` (required): at least one `[[sites.routes]]` block. Longest matching path prefix wins.
- `tls_cert`, `tls_key`: optional supplied certificate chain and private key paths. They must be provided as a pair.
- `[sites.acme]`: optional ACME configuration. With HTTPS enabled, each site needs supplied files, ACME, or both. With HTTPS disabled, neither may be configured.

### `[[sites.routes]]`

- `prefix` (required): path prefix beginning with `/`, unique within the site. Prefixes use the same normalization as request paths, so `/%61dmin` becomes `/admin`. `/api` matches `/api` and `/api/x`, not `/apix`. The matched prefix is preserved when forwarding.
- `upstreams` (required): nonempty list of absolute HTTP base URIs. HTTPS upstreams are rejected by `--check` until implemented. Base paths are prepended to the normalized request path; the original query is preserved. Plain HTTP to non-loopback upstreams requires `allow_remote_http = true`.
- `websocket`: optional, default `false`. Enables HTTP/1.1 WebSocket upgrades.
- `origins`: optional, default `[]`. When nonempty, WebSocket requests must have an exactly matching `Origin` URI. Ordinary HTTP requests are not affected.
- `allow_remote_http`: optional, default `false`. Explicitly permits plaintext HTTP to non-loopback upstreams.
- `requests_per_second`, `request_burst`: optional per-route rate-limit overrides.

### `[sites.acme]`

| Field | Default | Meaning |
| --- | --- | --- |
| `contact` | required | ACME contact beginning with `mailto:`. |
| `directory_url` | Let's Encrypt production | Absolute HTTPS ACME directory URL without query or fragment. |
| `state_dir` | `"./rookd-acme"` | Account, certificate, and key state directory. |
| `trusted_root` | required | PEM root used only for this ACME client. |
| `renew_before_days` | `30` | Renew when expiry is within this many days, from 1 through 60. |

### Runtime blocklist

`blocklist_file` is reloaded every two seconds. Invalid reloads keep the previous valid blocklist. Blank lines and `#` comments are ignored; other lines have these forms:

```text
cert-sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
key-sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
```

Certificate hashes cover DER certificates in the verified chain. Key hashes cover the complete DER SubjectPublicKeyInfo. The blocklist adds to normal WebPki chain and hostname verification and applies to the ACME connection. It checks the leaf and presented intermediates; a root that is not sent by the server cannot be matched, so remove a distrusted root from `trusted_root` as well.

## Request behavior

- Plaintext listeners accept HTTP/1.1 only; h2c and HTTP/2 prior-knowledge are refused. HTTPS negotiates HTTP/1.1 or HTTP/2. Every HTTPS-enabled site redirects plain HTTP to HTTPS after ACME challenges.
- Unknown hosts have no default upstream and return 404. Unknown SNI has no certificate. SNI and Host mismatches return 421.
- Multiple Host headers and absolute-URI/Host or HTTP/2 authority/Host mismatches return 400.
- Rook normalizes percent-encoded unreserved path characters before matching. It rejects encoded slashes/backslashes, dot segments including semicolon forms, repeated separators, invalid escapes, and control characters.
- Hop-by-hop headers are removed in both directions. Forwarding and client-IP spoof headers are overwritten or stripped; underscore header names are rejected.
- X-Real-IP and X-Forwarded-For contain the verified client IP without a port. X-Forwarded-Proto reflects the incoming scheme.
- `CF-Connecting-IP` is read only when the direct peer is in `cloudflare_ranges`; from anywhere else it is ignored, never rejected. X-Forwarded-For is evaluated from the proxy boundary toward the client for peers in either list.
- WebSocket tunneling starts only after a valid upstream 101 response. Rejected upgrades are forwarded as ordinary HTTP responses; invalid upgrade responses return 502.
- HSTS is added to HTTPS responses when enabled and never to plain HTTP. An upstream HSTS header is not duplicated.
- Error responses are empty and do not expose upstream addresses or internal errors.
