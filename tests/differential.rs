//! Differential request-smuggling tests (plan §9): the same corpus of
//! malformed and ambiguous raw requests goes to Rook and to Caddy, each
//! fronting its own byte-capturing upstream.
//!
//! The property asserted for Rook: every ambiguous entry is refused
//! (400) and nothing it rejected reaches its upstream — no marker in a
//! request line, none inside a body. Rook is deliberately stricter than
//! Caddy here (underscore header names, ambiguous framing): Caddy's Go
//! stack normalizes several of these, and a pipelined second request
//! from the same client is not a desync, so Caddy's outcomes are
//! recorded as the comparison baseline, not asserted as failures.
//!
//! Caddy is an optional oracle: if the binary is not on PATH the Caddy
//! half is skipped and Rook is still held to the property.

use std::{
    io::Write as _,
    net::{Ipv4Addr, SocketAddr},
    process::{Child, Command, Stdio},
    time::Duration,
};

use rookd::{config::Config, server};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::JoinHandle,
    time::{Instant, sleep, timeout},
};

const IO_TIMEOUT: Duration = Duration::from_secs(2);
const MARKER: &str = "SMUGGLED";

struct TaskGuard(JoinHandle<()>);

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// What the capturing upstream reports. `Raw` is every byte read,
/// teed before parsing: desync shows up as bytes that never form a
/// request (a partial head at EOF, an over-long head, leftovers in the
/// buffer), so asserting only on parsed `Request`s would be blind to
/// exactly that (Thomas, review of PR #9).
#[derive(Debug)]
enum UpstreamEvent {
    Raw(Vec<u8>),
    Request(Captured),
}

/// One request the upstream received, as raw head + body bytes.
#[derive(Debug)]
struct Captured {
    head: String,
    body: Vec<u8>,
}

impl Captured {
    fn mentions_marker(&self) -> bool {
        self.head.contains(MARKER)
            || self
                .body
                .windows(MARKER.len())
                .any(|w| w == MARKER.as_bytes())
    }
}

fn contains_marker(bytes: &[u8]) -> bool {
    bytes.windows(MARKER.len()).any(|w| w == MARKER.as_bytes())
}

/// A minimal HTTP/1.1 server that tees every byte it reads, captures
/// every request it parses, and answers 200. Parses Content-Length and
/// chunked bodies so keep-alive framing stays aligned; a request it
/// cannot frame closes the connection.
async fn spawn_capture_upstream() -> (SocketAddr, mpsc::UnboundedReceiver<UpstreamEvent>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let tx = tx.clone();
            tokio::spawn(async move { serve_capturing(stream, tx).await });
        }
    });
    (addr, rx)
}

/// One read, teed into the event channel before anything parses it.
async fn read_teed(
    stream: &mut TcpStream,
    chunk: &mut [u8; 8192],
    tx: &mpsc::UnboundedSender<UpstreamEvent>,
) -> std::io::Result<usize> {
    let read = stream.read(chunk).await?;
    if read > 0 {
        let _ = tx.send(UpstreamEvent::Raw(chunk[..read].to_vec()));
    }
    Ok(read)
}

async fn serve_capturing(
    mut stream: TcpStream,
    tx: mpsc::UnboundedSender<UpstreamEvent>,
) -> std::io::Result<()> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        // Read until a complete head.
        let head_end = loop {
            if let Some(end) = find_subslice(&buffer, b"\r\n\r\n") {
                break end + 4;
            }
            let read = read_teed(&mut stream, &mut chunk, &tx).await?;
            if read == 0 {
                return Ok(());
            }
            buffer.extend_from_slice(&chunk[..read]);
            if buffer.len() > 64 * 1024 {
                return Ok(());
            }
        };
        let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
        buffer.drain(..head_end);

        // Body framing: Content-Length wins; otherwise chunked if the
        // only Transfer-Encoding value is exactly "chunked".
        let content_length = head
            .lines()
            .filter_map(|line| line.split_once(':'))
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .filter_map(|(_, value)| value.trim().parse::<usize>().ok())
            .next();
        let chunked = head
            .lines()
            .filter_map(|line| line.split_once(':'))
            .any(|(name, value)| {
                name.eq_ignore_ascii_case("transfer-encoding") && value.trim() == "chunked"
            });
        let body = if let Some(length) = content_length {
            while buffer.len() < length {
                let read = read_teed(&mut stream, &mut chunk, &tx).await?;
                if read == 0 {
                    break;
                }
                buffer.extend_from_slice(&chunk[..read]);
            }
            let body = buffer[..buffer.len().min(length)].to_vec();
            buffer.drain(..body.len());
            body
        } else if chunked {
            read_chunked(&mut stream, &mut buffer, &mut chunk, &tx).await?
        } else {
            Vec::new()
        };
        let _ = tx.send(UpstreamEvent::Request(Captured { head, body }));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
            .await?;
    }
}

/// Read a chunked body from `buffer` (already-read bytes) plus the
/// stream. Stops after the terminating zero chunk; trailers are
/// consumed. Malformed chunks close the connection with what we have.
async fn read_chunked(
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
    chunk: &mut [u8; 8192],
    tx: &mpsc::UnboundedSender<UpstreamEvent>,
) -> std::io::Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        // One line: the chunk size.
        let line = loop {
            if let Some(end) = buffer.windows(2).position(|w| w == b"\r\n") {
                let line = buffer[..end].to_vec();
                buffer.drain(..end + 2);
                break line;
            }
            let read = read_teed(stream, chunk, tx).await?;
            if read == 0 {
                return Ok(body);
            }
            buffer.extend_from_slice(&chunk[..read]);
        };
        let size_str = String::from_utf8_lossy(&line);
        let size_str = size_str.split(';').next().unwrap_or("").trim();
        let Ok(size) = usize::from_str_radix(size_str, 16) else {
            return Ok(body);
        };
        if size == 0 {
            // Consume trailers up to a blank line.
            loop {
                if let Some(end) = find_subslice(buffer, b"\r\n\r\n") {
                    buffer.drain(..end + 4 - 2);
                    break;
                }
                if buffer.starts_with(b"\r\n") {
                    buffer.drain(..2);
                    break;
                }
                let read = read_teed(stream, chunk, tx).await?;
                if read == 0 {
                    break;
                }
                buffer.extend_from_slice(&chunk[..read]);
                if buffer.len() > 64 * 1024 {
                    break;
                }
            }
            return Ok(body);
        }
        while buffer.len() < size + 2 {
            let read = read_teed(stream, chunk, tx).await?;
            if read == 0 {
                return Ok(body);
            }
            buffer.extend_from_slice(&chunk[..read]);
        }
        body.extend_from_slice(&buffer[..size]);
        buffer.drain(..size + 2);
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

async fn free_addr() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    listener.local_addr().unwrap()
}

async fn wait_for_port(addr: SocketAddr, deadline: Duration) -> bool {
    let start = Instant::now();
    loop {
        if let Ok(Ok(stream)) = timeout(Duration::from_millis(50), TcpStream::connect(addr)).await {
            drop(stream);
            return true;
        }
        if start.elapsed() >= deadline {
            return false;
        }
        sleep(Duration::from_millis(10)).await;
    }
}

async fn spawn_rook(upstream: SocketAddr) -> (SocketAddr, TaskGuard) {
    let addr = free_addr().await;
    let config = format!(
        r#"
[server]
listen = "{addr}"
header_read_timeout = 2
request_timeout = 2
idle_timeout = 2
upstream_connect_timeout = 1
shutdown_drain = 1

[[sites]]
hosts = ["example.com"]

[[sites.routes]]
prefix = "/"
upstreams = ["http://{upstream}"]
"#
    );
    let config = Config::parse(&config).unwrap();
    let task = tokio::spawn(async move {
        server::run(config).await.unwrap();
    });
    assert!(
        wait_for_port(addr, IO_TIMEOUT).await,
        "rook did not come up"
    );
    (addr, TaskGuard(task))
}

/// Caddy fronting the same upstream, HTTP only, admin API off.
fn spawn_caddy(upstream: SocketAddr) -> Option<(SocketAddr, ChildGuard)> {
    let addr = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = addr.local_addr().unwrap().port();
    drop(addr);
    let config = format!(
        "{{\n  admin off\n  auto_https off\n}}\nhttp://:{port} {{\n  reverse_proxy {upstream}\n}}\n"
    );
    let mut path = std::env::temp_dir();
    path.push(format!("rook-differential-caddy-{port}.Caddyfile"));
    std::fs::File::create(&path)
        .unwrap()
        .write_all(config.as_bytes())
        .unwrap();
    let log_path = std::env::temp_dir().join(format!("rook-differential-caddy-{port}.log"));
    let log = std::fs::File::create(&log_path).unwrap();
    let child = Command::new("caddy")
        .args(["run", "--config"])
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::from(log))
        .spawn()
        .ok()?;
    Some((
        format!("127.0.0.1:{port}").parse().unwrap(),
        ChildGuard(child),
    ))
}

/// Send one raw corpus entry, read whatever response head comes back.
async fn send_raw(addr: SocketAddr, raw: &str) -> Option<u16> {
    let Ok(mut stream) = TcpStream::connect(addr).await else {
        return None;
    };
    stream.write_all(raw.as_bytes()).await.ok()?;
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let read = timeout(IO_TIMEOUT, stream.read(&mut chunk))
        .await
        .ok()?
        .ok()?;
    if read == 0 {
        return None;
    }
    buffer.extend_from_slice(&chunk[..read]);
    let head = String::from_utf8_lossy(&buffer);
    head.split_whitespace().nth(1).and_then(|s| s.parse().ok())
}

fn corpus() -> Vec<(&'static str, String)> {
    let smuggled = format!("GET /{MARKER} HTTP/1.1\r\nHost: example.com\r\n\r\n");
    // extra_headers carries its own trailing CRLFCRLF.
    let post = |extra_headers: &str, body: &str| {
        format!("POST / HTTP/1.1\r\nHost: example.com\r\n{extra_headers}{body}")
    };
    vec![
        // Control: a clean request that must reach the upstream, so an
        // empty capture can't mask a broken harness.
        (
            "clean-get",
            "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_string(),
        ),
        // CL.TE: Content-Length first, Transfer-Encoding second.
        (
            "cl-te",
            post(
                "Content-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n",
                &format!("0\r\n\r\n{smuggled}"),
            ),
        ),
        // TE.CL: Transfer-Encoding first, Content-Length second.
        (
            "te-cl",
            post(
                "Transfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n",
                &format!("5\r\nhello\r\n0\r\n\r\n{smuggled}"),
            ),
        ),
        // Duplicate Content-Length, same value.
        (
            "duplicate-cl-same",
            post("Content-Length: 5\r\nContent-Length: 5\r\n\r\n", "hello"),
        ),
        // Duplicate Content-Length, different values.
        (
            "duplicate-cl-differ",
            post("Content-Length: 0\r\nContent-Length: 30\r\n\r\n", &smuggled),
        ),
        // Obfuscated Transfer-Encoding values.
        (
            "te-whitespace-before-colon",
            post(
                "Transfer-Encoding : chunked\r\nContent-Length: 4\r\n\r\n",
                &format!("0\r\n\r\n{smuggled}"),
            ),
        ),
        (
            "te-padded-value",
            post(
                "Transfer-Encoding:  chunked\r\nContent-Length: 13\r\n\r\n",
                &format!("0\r\n\r\n{smuggled}"),
            ),
        ),
        (
            "te-chunked-identity",
            post(
                "Transfer-Encoding: chunked, identity\r\nContent-Length: 13\r\n\r\n",
                &format!("0\r\n\r\n{smuggled}"),
            ),
        ),
        // Signed Content-Length.
        (
            "cl-plus-prefix",
            post(
                "Content-Length: +13\r\nTransfer-Encoding: chunked\r\n\r\n",
                &format!("0\r\n\r\n{smuggled}"),
            ),
        ),
        // Bare-LF line endings framing a smuggled request.
        (
            "bare-lf",
            format!(
                "POST / HTTP/1.1\nHost: example.com\nContent-Length: 0\nTransfer-Encoding: chunked\n\n0\n\nGET /{MARKER} HTTP/1.1\nHost: example.com\n\n"
            ),
        ),
        // HTTP/1.0 carrying Transfer-Encoding.
        (
            "http10-te",
            format!(
                "POST / HTTP/1.0\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n{smuggled}"
            ),
        ),
        // Underscore header names (Rook rejects by design; Caddy passes).
        (
            "underscore-headers",
            format!("GET / HTTP/1.1\r\nHost: example.com\r\nX_Forwarded_For: 10.0.0.1\r\n\r\n"),
        ),
        // Absolute-form request target to a foreign authority. Marker-
        // free on purpose: forwarding an absolute-form request is a
        // correctness question, not smuggling; the corpus assertion
        // only fires on the MARKER.
        (
            "absolute-form",
            "GET http://other.invalid/ HTTP/1.1\r\nHost: example.com\r\n\r\n".to_string(),
        ),
    ]
}

#[tokio::test]
async fn smuggling_corpus_never_reaches_the_upstream() {
    // Each proxy fronts its OWN capturing upstream: the property under
    // test is per-proxy. (Sharing one would conflate a Caddy pipeline
    // artifact with a Rook leak.)
    let (rook_upstream, mut rook_rx) = spawn_capture_upstream().await;
    let (caddy_upstream, mut caddy_rx) = spawn_capture_upstream().await;
    let (rook_addr, _rook) = spawn_rook(rook_upstream).await;
    let caddy = spawn_caddy(caddy_upstream);
    // A missing Caddy must not fail silently: a green "differential"
    // run that compared against nothing is worse than a red one (Harry,
    // review of PR #9). Skip only with an explicit opt-out.
    if caddy.is_none() {
        assert!(
            std::env::var_os("ROOK_DIFFERENTIAL_NO_CADDY").is_some(),
            "caddy not on PATH; set ROOK_DIFFERENTIAL_NO_CADDY=1 to run rook-only"
        );
        eprintln!(
            "differential: caddy not on PATH — caddy half SKIPPED (ROOK_DIFFERENTIAL_NO_CADDY)"
        );
    }
    if let Some((addr, _)) = &caddy {
        assert!(
            wait_for_port(*addr, IO_TIMEOUT).await,
            "caddy did not come up"
        );
    }

    // (name, rook status, caddy status) for the report.
    let mut table: Vec<(&str, Option<u16>, Option<u16>)> = Vec::new();
    for (name, raw) in corpus() {
        let rook_status = send_raw(rook_addr, &raw).await;
        let caddy_status = match &caddy {
            Some((addr, _)) => send_raw(*addr, &raw).await,
            None => None,
        };
        table.push((name, rook_status, caddy_status));
    }

    // Give any in-flight upstream delivery a moment, then drain both
    // the parsed requests and the raw teed bytes.
    sleep(Duration::from_millis(300)).await;
    let mut rook_seen = Vec::new();
    let mut rook_raw: Vec<u8> = Vec::new();
    while let Ok(event) = rook_rx.try_recv() {
        match event {
            UpstreamEvent::Raw(bytes) => rook_raw.extend_from_slice(&bytes),
            UpstreamEvent::Request(request) => rook_seen.push(request),
        }
    }
    let mut caddy_seen = Vec::new();
    while let Ok(event) = caddy_rx.try_recv() {
        if let UpstreamEvent::Request(request) = event {
            caddy_seen.push(request);
        }
    }

    // The property, on both views: no marker Rook rejected ever reaches
    // its upstream — not as a parsed request, and not as raw bytes that
    // never formed one (which is exactly how a desync would surface).
    for request in &rook_seen {
        assert!(
            !request.mentions_marker(),
            "rook's upstream received smuggled content: {:?}",
            request.head
        );
    }
    assert!(
        !contains_marker(&rook_raw),
        "rook's upstream received marker bytes in the raw stream"
    );
    // Rook is deliberately strict: every ambiguous entry is refused
    // outright rather than normalized-and-forwarded.
    for (name, rook_status, _) in &table {
        let expected = if *name == "clean-get" { 200 } else { 400 };
        assert_eq!(
            *rook_status,
            Some(expected),
            "{name}: rook should answer {expected}"
        );
    }
    // Harness sanity: the control request did reach Rook's upstream, so
    // an empty capture can't mask a broken harness.
    assert!(
        rook_seen.iter().any(|r| r.head.starts_with("GET / HTTP")),
        "harness sanity: rook's upstream saw the clean request: {rook_seen:?}"
    );

    // The Caddy half is the differential record: what the incumbent
    // does with the same bytes (Go normalizes several of these; a
    // pipelined second request from the same client is not a leak).
    eprintln!("differential corpus results (rook / caddy status):");
    for (name, rook_status, caddy_status) in &table {
        eprintln!(
            "  {name:28} rook={} caddy={}",
            rook_status.map_or("-".into(), |s| s.to_string()),
            caddy_status.map_or("n/a".into(), |s| s.to_string())
        );
    }
    for request in &caddy_seen {
        if request.mentions_marker() {
            eprintln!(
                "  note: caddy forwarded marker content as a request: {:?}",
                request.head.lines().next().unwrap_or("")
            );
        }
    }
}

/// Negative control for the raw check (Thomas): send the marker through
/// a request Rook SHOULD accept (an ordinary custom header crosses
/// intact), and prove the raw assertion can see it. Without this, a
/// broken tee would pass the corpus test forever.
#[tokio::test]
async fn raw_marker_check_is_live() {
    let (upstream, mut rx) = spawn_capture_upstream().await;
    let (rook_addr, _rook) = spawn_rook(upstream).await;

    let status = send_raw(
        rook_addr,
        &format!("GET / HTTP/1.1\r\nHost: example.com\r\nX-Note: {MARKER}\r\n\r\n"),
    )
    .await;
    assert_eq!(status, Some(200), "rook should accept and forward this");

    sleep(Duration::from_millis(300)).await;
    let mut raw: Vec<u8> = Vec::new();
    while let Ok(event) = rx.try_recv() {
        if let UpstreamEvent::Raw(bytes) = event {
            raw.extend_from_slice(&bytes);
        }
    }
    assert!(
        contains_marker(&raw),
        "raw check could not see a marker that was definitely sent — the tee is blind"
    );
}
