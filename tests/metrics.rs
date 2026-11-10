//! The loopback-only metrics endpoint (plan §8): serves Prometheus text
//! on GET /metrics, refuses everything else, and cannot be reached
//! through the proxy it observes.

use std::{
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use rookd::{config::Config, server};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::{Instant, sleep, timeout},
};

const IO_TIMEOUT: Duration = Duration::from_secs(2);

struct TaskGuard(JoinHandle<()>);

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Rook {
    addr: SocketAddr,
    metrics: SocketAddr,
    _task: TaskGuard,
}

async fn free_addr() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    listener.local_addr().unwrap()
}

/// A minimal upstream that answers 200 with a fixed body.
async fn spawn_upstream() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                let _ = stream.read(&mut buffer).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                    )
                    .await;
            });
        }
    });
    addr
}

fn rook_config(addr: SocketAddr, metrics: SocketAddr, upstream: &str) -> String {
    format!(
        r#"
[server]
listen = "{addr}"
header_read_timeout = 1
request_timeout = 2
idle_timeout = 1
upstream_connect_timeout = 1
shutdown_drain = 1

[metrics]
enabled = true
listen = "{metrics}"

[[sites]]
hosts = ["example.com"]

[[sites.routes]]
prefix = "/"
upstreams = ["{upstream}"]
"#
    )
}

async fn wait_for(addr: SocketAddr, task: &JoinHandle<()>) -> bool {
    let deadline = Instant::now() + IO_TIMEOUT;
    loop {
        if task.is_finished() {
            return false;
        }
        if let Ok(Ok(stream)) = timeout(Duration::from_millis(50), TcpStream::connect(addr)).await {
            drop(stream);
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        sleep(Duration::from_millis(10)).await;
    }
}

async fn spawn_rook(config: String, addr: SocketAddr, metrics: SocketAddr) -> Rook {
    let config = Config::parse(&config).unwrap();
    let task = tokio::spawn(async move {
        server::run(config).await.unwrap();
    });
    assert!(wait_for(addr, &task).await, "main listener did not come up");
    assert!(
        wait_for(metrics, &task).await,
        "metrics listener did not come up"
    );
    Rook {
        addr,
        metrics,
        _task: TaskGuard(task),
    }
}

fn get(
    addr: SocketAddr,
    host: &str,
    path: &str,
) -> impl Future<Output = (u16, Option<String>, String)> {
    let request = format!("GET {path} HTTP/1.1\r\nhost: {host}\r\nconnection: close\r\n\r\n");
    async move { request_addr(addr, &request).await }
}

/// One raw HTTP/1.1 exchange; returns (status, content-type, body).
async fn request_addr(addr: SocketAddr, raw: &str) -> (u16, Option<String>, String) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(raw.as_bytes()).await.unwrap();
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let read = timeout(IO_TIMEOUT, stream.read(&mut chunk))
            .await
            .expect("timed out reading HTTP head")
            .unwrap();
        assert!(read > 0, "connection closed before a response head");
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(end) = find_subslice(&buffer, b"\r\n\r\n") {
            break end + 4;
        }
    };
    let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap();
    let content_type = head
        .lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        })
        .map(|(_, value)| value.trim().to_owned());
    let content_length: usize = head
        .lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        })
        .and_then(|(_, value)| value.trim().parse().ok())
        .unwrap_or(0);
    while buffer.len() < head_end + content_length {
        let read = timeout(IO_TIMEOUT, stream.read(&mut chunk))
            .await
            .expect("timed out reading HTTP body")
            .unwrap();
        assert!(read > 0, "connection closed mid-body");
        buffer.extend_from_slice(&chunk[..read]);
    }
    let body = String::from_utf8_lossy(&buffer[head_end..head_end + content_length]).into_owned();
    (status, content_type, body)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[tokio::test]
async fn serves_prometheus_text_on_get_metrics() {
    let upstream = spawn_upstream().await;
    let addr = free_addr().await;
    let metrics = free_addr().await;
    let rook = spawn_rook(
        rook_config(addr, metrics, &format!("http://{upstream}")),
        addr,
        metrics,
    )
    .await;

    // One proxied request, so the scrape has something to count.
    let (status, _, body) = get(rook.addr, "example.com", "/").await;
    assert_eq!(status, 200);
    assert_eq!(body, "ok");

    let (status, content_type, body) = get(rook.metrics, "localhost", "/metrics").await;
    assert_eq!(status, 200);
    assert_eq!(
        content_type.as_deref(),
        Some("text/plain; version=0.0.4; charset=utf-8")
    );
    assert!(body.contains("rook_requests_total 1"), "{body}");
    assert!(
        body.contains("rook_responses_total{class=\"2xx\"} 1"),
        "{body}"
    );
    assert!(
        body.contains("rook_connections_accepted_total{listener=\"http\"}"),
        "{body}"
    );
    assert!(body.contains("rook_strikes_total"), "{body}");
}

#[tokio::test]
async fn anything_but_get_metrics_is_not_found_or_refused() {
    let upstream = spawn_upstream().await;
    let addr = free_addr().await;
    let metrics = free_addr().await;
    let rook = spawn_rook(
        rook_config(addr, metrics, &format!("http://{upstream}")),
        addr,
        metrics,
    )
    .await;

    let (status, _, body) = get(rook.metrics, "localhost", "/").await;
    assert_eq!(status, 404);
    assert!(body.is_empty(), "{body}");

    let (status, _, _) = request_addr(
        rook.metrics,
        "POST /metrics HTTP/1.1\r\nhost: localhost\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 405);
}

#[tokio::test]
async fn scrapes_carrying_forwarding_headers_are_refused() {
    // Thomas's guard: a direct scrape never has Forwarded/X-Forwarded-*;
    // their presence means the request came through a proxy.
    let upstream = spawn_upstream().await;
    let addr = free_addr().await;
    let metrics = free_addr().await;
    let rook = spawn_rook(
        rook_config(addr, metrics, &format!("http://{upstream}")),
        addr,
        metrics,
    )
    .await;

    for header in [
        "x-forwarded-for: 203.0.113.9",
        "x-forwarded-proto: https",
        "forwarded: for=203.0.113.9",
    ] {
        let (status, _, body) = request_addr(
            rook.metrics,
            &format!(
                "GET /metrics HTTP/1.1\r\nhost: localhost\r\n{header}\r\nconnection: close\r\n\r\n"
            ),
        )
        .await;
        assert_eq!(status, 403, "header {header:?}");
        assert!(body.is_empty(), "{body}");
    }
}

#[tokio::test]
async fn the_metrics_listener_caps_concurrent_connections() {
    // Harry's finding: loopback limits who can scrape, not how many.
    // Hold every slot, then prove the next connection is refused and
    // that a freed slot serves again.
    let upstream = spawn_upstream().await;
    let addr = free_addr().await;
    let metrics = free_addr().await;
    let rook = spawn_rook(
        rook_config(addr, metrics, &format!("http://{upstream}")),
        addr,
        metrics,
    )
    .await;

    let mut held = Vec::new();
    for _ in 0..rookd::server::MAX_METRICS_CONNECTIONS {
        held.push(TcpStream::connect(rook.metrics).await.unwrap());
    }
    // Let the accept loop account the held set before probing.
    sleep(Duration::from_millis(50)).await;

    let mut extra = TcpStream::connect(rook.metrics).await.unwrap();
    extra
        .write_all(b"GET /metrics HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut body = Vec::new();
    // A refused connection is dropped with our request still unread in
    // its receive buffer, which surfaces as EOF-with-no-data or as a
    // reset; a timeout would mean it was served (held open).
    let refused = match timeout(IO_TIMEOUT, extra.read_to_end(&mut body)).await {
        Ok(Ok(_)) => body.is_empty(),
        Ok(Err(error)) => error.kind() == std::io::ErrorKind::ConnectionReset,
        Err(_) => false,
    };
    assert!(refused, "over-cap connection was served: {body:?}");

    // A freed slot serves again.
    drop(held);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Ok(stream) = TcpStream::connect(rook.metrics).await {
            drop(stream);
            let (status, _, _) = get(rook.metrics, "localhost", "/metrics").await;
            if status == 200 {
                break;
            }
        }
        assert!(Instant::now() < deadline, "listener never served again");
        sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn the_proxy_cannot_dial_the_metrics_listener() {
    // The config-load check covers IP-literal upstreams; a hostname that
    // resolves to the listener later (here: localhost, on the metrics
    // port) is refused by the connector at connect time.
    let addr = free_addr().await;
    let metrics = free_addr().await;
    let config = rook_config(
        addr,
        metrics,
        &format!("http://localhost:{}", metrics.port()),
    );
    let rook = spawn_rook(config, addr, metrics).await;

    let (status, _, _) = request_addr(
        rook.addr,
        "GET / HTTP/1.1\r\nhost: example.com\r\nconnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 502);

    // The refusal is visible to the operator, not silent.
    let (_, _, body) = get(rook.metrics, "localhost", "/metrics").await;
    assert!(body.contains("rook_upstream_failures_total 1"), "{body}");
    // And the scrape proves the listener itself still answers direct
    // scrapes: the guard never blocked it.
    assert!(body.contains("rook_requests_total 1"), "{body}");
}
