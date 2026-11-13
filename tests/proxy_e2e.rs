use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

#[cfg(unix)]
use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rookd::{
    config::Config,
    proxy::{AppState, RequestScheme},
    server,
};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, pem::PemObject},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::{Instant, sleep, timeout},
};
use tokio_rustls::{TlsConnector, client::TlsStream};

const IO_TIMEOUT: Duration = Duration::from_secs(2);
const TLS13_VERSIONS: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
const TLS12_VERSIONS: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];
const WEBSOCKET_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const WEBSOCKET_ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
const CLIENT_BYTES: &[u8] = b"client-to-upstream";
const UPSTREAM_BYTES: &[u8] = b"upstream-to-client";

struct TaskGuard(JoinHandle<()>);

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct StalledBody {
    sent: bool,
}

impl hyper::body::Body for StalledBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        if self.sent {
            return std::task::Poll::Pending;
        }
        self.sent = true;
        std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(Bytes::from_static(
            b"abc",
        )))))
    }

    fn is_end_stream(&self) -> bool {
        false
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        let mut hint = hyper::body::SizeHint::new();
        hint.set_exact(1_000_000);
        hint
    }
}

struct RookServer {
    addr: SocketAddr,
    _task: TaskGuard,
}

#[derive(Debug)]
struct RequestHead {
    request_line: String,
    headers: Vec<(String, String)>,
}

impl RequestHead {
    fn header_values(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .collect()
    }
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    raw_head: String,
    leftover: Vec<u8>,
}

impl HttpResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

async fn free_addr() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    listener.local_addr().unwrap()
}

fn rook_config(
    addr: SocketAddr,
    upstreams: &[SocketAddr],
    server_settings: &str,
    route_settings: &str,
) -> String {
    rook_config_site(addr, upstreams, server_settings, "", route_settings)
}

fn rook_config_site(
    addr: SocketAddr,
    upstreams: &[SocketAddr],
    server_settings: &str,
    site_settings: &str,
    route_settings: &str,
) -> String {
    let upstreams = upstreams
        .iter()
        .map(|addr| format!("\"http://{addr}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let header_read_timeout = if server_settings.contains("header_read_timeout") {
        ""
    } else {
        "header_read_timeout = 1\n"
    };
    let idle_timeout = if server_settings.contains("idle_timeout") {
        ""
    } else {
        "idle_timeout = 1\n"
    };
    let request_timeout = if server_settings.contains("request_timeout") {
        ""
    } else {
        "request_timeout = 2\n"
    };
    format!(
        r#"
[server]
listen = "{addr}"
{header_read_timeout}{request_timeout}upstream_connect_timeout = 1
{idle_timeout}websocket_idle_timeout = 2
websocket_max_lifetime = 5
shutdown_drain = 1
{server_settings}

[[sites]]
hosts = ["example.com"]
{site_settings}

[[sites.routes]]
prefix = "/"
upstreams = [{upstreams}]
{route_settings}
"#
    )
}

async fn spawn_rook(
    upstreams: &[SocketAddr],
    server_settings: &str,
    route_settings: &str,
) -> RookServer {
    spawn_rook_site(upstreams, server_settings, "", route_settings).await
}

async fn spawn_rook_site(
    upstreams: &[SocketAddr],
    server_settings: &str,
    site_settings: &str,
    route_settings: &str,
) -> RookServer {
    for _ in 0..5 {
        let addr = free_addr().await;
        let input = rook_config_site(
            addr,
            upstreams,
            server_settings,
            site_settings,
            route_settings,
        );
        let config = Config::parse(&input).unwrap();
        let task = tokio::spawn(async move {
            server::run(config).await.unwrap();
        });
        let deadline = Instant::now() + IO_TIMEOUT;
        loop {
            if task.is_finished() {
                let _ = task.await;
                break;
            }
            if let Ok(Ok(stream)) =
                timeout(Duration::from_millis(50), TcpStream::connect(addr)).await
            {
                drop(stream);
                sleep(Duration::from_millis(10)).await;
                if task.is_finished() {
                    let _ = task.await;
                    break;
                }
                return RookServer {
                    addr,
                    _task: TaskGuard(task),
                };
            }
            if Instant::now() >= deadline {
                task.abort();
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    }
    panic!("Rook could not bind a free loopback port after five attempts");
}

struct TestCertificate {
    _directory: tempfile::TempDir,
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
    certificate: CertificateDer<'static>,
}

impl TestCertificate {
    fn generate(host: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let cert_path = directory.path().join("certificate.pem");
        let key_path = directory.path().join("key.pem");
        let output = std::process::Command::new("openssl")
            .args([
                "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "1", "-nodes", "-subj",
            ])
            .arg(format!("/CN={host}"))
            .arg("-addext")
            .arg(format!("subjectAltName=DNS:{host}"))
            .arg("-addext")
            .arg("basicConstraints=critical,CA:FALSE")
            .arg("-keyout")
            .arg(&key_path)
            .arg("-out")
            .arg(&cert_path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "openssl failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let certificate = CertificateDer::from_pem_file(&cert_path).unwrap();
        Self {
            _directory: directory,
            cert_path,
            key_path,
            certificate,
        }
    }

    fn generate_expired(host: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let cert_path = directory.path().join("certificate.pem");
        let key_path = directory.path().join("key.pem");
        let csr_path = directory.path().join("request.csr");
        let output = std::process::Command::new("openssl")
            .args([
                "req", "-new", "-newkey", "rsa:2048", "-sha256", "-nodes", "-subj",
            ])
            .arg(format!("/CN={host}"))
            .arg("-addext")
            .arg(format!("subjectAltName=DNS:{host}"))
            .arg("-keyout")
            .arg(&key_path)
            .arg("-out")
            .arg(&csr_path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "openssl CSR failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let new_certs = directory.path().join("newcerts");
        std::fs::create_dir(&new_certs).unwrap();
        let index = directory.path().join("index.txt");
        let serial = directory.path().join("serial");
        std::fs::write(&index, "").unwrap();
        std::fs::write(&serial, "01\n").unwrap();
        let ca_config = directory.path().join("ca.cnf");
        std::fs::write(
            &ca_config,
            format!(
                "[ ca ]\ndefault_ca = testca\n[ testca ]\ndatabase = {}\nnew_certs_dir = {}\nserial = {}\ndefault_md = sha256\ncopy_extensions = copy\npolicy = policy\n[ policy ]\ncommonName = supplied\n",
                index.display(),
                new_certs.display(),
                serial.display()
            ),
        )
        .unwrap();
        let output = std::process::Command::new("openssl")
            .args(["ca", "-selfsign", "-keyfile"])
            .arg(&key_path)
            .arg("-in")
            .arg(&csr_path)
            .arg("-out")
            .arg(&cert_path)
            .args([
                "-startdate",
                "20200101000000Z",
                "-enddate",
                "20210101000000Z",
                "-config",
            ])
            .arg(&ca_config)
            .arg("-batch")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "openssl expired certificate failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let certificate = CertificateDer::from_pem_file(&cert_path).unwrap();
        Self {
            _directory: directory,
            cert_path,
            key_path,
            certificate,
        }
    }
}

fn tls_client_config(
    certificates: &[&TestCertificate],
    versions: &'static [&'static rustls::SupportedProtocolVersion],
    alpn: &[&[u8]],
) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots.add(certificate.certificate.clone()).unwrap();
    }
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(versions)
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    Arc::new(config)
}

async fn connect_tls(
    addr: SocketAddr,
    host: &str,
    config: Arc<ClientConfig>,
) -> std::io::Result<TlsStream<TcpStream>> {
    let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    let stream = TcpStream::connect(addr).await?;
    TlsConnector::from(config)
        .connect(server_name, stream)
        .await
}

async fn send_tls_http1(
    addr: SocketAddr,
    host: &str,
    config: Arc<ClientConfig>,
    request: &str,
) -> HttpResponse {
    let mut stream = timeout(IO_TIMEOUT, connect_tls(addr, host, config))
        .await
        .expect("TLS handshake timed out")
        .unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    read_response(&mut stream).await
}

fn peer_certificate(stream: &TlsStream<TcpStream>) -> Vec<u8> {
    stream
        .get_ref()
        .1
        .peer_certificates()
        .unwrap()
        .first()
        .unwrap()
        .as_ref()
        .to_vec()
}

async fn read_h2_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> std::io::Result<(u8, u8, u32, Vec<u8>)> {
    let mut header = [0; 9];
    stream.read_exact(&mut header).await?;
    let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
    if length > 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "HTTP/2 frame exceeded test limit",
        ));
    }
    let stream_id = u32::from_be_bytes([header[5] & 0x7f, header[6], header[7], header[8]]);
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).await?;
    Ok((header[3], header[4], stream_id, payload))
}

async fn write_h2_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: &[u8],
) -> std::io::Result<()> {
    let length = payload.len() as u32;
    let header = [
        ((length >> 16) & 0xff) as u8,
        ((length >> 8) & 0xff) as u8,
        (length & 0xff) as u8,
        frame_type,
        flags,
        ((stream_id >> 24) & 0x7f) as u8,
        ((stream_id >> 16) & 0xff) as u8,
        ((stream_id >> 8) & 0xff) as u8,
        (stream_id & 0xff) as u8,
    ];
    stream.write_all(&header).await?;
    stream.write_all(payload).await
}

async fn drive_h2_until_close<S>(stream: &mut S) -> usize
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut pings = 0;
    loop {
        let frame = match timeout(Duration::from_secs(3), read_h2_frame(stream)).await {
            Ok(Ok(frame)) => frame,
            Ok(Err(_)) => break,
            Err(_) => panic!("HTTP/2 connection did not close at its idle deadline"),
        };
        match frame {
            (6, 0, 0, payload) => {
                pings += 1;
                if write_h2_frame(stream, 6, 1, 0, &payload).await.is_err() {
                    break;
                }
            }
            (4, 0, 0, _) if write_h2_frame(stream, 4, 1, 0, &[]).await.is_err() => {
                break;
            }
            _ => {}
        }
    }
    pings
}

struct HttpsRook {
    http_addr: SocketAddr,
    https_addr: SocketAddr,
    _task: TaskGuard,
}

async fn spawn_https_rook(
    upstream: SocketAddr,
    certificate: &TestCertificate,
    server_settings: &str,
) -> HttpsRook {
    let http_addr = free_addr().await;
    let https_addr = free_addr().await;
    let settings = format!("https_listen = \"{https_addr}\"\n{server_settings}");
    let input = rook_config(http_addr, &[upstream], &settings, "").replace(
        "hosts = [\"example.com\"]",
        &format!(
            "hosts = [\"example.com\"]\ntls_cert = \"{}\"\ntls_key = \"{}\"",
            certificate.cert_path.display(),
            certificate.key_path.display()
        ),
    );
    let config = Config::parse(&input).unwrap();
    let task = tokio::spawn(async move {
        server::run(config).await.unwrap();
    });
    for addr in [http_addr, https_addr] {
        let deadline = Instant::now() + IO_TIMEOUT;
        loop {
            assert!(
                !task.is_finished(),
                "Rook exited before listening on {addr}"
            );
            if let Ok(Ok(stream)) =
                timeout(Duration::from_millis(50), TcpStream::connect(addr)).await
            {
                drop(stream);
                break;
            }
            assert!(Instant::now() < deadline, "Rook did not listen on {addr}");
            sleep(Duration::from_millis(10)).await;
        }
    }
    HttpsRook {
        http_addr,
        https_addr,
        _task: TaskGuard(task),
    }
}

async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> (Vec<u8>, Vec<u8>) {
    let mut bytes = Vec::new();
    let mut buffer = [0; 1024];
    loop {
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let end = position + 4;
            let leftover = bytes.split_off(end);
            return (bytes, leftover);
        }
        let read = timeout(IO_TIMEOUT, stream.read(&mut buffer))
            .await
            .expect("timed out reading HTTP headers")
            .unwrap();
        assert!(read > 0, "connection closed before HTTP headers completed");
        bytes.extend_from_slice(&buffer[..read]);
        assert!(bytes.len() <= 64 * 1024, "HTTP headers exceeded test limit");
    }
}

fn parse_headers(head: &str) -> Vec<(String, String)> {
    head.split("\r\n")
        .skip(1)
        .filter(|line| !line.is_empty())
        .map(|line| {
            let (name, value) = line.split_once(':').unwrap();
            (name.to_ascii_lowercase(), value.trim().to_owned())
        })
        .collect()
}

async fn read_response<S: AsyncRead + Unpin>(stream: &mut S) -> HttpResponse {
    let (head, mut leftover) = read_head(stream).await;
    let raw_head = String::from_utf8(head).unwrap();
    let status = raw_head
        .split("\r\n")
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = parse_headers(&raw_head);
    let content_length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .map(|(_, value)| value.parse::<usize>().unwrap())
        .unwrap_or(0);
    let mut body = Vec::new();
    if leftover.len() >= content_length {
        body.extend_from_slice(&leftover[..content_length]);
        leftover.drain(..content_length);
    } else {
        let buffered = leftover.len();
        body.append(&mut leftover);
        body.resize(content_length, 0);
        timeout(IO_TIMEOUT, stream.read_exact(&mut body[buffered..]))
            .await
            .expect("timed out reading HTTP body")
            .unwrap();
    }
    HttpResponse {
        status,
        headers,
        body,
        raw_head,
        leftover,
    }
}

async fn send_bytes(addr: SocketAddr, request: &[u8]) -> HttpResponse {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(request).await.unwrap();
    read_response(&mut stream).await
}

async fn send_request(addr: SocketAddr, request: &str) -> HttpResponse {
    send_bytes(addr, request.as_bytes()).await
}

fn parse_request(head: Vec<u8>) -> RequestHead {
    let head = String::from_utf8(head).unwrap();
    RequestHead {
        request_line: head.split("\r\n").next().unwrap().to_owned(),
        headers: parse_headers(&head),
    }
}

async fn spawn_capture_upstream(
    response: String,
) -> (SocketAddr, oneshot::Receiver<RequestHead>, TaskGuard) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (request_tx, request_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (head, _) = read_head(&mut stream).await;
        request_tx.send(parse_request(head)).unwrap();
        stream.write_all(response.as_bytes()).await.unwrap();
    });
    (addr, request_rx, TaskGuard(task))
}

async fn spawn_identity_upstream(identity: &'static str) -> (SocketAddr, TaskGuard) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = read_head(&mut stream).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nX-Upstream: {identity}\r\nConnection: close\r\n\r\n{identity}",
                identity.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    });
    (addr, TaskGuard(task))
}

async fn spawn_recording_upstream() -> (SocketAddr, mpsc::UnboundedReceiver<RequestHead>, TaskGuard)
{
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (request_tx, request_rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (head, _) = read_head(&mut stream).await;
            request_tx.send(parse_request(head)).unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        }
    });
    (addr, request_rx, TaskGuard(task))
}

async fn spawn_websocket_hold_upstream() -> (SocketAddr, TaskGuard) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (mut stream, _) = accepted.unwrap();
                    connections.spawn(async move {
                        let _ = read_head(&mut stream).await;
                        let response = format!(
                            "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {WEBSOCKET_ACCEPT}\r\n\r\n"
                        );
                        stream.write_all(response.as_bytes()).await.unwrap();
                        let mut buffer = [0; 1024];
                        while let Ok(read) = stream.read(&mut buffer).await {
                            if read == 0 {
                                break;
                            }
                        }
                    });
                }
                completed = connections.join_next(), if !connections.is_empty() => {
                    completed.unwrap().unwrap();
                }
            }
        }
    });
    (addr, TaskGuard(task))
}

async fn open_websocket(addr: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(websocket_request("/held").as_bytes())
        .await
        .unwrap();
    let response = read_response(&mut stream).await;
    assert_eq!(response.status, 101, "{}", response.raw_head);
    stream
}

async fn assert_connection_closed<S: AsyncRead + Unpin>(stream: &mut S) {
    let mut byte = [0; 1];
    match timeout(IO_TIMEOUT, stream.read(&mut byte)).await {
        Ok(Ok(0)) => {}
        Ok(Ok(read)) => panic!("connection returned {read} bytes instead of closing"),
        Ok(Err(error))
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
            ) => {}
        Ok(Err(error)) => panic!("unexpected error while waiting for close: {error}"),
        Err(_) => panic!("connection remained open"),
    }
}

async fn spawn_stalled_response_upstream() -> (SocketAddr, TaskGuard) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _ = read_head(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc")
            .await
            .unwrap();
        sleep(Duration::from_secs(5)).await;
    });
    (addr, TaskGuard(task))
}

async fn spawn_upload_upstream() -> (SocketAddr, TaskGuard) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (_, leftover) = read_head(&mut stream).await;
        let buffered = leftover.len();
        let mut body = leftover;
        body.resize(12, 0);
        stream.read_exact(&mut body[buffered..]).await.unwrap();
        assert_eq!(body, b"abcdefghijkl");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
    });
    (addr, TaskGuard(task))
}

async fn spawn_never_responding_upstream() -> (SocketAddr, TaskGuard) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (_, leftover) = read_head(&mut stream).await;
        let buffered = leftover.len();
        let mut body = leftover;
        body.resize(4, 0);
        stream.read_exact(&mut body[buffered..]).await.unwrap();
        assert_eq!(body, b"test");
        sleep(Duration::from_secs(5)).await;
    });
    (addr, TaskGuard(task))
}

async fn spawn_stalled_large_upload_upstream() -> (SocketAddr, TaskGuard) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.unwrap();
        let (_, leftover) = read_head(&mut first).await;
        let buffered = leftover.len();
        let mut body = leftover;
        body.resize(3, 0);
        first.read_exact(&mut body[buffered..]).await.unwrap();
        assert_eq!(body, b"abc");
        tokio::spawn(async move {
            sleep(Duration::from_secs(5)).await;
            drop(first);
        });

        let (mut second, _) = listener.accept().await.unwrap();
        let _ = read_head(&mut second).await;
        second
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
    });
    (addr, TaskGuard(task))
}

async fn send_tls_http1_upload(addr: SocketAddr, config: Arc<ClientConfig>) -> HttpResponse {
    let mut stream = timeout(IO_TIMEOUT, connect_tls(addr, "example.com", config))
        .await
        .unwrap()
        .unwrap();
    stream
        .write_all(b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 12\r\n\r\n")
        .await
        .unwrap();
    for chunk in [b"abc".as_slice(), b"def", b"ghi", b"jkl"] {
        sleep(Duration::from_millis(400)).await;
        stream.write_all(chunk).await.unwrap();
    }
    read_response(&mut stream).await
}

#[cfg(unix)]
struct ChildRook {
    addr: SocketAddr,
    child: Child,
    logs: mpsc::UnboundedReceiver<String>,
    _config_dir: tempfile::TempDir,
}

#[cfg(unix)]
impl Drop for ChildRook {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(unix)]
async fn spawn_rook_child(upstream: SocketAddr, low_fd_limit: bool) -> ChildRook {
    let addr = free_addr().await;
    let config_dir = tempfile::tempdir().unwrap();
    let config_path = config_dir.path().join("rookd.toml");
    // Under the low fd limit the default config's worst-case budget
    // (4096 + 1024 + listeners) far exceeds 90% of 24 and would refuse
    // to start — which is the budget check doing its job. This test
    // exists for the runtime EMFILE path, so its config passes the
    // check (12 + 4 + 1 = 17 <= 21) while the runtime table still
    // fills: baseline ~11 descriptors plus 12 client connections
    // exceeds 24 before the cap engages.
    let settings = if low_fd_limit {
        "max_connections = 12\nmax_connections_per_upstream = 4\nupstream_pool_idle = 2\n"
    } else {
        ""
    };
    std::fs::write(&config_path, rook_config(addr, &[upstream], settings, "")).unwrap();
    let binary = env!("CARGO_BIN_EXE_rookd");
    let mut command = if low_fd_limit {
        let descriptors = (3..=9)
            .map(|fd| format!("exec {fd}</dev/null\n"))
            .collect::<String>();
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(format!(
                "ulimit -n 24 || exit 1\n{descriptors}exec \"$0\" --config \"$1\""
            ))
            .arg(binary)
            .arg(&config_path);
        command
    } else {
        let mut command = Command::new(binary);
        command.arg("--config").arg(&config_path);
        command
    };
    command
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (log_tx, logs) = mpsc::unbounded_channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = log_tx.send(line);
        }
    });
    ChildRook {
        addr,
        child,
        logs,
        _config_dir: config_dir,
    }
}

#[cfg(unix)]
async fn wait_for_child_log(child: &mut ChildRook, expected: &str) {
    timeout(Duration::from_secs(3), async {
        while let Some(line) = child.logs.recv().await {
            if line.contains(expected) {
                return;
            }
        }
        panic!("child log stream ended before {expected:?}");
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for child log {expected:?}"));
}

#[cfg(unix)]
async fn wait_for_child_exit(child: &mut Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(Instant::now() < deadline, "child did not exit after signal");
        sleep(Duration::from_millis(10)).await;
    }
}

fn assert_error_response(response: &HttpResponse, status: u16, upstream: SocketAddr) {
    assert_eq!(response.status, status, "{}", response.raw_head);
    assert!(response.body.is_empty(), "error exposed a response body");
    assert!(response.header("x-upstream").is_none());
    let exposed = format!(
        "{}{}",
        response.raw_head,
        String::from_utf8_lossy(&response.body)
    );
    assert!(
        !exposed.contains(&upstream.to_string()),
        "error exposed upstream address: {exposed}"
    );
    assert!(
        !exposed.to_ascii_lowercase().contains("upstream"),
        "error exposed upstream details: {exposed}"
    );
}

fn websocket_request(path: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {WEBSOCKET_KEY}\r\n\r\n"
    )
}

enum WebSocketBehavior {
    Tunnel,
    Reject,
    InvalidAccept,
}

async fn spawn_websocket_upstream(
    behavior: WebSocketBehavior,
) -> (SocketAddr, oneshot::Receiver<RequestHead>, TaskGuard) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (request_tx, request_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (head, _) = read_head(&mut stream).await;
        request_tx.send(parse_request(head)).unwrap();
        match behavior {
            WebSocketBehavior::Tunnel => {
                let response = format!(
                    "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {WEBSOCKET_ACCEPT}\r\n\r\n"
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                let mut received = vec![0; CLIENT_BYTES.len()];
                timeout(IO_TIMEOUT, stream.read_exact(&mut received))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(received, CLIENT_BYTES);
                stream.write_all(UPSTREAM_BYTES).await.unwrap();
            }
            WebSocketBehavior::Reject => {
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nX-Upstream: rejected\r\nConnection: close\r\n\r\nnot-a-ws",
                    )
                    .await
                    .unwrap();
            }
            WebSocketBehavior::InvalidAccept => {
                stream
                    .write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: invalid\r\n\r\nRAW-TUNNEL-LEAK",
                    )
                    .await
                    .unwrap();
            }
        }
    });
    (addr, request_rx, TaskGuard(task))
}

#[tokio::test]
async fn forwards_normalized_path_original_query_host_and_direct_client_ip() {
    let (upstream, request_rx, _upstream_task) = spawn_capture_upstream(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_owned(),
    )
    .await;
    let rook = spawn_rook(&[upstream], "", "").await;
    let response = send_request(
        rook.addr,
        "GET /%61dmin?next=%2f&letter=%61&&= HTTP/1.1\r\nHost: Example.COM\r\nX-Real-IP: 203.0.113.1:1234\r\nX-Forwarded-For: 198.51.100.2:5678\r\nX-Forwarded-Proto: https\r\n\r\n",
    )
    .await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"ok");

    let request = timeout(IO_TIMEOUT, request_rx).await.unwrap().unwrap();
    assert_eq!(
        request.request_line,
        "GET /admin?next=%2f&letter=%61&&= HTTP/1.1"
    );
    assert_eq!(request.header_values("host"), ["Example.COM"]);
    assert_eq!(request.header_values("x-real-ip"), ["127.0.0.1"]);
    assert_eq!(request.header_values("x-forwarded-for"), ["127.0.0.1"]);
    assert_eq!(request.header_values("x-forwarded-proto"), ["http"]);
}

#[tokio::test]
async fn strips_upstream_disclosure_headers_by_default() {
    let (upstream, _request_rx, _upstream_task) = spawn_capture_upstream(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nServer: SimpleHTTP/0.6 Python/3.12.15\r\nX-Powered-By: PHP/8.1\r\nX-Upstream: kept\r\nConnection: close\r\n\r\nok".to_owned(),
    )
    .await;
    let rook = spawn_rook(&[upstream], "", "").await;
    let response = send_request(rook.addr, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"ok");
    assert_eq!(response.header("server"), None);
    assert_eq!(response.header("x-powered-by"), None);
    // An ordinary upstream header is not disclosure: it survives.
    assert_eq!(response.header("x-upstream"), Some("kept"));
}

#[tokio::test]
async fn preserve_upstream_headers_keeps_only_the_named_headers() {
    let (upstream, _request_rx, _upstream_task) = spawn_capture_upstream(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nServer: my-app/1.0\r\nX-Powered-By: PHP/8.1\r\nConnection: close\r\n\r\nok".to_owned(),
    )
    .await;
    let rook = spawn_rook_site(
        &[upstream],
        "",
        "preserve_upstream_headers = [\"server\"]",
        "",
    )
    .await;
    let response = send_request(rook.addr, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.header("server"), Some("my-app/1.0"));
    // The opt-out names headers one by one: x-powered-by still strips.
    assert_eq!(response.header("x-powered-by"), None);
}

#[tokio::test]
async fn round_robins_across_two_upstream_identities() {
    let (first, _first_task) = spawn_identity_upstream("first").await;
    let (second, _second_task) = spawn_identity_upstream("second").await;
    let rook = spawn_rook(&[first, second], "", "").await;

    for expected in ["first", "second", "first", "second"] {
        let response = send_request(
            rook.addr,
            "GET /balance HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        .await;
        assert_eq!(response.status, 200);
        assert_eq!(response.body, expected.as_bytes());
        assert_eq!(response.header("x-upstream"), Some(expected));
    }
}

#[tokio::test]
async fn rejects_unknown_repeated_and_mismatched_hosts_without_upstream_details() {
    let (upstream, _upstream_task) = spawn_identity_upstream("hidden").await;
    let rook = spawn_rook(&[upstream], "", "").await;
    let cases = [
        ("GET / HTTP/1.1\r\nHost: unknown.example\r\n\r\n", 404),
        (
            "GET / HTTP/1.1\r\nHost: example.com\r\nHost: example.com\r\n\r\n",
            400,
        ),
        (
            "GET http://other.example/admin HTTP/1.1\r\nHost: example.com\r\n\r\n",
            400,
        ),
    ];

    for (request, status) in cases {
        let response = send_request(rook.addr, request).await;
        assert_error_response(&response, status, upstream);
    }
}

#[tokio::test]
async fn rejects_unsafe_paths_without_upstream_details() {
    let (upstream, _upstream_task) = spawn_identity_upstream("hidden").await;
    let rook = spawn_rook(&[upstream], "", "").await;

    for path in [
        "/%2fadmin",
        "/safe/../admin",
        "/safe/%2e%2e/admin",
        "/public/..;/admin",
        "/public/..%3B/admin",
        "/public/..%3b/admin",
        "/admin//x",
    ] {
        let request = format!("GET {path} HTTP/1.1\r\nHost: example.com\r\n\r\n");
        let response = send_request(rook.addr, &request).await;
        assert_error_response(&response, 400, upstream);
    }
}

#[tokio::test]
async fn raw_semicolon_path_parameter_still_routes() {
    let (upstream, mut request_rx, _upstream_task) = spawn_recording_upstream().await;
    let rook = spawn_rook(&[upstream], "", "").await;

    let response = send_request(
        rook.addr,
        "GET /public/foo;jsessionid=abc123 HTTP/1.1\r\nHost: example.com\r\n\r\n",
    )
    .await;
    assert_eq!(response.status, 200);
    let request = timeout(IO_TIMEOUT, request_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        request.request_line,
        "GET /public/foo;jsessionid=abc123 HTTP/1.1"
    );
}

#[tokio::test]
async fn route_rate_limit_returns_429() {
    let (upstream, _upstream_task) = spawn_identity_upstream("limited").await;
    let rook = spawn_rook(
        &[upstream],
        "",
        "requests_per_second = 1\nrequest_burst = 1",
    )
    .await;
    let request = "GET /limited HTTP/1.1\r\nHost: example.com\r\n\r\n";

    let first = send_request(rook.addr, request).await;
    assert_eq!(first.status, 200);
    let second = send_request(rook.addr, request).await;
    assert_error_response(&second, 429, upstream);
}

#[tokio::test]
async fn content_length_above_configured_max_returns_413() {
    let (upstream, _request_rx, _upstream_task) =
        spawn_capture_upstream("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_owned()).await;
    let rook = spawn_rook(&[upstream], "max_request_body_bytes = 4", "").await;
    let response = send_request(
        rook.addr,
        "POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\n12345",
    )
    .await;
    assert_error_response(&response, 413, upstream);
}

#[tokio::test]
async fn unreachable_upstream_returns_503_without_upstream_details() {
    let upstream = free_addr().await;
    let rook = spawn_rook(&[upstream], "", "").await;
    let response = send_request(
        rook.addr,
        "GET /unavailable HTTP/1.1\r\nHost: example.com\r\n\r\n",
    )
    .await;
    // Connect refusal is overload-shaped: 503 + Retry-After (the
    // header is pinned in upstream_connect_refusal_is_503_with_retry_after).
    assert_error_response(&response, 503, upstream);
}

#[tokio::test]
async fn websocket_valid_upgrade_tunnels_raw_bytes_bidirectionally() {
    let (upstream, request_rx, _upstream_task) =
        spawn_websocket_upstream(WebSocketBehavior::Tunnel).await;
    let rook = spawn_rook(&[upstream], "", "websocket = true").await;
    let mut stream = TcpStream::connect(rook.addr).await.unwrap();
    stream
        .write_all(websocket_request("/socket?mode=raw").as_bytes())
        .await
        .unwrap();
    let response = read_response(&mut stream).await;
    assert_eq!(response.status, 101, "{}", response.raw_head);
    assert_eq!(
        response.header("sec-websocket-accept"),
        Some(WEBSOCKET_ACCEPT)
    );
    assert!(response.leftover.is_empty());

    let request = timeout(IO_TIMEOUT, request_rx).await.unwrap().unwrap();
    assert_eq!(request.request_line, "GET /socket?mode=raw HTTP/1.1");
    assert_eq!(request.header_values("sec-websocket-key"), [WEBSOCKET_KEY]);

    stream.write_all(CLIENT_BYTES).await.unwrap();
    let mut received = vec![0; UPSTREAM_BYTES.len()];
    timeout(IO_TIMEOUT, stream.read_exact(&mut received))
        .await
        .expect("timed out reading tunneled upstream bytes")
        .unwrap();
    assert_eq!(received, UPSTREAM_BYTES);
}

#[tokio::test]
async fn websocket_rejected_upgrade_is_returned_as_normal_http() {
    let (upstream, request_rx, _upstream_task) =
        spawn_websocket_upstream(WebSocketBehavior::Reject).await;
    let rook = spawn_rook(&[upstream], "", "websocket = true").await;
    let response = send_request(rook.addr, &websocket_request("/socket")).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.header("x-upstream"), Some("rejected"));
    assert_eq!(response.body, b"not-a-ws");

    let request = timeout(IO_TIMEOUT, request_rx).await.unwrap().unwrap();
    assert_eq!(request.header_values("sec-websocket-key"), [WEBSOCKET_KEY]);
}

#[tokio::test]
async fn websocket_invalid_accept_returns_502_and_never_tunnels() {
    let (upstream, _request_rx, _upstream_task) =
        spawn_websocket_upstream(WebSocketBehavior::InvalidAccept).await;
    let rook = spawn_rook(&[upstream], "", "websocket = true").await;
    let mut stream = TcpStream::connect(rook.addr).await.unwrap();
    stream
        .write_all(websocket_request("/socket").as_bytes())
        .await
        .unwrap();
    let response = read_response(&mut stream).await;
    assert_error_response(&response, 502, upstream);
    assert!(response.leftover.is_empty());

    let mut extra = [0; 32];
    match timeout(Duration::from_millis(150), stream.read(&mut extra)).await {
        Ok(Ok(0)) | Err(_) => {}
        Ok(Ok(read)) => panic!("invalid upgrade tunneled raw bytes: {:?}", &extra[..read]),
        Ok(Err(error)) => panic!("unexpected socket error: {error}"),
    }
}

#[tokio::test]
async fn connection_headers_cannot_remove_host_and_forwarding_spoofs_are_stripped() {
    let (upstream, request_rx, _upstream_task) = spawn_capture_upstream(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_owned(),
    )
    .await;
    let rook = spawn_rook(&[upstream], "", "").await;
    let response = send_request(
        rook.addr,
        "GET /headers HTTP/1.1\r\nHost: Example.COM\r\nConnection: host, x-remove-me\r\nConnection: keep-alive\r\nX-Remove-Me: remove\r\nX-Forwarded-Host: attacker.example\r\nForwarded: for=192.0.2.1;host=attacker.example\r\nTrue-Client-IP: 192.0.2.2\r\n\r\n",
    )
    .await;
    assert_eq!(response.status, 200);

    let request = timeout(IO_TIMEOUT, request_rx).await.unwrap().unwrap();
    assert_eq!(request.header_values("host"), ["Example.COM"]);
    assert!(request.header_values("x-remove-me").is_empty());
    for name in ["x-forwarded-host", "forwarded", "true-client-ip"] {
        assert!(
            request.header_values(name).is_empty(),
            "{name} reached the upstream"
        );
    }
    assert_eq!(request.header_values("x-real-ip"), ["127.0.0.1"]);

    let response = send_request(
        rook.addr,
        "GET /headers HTTP/1.1\r\nHost: example.com\r\nX_Underscore: rejected\r\n\r\n",
    )
    .await;
    assert_error_response(&response, 400, upstream);
}

#[tokio::test]
async fn h2c_upgrade_and_http2_prior_knowledge_are_refused_before_upstream() {
    let (upstream, mut request_rx, _upstream_task) = spawn_recording_upstream().await;
    let rook = spawn_rook(&[upstream], "", "").await;

    let upgrade = send_request(
        rook.addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n",
    )
    .await;
    assert_error_response(&upgrade, 400, upstream);

    let mut prior_knowledge = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    prior_knowledge.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
    let mut stream = TcpStream::connect(rook.addr).await.unwrap();
    stream.write_all(&prior_knowledge).await.unwrap();
    let mut reply = [0; 256];
    match timeout(IO_TIMEOUT, stream.read(&mut reply))
        .await
        .expect("HTTP/2 prior knowledge was not refused")
    {
        Ok(0) => {}
        Ok(read) => {
            let response = String::from_utf8_lossy(&reply[..read]);
            let status = response
                .split_whitespace()
                .nth(1)
                .and_then(|status| status.parse::<u16>().ok());
            assert!(
                matches!(status, Some(400 | 505)),
                "unexpected HTTP/2 prior-knowledge response: {response:?}"
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(error) => panic!("unexpected prior-knowledge read error: {error}"),
    }
    assert!(
        request_rx.try_recv().is_err(),
        "an h2c request reached the upstream"
    );
}

#[tokio::test]
async fn open_websocket_counts_toward_max_connections_per_ip() {
    let (upstream, _upstream_task) = spawn_websocket_hold_upstream().await;
    let rook = spawn_rook(
        &[upstream],
        "max_connections_per_ip = 1",
        "websocket = true",
    )
    .await;
    sleep(Duration::from_millis(25)).await;
    let held = open_websocket(rook.addr).await;

    let mut second = TcpStream::connect(rook.addr).await.unwrap();
    second
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    assert_connection_closed(&mut second).await;
    drop(held);
}

#[tokio::test]
async fn open_websocket_counts_toward_max_connections_per_upstream() {
    let (upstream, _upstream_task) = spawn_websocket_hold_upstream().await;
    let rook = spawn_rook(
        &[upstream],
        "max_connections_per_upstream = 1",
        "websocket = true",
    )
    .await;
    let held = open_websocket(rook.addr).await;

    let response = send_request(rook.addr, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
    assert_error_response(&response, 503, upstream);
    drop(held);
}

#[tokio::test]
async fn header_read_timeout_closes_silent_connection() {
    let upstream = free_addr().await;
    let rook = spawn_rook(&[upstream], "", "").await;
    let mut stream = TcpStream::connect(rook.addr).await.unwrap();
    let started = Instant::now();
    assert_connection_closed(&mut stream).await;
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(800),
        "silent connection closed too early: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(1800),
        "header read timeout was not enforced: {elapsed:?}"
    );
}

#[tokio::test]
async fn trusted_proxy_rejects_repeated_cf_and_combines_forwarded_for_safely() {
    let (upstream, mut request_rx, _upstream_task) = spawn_recording_upstream().await;
    let rook = spawn_rook(
        &[upstream],
        "trusted_proxies = [\"127.0.0.0/8\"]\ncloudflare_ranges = [\"127.0.0.0/8\"]",
        "",
    )
    .await;

    let repeated_cf = send_request(
        rook.addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nCF-Connecting-IP: 192.0.2.1\r\nCF-Connecting-IP: 192.0.2.2\r\n\r\n",
    )
    .await;
    assert_error_response(&repeated_cf, 400, upstream);
    assert!(request_rx.try_recv().is_err());

    let forwarded = send_request(
        rook.addr,
        "GET /forwarded HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 198.51.100.1\r\nX-Forwarded-For: 203.0.113.2\r\n\r\n",
    )
    .await;
    assert_eq!(forwarded.status, 200);
    let request = timeout(IO_TIMEOUT, request_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(request.header_values("x-real-ip"), ["203.0.113.2"]);
    assert_eq!(request.header_values("x-forwarded-for"), ["203.0.113.2"]);

    let mapped = send_request(
        rook.addr,
        "GET /mapped HTTP/1.1\r\nHost: example.com\r\nCF-Connecting-IP: ::ffff:192.0.2.10\r\n\r\n",
    )
    .await;
    assert_eq!(mapped.status, 200);
    let request = timeout(IO_TIMEOUT, request_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(request.header_values("x-real-ip"), ["192.0.2.10"]);
    assert_eq!(request.header_values("x-forwarded-for"), ["192.0.2.10"]);
}

#[tokio::test]
async fn cloudflare_ranges_gate_cf_header_and_xff_still_walks() {
    // Case 1: CF header from a peer in cloudflare_ranges -> honoured.
    // (Peer is NOT in trusted_proxies: membership in the union suffices.)
    let (upstream, mut request_rx, _upstream_task) = spawn_recording_upstream().await;
    let rook = spawn_rook(&[upstream], "cloudflare_ranges = [\"127.0.0.0/8\"]", "").await;
    let honoured = send_request(
        rook.addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nCF-Connecting-IP: 192.0.2.1\r\n\r\n",
    )
    .await;
    assert_eq!(honoured.status, 200);
    let request = timeout(IO_TIMEOUT, request_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(request.header_values("x-real-ip"), ["192.0.2.1"]);

    // Case 3 (same instance): no CF header, peer in CF ranges, XFF present
    // -> XFF walked, visitor IP returned; visitors don't collapse to the
    // edge address.
    let walked = send_request(
        rook.addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 198.51.100.7\r\n\r\n",
    )
    .await;
    assert_eq!(walked.status, 200);
    let request = timeout(IO_TIMEOUT, request_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(request.header_values("x-real-ip"), ["198.51.100.7"]);

    // Case 2: CF header from a trusted peer NOT in cloudflare_ranges ->
    // ignored without being parsed, peer IP used. Even a malformed value
    // must not turn the peer's legitimate traffic into 400s.
    let (upstream2, mut request_rx2, _upstream_task2) = spawn_recording_upstream().await;
    let rook2 = spawn_rook(&[upstream2], "trusted_proxies = [\"127.0.0.0/8\"]", "").await;
    let ignored = send_request(
        rook2.addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nCF-Connecting-IP: not-an-ip\r\n\r\n",
    )
    .await;
    assert_eq!(ignored.status, 200);
    let request = timeout(IO_TIMEOUT, request_rx2.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(request.header_values("x-real-ip"), ["127.0.0.1"]);
}

#[tokio::test]
async fn response_body_idle_timeout_stops_stalled_upstream_response() {
    let (upstream, _upstream_task) = spawn_stalled_response_upstream().await;
    let rook = spawn_rook(&[upstream], "", "").await;
    let mut stream = TcpStream::connect(rook.addr).await.unwrap();
    let started = Instant::now();
    stream
        .write_all(b"GET /stall HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let (head, mut body) = read_head(&mut stream).await;
    assert!(String::from_utf8(head).unwrap().starts_with("HTTP/1.1 200"));
    let mut buffer = [0; 32];
    loop {
        match timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
            Ok(Ok(0)) | Ok(Err(_)) => break,
            Ok(Ok(read)) => body.extend_from_slice(&buffer[..read]),
            Err(_) => panic!("stalled response body did not time out"),
        }
    }
    let elapsed = started.elapsed();
    assert_eq!(body, b"abc");
    assert!(
        elapsed >= Duration::from_millis(800),
        "response body timed out too early: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(2200),
        "response body idle timeout was not enforced: {elapsed:?}"
    );
}

#[tokio::test]
async fn request_body_idle_timeout_aborts_stalled_upstream_request() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let upstream = listener.local_addr().unwrap();
    let (request_tx, request_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _ = read_head(&mut stream).await;
        request_tx.send(()).unwrap();
        let mut body = Vec::new();
        let _ = timeout(Duration::from_secs(3), stream.read_to_end(&mut body)).await;
        assert!(body.len() < 10);
    });
    let _upstream_task = TaskGuard(upstream_task);
    let rook = spawn_rook(&[upstream], "", "").await;
    let mut stream = TcpStream::connect(rook.addr).await.unwrap();
    let started = Instant::now();
    stream
        .write_all(b"POST /stall HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\n\r\nabc")
        .await
        .unwrap();
    timeout(IO_TIMEOUT, request_rx)
        .await
        .expect("upstream did not receive stalled request")
        .unwrap();
    let response = read_response(&mut stream).await;
    assert_error_response(&response, 504, upstream);
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(800),
        "request body timed out too early: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(2200),
        "request body idle timeout was not enforced: {elapsed:?}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn sigterm_drains_and_exits_child_rookd() {
    let upstream = free_addr().await;
    let mut child = spawn_rook_child(upstream, false).await;
    wait_for_child_log(&mut child, "Rook HTTP is listening").await;

    let status = Command::new("kill")
        .arg("-TERM")
        .arg(child.child.id().to_string())
        .status()
        .unwrap();
    assert!(status.success(), "could not signal child rookd");
    let status = wait_for_child_exit(&mut child.child).await;
    assert!(status.success(), "rookd exited unsuccessfully: {status}");
    assert!(
        TcpStream::connect(child.addr).await.is_err(),
        "rookd still accepted connections after SIGTERM"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn child_recovers_from_accept_errors_under_low_fd_limit() {
    let (upstream, _upstream_task) = spawn_identity_upstream("recovered").await;
    let mut child = spawn_rook_child(upstream, true).await;
    wait_for_child_log(&mut child, "Rook HTTP is listening").await;

    let mut held = Vec::new();
    for _ in 0..24 {
        if let Ok(Ok(mut stream)) =
            timeout(Duration::from_millis(200), TcpStream::connect(child.addr)).await
        {
            stream.write_all(b"G").await.unwrap();
            held.push(stream);
        }
    }
    assert!(
        held.len() >= 8,
        "could not create enough pending connections"
    );
    wait_for_child_log(&mut child, "HTTP accept failed; retrying").await;
    drop(held);

    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let attempt = timeout(Duration::from_millis(250), async {
            let mut stream = TcpStream::connect(child.addr).await?;
            stream
                .write_all(b"GET /recovered HTTP/1.1\r\nHost: example.com\r\n\r\n")
                .await?;
            let mut response = [0; 256];
            let read = stream.read(&mut response).await?;
            Ok::<_, std::io::Error>(response[..read].to_vec())
        })
        .await;
        if let Ok(Ok(response)) = attempt
            && response.starts_with(b"HTTP/1.1 200")
        {
            assert!(response.windows(9).any(|window| window == b"recovered"));
            break;
        }
        assert!(
            Instant::now() < deadline,
            "child did not serve a request after accept errors"
        );
        sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test]
async fn silent_header_waiters_do_not_delay_a_normal_request() {
    let (upstream, _upstream_task) = spawn_identity_upstream("prompt").await;
    let rook = spawn_rook(&[upstream], "header_read_timeout = 2", "").await;
    let mut silent = Vec::new();
    for _ in 0..8 {
        silent.push(TcpStream::connect(rook.addr).await.unwrap());
    }
    sleep(Duration::from_millis(50)).await;

    let started = Instant::now();
    let response = timeout(
        Duration::from_millis(500),
        send_request(
            rook.addr,
            "GET /prompt HTTP/1.1\r\nHost: example.com\r\n\r\n",
        ),
    )
    .await
    .expect("silent connections delayed a normal request");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"prompt");
    assert!(started.elapsed() < Duration::from_millis(500));
    drop(silent);
}

#[tokio::test]
async fn write_backpressure_disconnects_client_that_stops_reading() {
    const RESPONSE_LEN: usize = 16 * 1024 * 1024;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let upstream = listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _ = read_head(&mut stream).await;
        stream
            .write_all(
                format!("HTTP/1.1 200 OK\r\nContent-Length: {RESPONSE_LEN}\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
        let chunk = [b'x'; 16 * 1024];
        for _ in 0..RESPONSE_LEN / chunk.len() {
            stream.write_all(&chunk).await.unwrap();
        }
    });
    let _upstream_task = TaskGuard(upstream_task);
    let rook = spawn_rook(&[upstream], "idle_timeout = 2", "").await;
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(16 * 1024).unwrap();
    let mut stream = socket.connect(rook.addr).await.unwrap();
    stream
        .write_all(b"GET /large HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let (head, leftover) = read_head(&mut stream).await;
    let head = String::from_utf8(head).unwrap();
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(
        head.to_ascii_lowercase()
            .contains(&format!("content-length: {RESPONSE_LEN}")),
        "{head}"
    );

    let started = Instant::now();
    sleep(Duration::from_millis(2300)).await;
    let mut received = leftover.len();
    let mut buffer = [0; 64 * 1024];
    loop {
        match timeout(Duration::from_secs(1), stream.read(&mut buffer)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(read)) => {
                received += read;
                assert!(
                    received < 4 * 1024 * 1024,
                    "response resumed instead of timing out after backpressure"
                );
            }
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
            Ok(Err(error)) => panic!("unexpected backpressure read error: {error}"),
            Err(_) => panic!("backpressured response was not disconnected"),
        }
    }
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn additional_client_and_forwarding_spoofs_are_stripped() {
    let (upstream, request_rx, _upstream_task) = spawn_capture_upstream(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_owned(),
    )
    .await;
    let rook = spawn_rook(&[upstream], "", "").await;
    let response = send_request(
        rook.addr,
        "GET /headers HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-Port: 443\r\nX-Client-IP: 192.0.2.1\r\nX-Cluster-Client-IP: 192.0.2.2\r\nX-Host: attacker.example\r\nFront-End-Https: on\r\nX-Forwarded-Arbitrary: attacker\r\n\r\n",
    )
    .await;
    assert_eq!(response.status, 200);

    let request = timeout(IO_TIMEOUT, request_rx).await.unwrap().unwrap();
    for name in [
        "x-forwarded-port",
        "x-client-ip",
        "x-cluster-client-ip",
        "x-host",
        "front-end-https",
        "x-forwarded-arbitrary",
    ] {
        assert!(
            request.header_values(name).is_empty(),
            "{name} reached the upstream"
        );
    }
    assert_eq!(request.header_values("x-forwarded-for"), ["127.0.0.1"]);
    assert_eq!(request.header_values("x-forwarded-proto"), ["http"]);
}

#[tokio::test]
async fn streaming_response_holds_upstream_permit_until_body_completes() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let upstream = listener.local_addr().unwrap();
    let (release_tx, release_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.unwrap();
        let _ = read_head(&mut first).await;
        first
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhe")
            .await
            .unwrap();
        release_rx.await.unwrap();
        first.write_all(b"llo").await.unwrap();
        drop(first);

        let (mut second, _) = listener.accept().await.unwrap();
        let _ = read_head(&mut second).await;
        second
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
    });
    let _upstream_task = TaskGuard(upstream_task);
    let rook = spawn_rook(&[upstream], "max_connections_per_upstream = 1", "").await;
    let mut first = TcpStream::connect(rook.addr).await.unwrap();
    first
        .write_all(b"GET /stream HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let (head, leftover) = read_head(&mut first).await;
    assert!(String::from_utf8(head).unwrap().starts_with("HTTP/1.1 200"));

    let limited = send_request(
        rook.addr,
        "GET /limited HTTP/1.1\r\nHost: example.com\r\n\r\n",
    )
    .await;
    assert_error_response(&limited, 503, upstream);

    release_tx.send(()).unwrap();
    let buffered = leftover.len();
    let mut body = leftover;
    body.resize(5, 0);
    timeout(IO_TIMEOUT, first.read_exact(&mut body[buffered..]))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(body, b"hello");

    let deadline = Instant::now() + IO_TIMEOUT;
    loop {
        let response = send_request(
            rook.addr,
            "GET /after HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        .await;
        if response.status == 200 {
            assert_eq!(response.body, b"ok");
            break;
        }
        assert_error_response(&response, 503, upstream);
        assert!(
            Instant::now() < deadline,
            "upstream permit was not released"
        );
        sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn https_http1_sets_forwarded_proto_and_hsts_only_on_tls() {
    let certificate = TestCertificate::generate("example.com");
    let (upstream, mut request_rx, _upstream_task) = spawn_recording_upstream().await;
    let rook = spawn_https_rook(upstream, &certificate, "").await;
    let config = tls_client_config(&[&certificate], TLS13_VERSIONS, &[b"http/1.1"]);

    let response = send_tls_http1(
        rook.https_addr,
        "example.com",
        config,
        "GET /secure HTTP/1.1\r\nHost: Example.COM\r\n\r\n",
    )
    .await;
    assert_eq!(response.status, 200);
    let hsts = response
        .headers
        .iter()
        .filter(|(name, _)| name == "strict-transport-security")
        .collect::<Vec<_>>();
    assert_eq!(hsts.len(), 1);
    assert_eq!(hsts[0].1, "max-age=31536000");
    let request = timeout(IO_TIMEOUT, request_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(request.header_values("host"), ["Example.COM"]);
    assert_eq!(request.header_values("x-forwarded-proto"), ["https"]);

    let plain = send_request(
        rook.http_addr,
        "GET /plain HTTP/1.1\r\nHost: Example.COM\r\n\r\n",
    )
    .await;
    assert_eq!(plain.status, 308);
    assert_eq!(
        plain.header("location"),
        Some(format!("https://example.com:{}/plain", rook.https_addr.port()).as_str())
    );
    assert!(plain.header("strict-transport-security").is_none());
    assert!(
        request_rx.try_recv().is_err(),
        "plain HTTP redirect reached the upstream"
    );
}

#[tokio::test]
async fn sni_host_mismatch_is_421_and_unknown_sni_has_no_certificate() {
    let certificate = TestCertificate::generate("example.com");
    let (upstream, _upstream_task) = spawn_identity_upstream("unused").await;
    let rook = spawn_https_rook(upstream, &certificate, "").await;
    let config = tls_client_config(&[&certificate], TLS13_VERSIONS, &[b"http/1.1"]);

    let mismatch = send_tls_http1(
        rook.https_addr,
        "example.com",
        Arc::clone(&config),
        "GET / HTTP/1.1\r\nHost: other.example\r\n\r\n",
    )
    .await;
    assert_eq!(mismatch.status, 421);
    assert!(mismatch.body.is_empty());

    let unknown = timeout(
        IO_TIMEOUT,
        connect_tls(rook.https_addr, "unknown.example", config),
    )
    .await
    .expect("unknown-SNI handshake timed out");
    assert!(
        unknown.is_err(),
        "unknown SNI received a default certificate"
    );
}

#[tokio::test]
async fn tls13_is_default_and_tls12_requires_explicit_opt_in() {
    let certificate = TestCertificate::generate("example.com");
    let (upstream, _upstream_task) = spawn_identity_upstream("tls").await;
    let rook = spawn_https_rook(upstream, &certificate, "").await;
    let tls13 = tls_client_config(&[&certificate], TLS13_VERSIONS, &[b"http/1.1"]);
    let mut stream = timeout(
        IO_TIMEOUT,
        connect_tls(rook.https_addr, "example.com", tls13),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        stream.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(read_response(&mut stream).await.status, 200);

    let tls12 = tls_client_config(&[&certificate], TLS12_VERSIONS, &[b"http/1.1"]);
    let refused = timeout(
        IO_TIMEOUT,
        connect_tls(rook.https_addr, "example.com", Arc::clone(&tls12)),
    )
    .await
    .expect("TLS 1.2 handshake timed out");
    assert!(refused.is_err(), "TLS 1.2 succeeded without opt-in");
    drop(rook);

    let rook = spawn_https_rook(upstream, &certificate, "allow_tls12 = true").await;
    let mut stream = timeout(
        IO_TIMEOUT,
        connect_tls(rook.https_addr, "example.com", tls12),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        stream.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_2)
    );
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(read_response(&mut stream).await.status, 200);
}

#[tokio::test]
async fn https_http2_preserves_authority_and_does_not_duplicate_upstream_hsts() {
    let certificate = TestCertificate::generate("example.com");
    let (upstream, request_rx, _upstream_task) = spawn_capture_upstream(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nStrict-Transport-Security: max-age=123\r\nConnection: close\r\n\r\nok"
            .to_owned(),
    )
    .await;
    let rook = spawn_https_rook(upstream, &certificate, "").await;
    let config = tls_client_config(&[&certificate], TLS13_VERSIONS, &[b"h2"]);
    let stream = timeout(
        IO_TIMEOUT,
        connect_tls(rook.https_addr, "example.com", config),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let (mut sender, connection) = hyper::client::conn::http2::handshake::<_, _, Empty<Bytes>>(
        TokioExecutor::new(),
        TokioIo::new(stream),
    )
    .await
    .unwrap();
    let connection_task = tokio::spawn(async move {
        connection.await.unwrap();
    });
    let _connection_task = TaskGuard(connection_task);

    let request = hyper::Request::builder()
        .method("GET")
        .uri("https://Example.COM/h2")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let response = timeout(IO_TIMEOUT, sender.send_request(request))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.version(), http::Version::HTTP_2);
    let hsts = response
        .headers()
        .get_all("strict-transport-security")
        .iter()
        .collect::<Vec<_>>();
    assert_eq!(hsts.len(), 1);
    assert_eq!(hsts[0], "max-age=123");
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        Bytes::from_static(b"ok")
    );
    let request = timeout(IO_TIMEOUT, request_rx).await.unwrap().unwrap();
    assert_eq!(request.header_values("host"), ["Example.COM"]);
    assert_eq!(request.header_values("x-forwarded-proto"), ["https"]);
}

#[tokio::test]
async fn certificate_hot_reload_switches_and_failed_reload_keeps_valid_certificate() {
    let first = TestCertificate::generate("example.com");
    let second = TestCertificate::generate("example.com");
    let (upstream, _upstream_task) = spawn_identity_upstream("unused").await;
    let rook = spawn_https_rook(upstream, &first, "").await;
    let config = tls_client_config(&[&first, &second], TLS13_VERSIONS, &[b"http/1.1"]);
    let stream = timeout(
        IO_TIMEOUT,
        connect_tls(rook.https_addr, "example.com", Arc::clone(&config)),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(peer_certificate(&stream), first.certificate.as_ref());
    drop(stream);

    let new_cert = first._directory.path().join("new-certificate.pem");
    let new_key = first._directory.path().join("new-key.pem");
    std::fs::copy(&second.cert_path, &new_cert).unwrap();
    std::fs::copy(&second.key_path, &new_key).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&new_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::rename(&new_cert, &first.cert_path).unwrap();
    std::fs::rename(&new_key, &first.key_path).unwrap();

    let deadline = Instant::now() + Duration::from_secs(7);
    loop {
        if let Ok(Ok(stream)) = timeout(
            IO_TIMEOUT,
            connect_tls(rook.https_addr, "example.com", Arc::clone(&config)),
        )
        .await
            && peer_certificate(&stream) == second.certificate.as_ref()
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "certificate did not switch after the reload interval"
        );
        sleep(Duration::from_millis(50)).await;
    }

    std::fs::write(&first.cert_path, "not a PEM certificate").unwrap();
    sleep(Duration::from_millis(2200)).await;
    let stream = timeout(
        IO_TIMEOUT,
        connect_tls(rook.https_addr, "example.com", config),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(peer_certificate(&stream), second.certificate.as_ref());
}

#[tokio::test]
async fn acme_http01_challenge_is_served_before_plain_http_redirect() {
    let certificate = TestCertificate::generate("example.com");
    let http_addr = free_addr().await;
    let https_addr = free_addr().await;
    let upstream = free_addr().await;
    let settings = format!("https_listen = \"{https_addr}\"");
    let input = rook_config(http_addr, &[upstream], &settings, "").replace(
        "hosts = [\"example.com\"]",
        &format!(
            "hosts = [\"example.com\"]\ntls_cert = \"{}\"\ntls_key = \"{}\"",
            certificate.cert_path.display(),
            certificate.key_path.display()
        ),
    );
    let state = AppState::new(Config::parse(&input).unwrap());
    assert!(state.acme_challenges.insert(
        "Example.COM",
        "test-token",
        "test-key-authorization".to_owned()
    ));

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let service_state = Arc::clone(&state);
    let task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let service = hyper::service::service_fn(move |mut request| {
            request.extensions_mut().insert(RequestScheme::Http);
            Arc::clone(&service_state).handle(peer, request)
        });
        hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await
            .unwrap();
    });
    let _task = TaskGuard(task);

    let response = send_request(
        addr,
        "GET /.well-known/acme-challenge/test-token HTTP/1.1\r\nHost: example.com\r\n\r\n",
    )
    .await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"test-key-authorization");
    assert!(response.header("location").is_none());
    assert!(response.header("strict-transport-security").is_none());
}

#[cfg(unix)]
#[tokio::test]
async fn check_rejects_bad_supplied_certificates_without_side_effects() {
    use std::os::unix::fs::PermissionsExt;

    let missing = TestCertificate::generate("example.com");
    std::fs::remove_file(&missing.cert_path).unwrap();
    let insecure = TestCertificate::generate("example.com");
    std::fs::set_permissions(&insecure.key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let acme_root = TestCertificate::generate("acme-root.example");
    let directory = tempfile::tempdir().unwrap();
    let blocklist = directory.path().join("blocklist.txt");
    std::fs::write(&blocklist, "").unwrap();
    let acme_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let acme_addr = acme_listener.local_addr().unwrap();
    let http_addr = free_addr().await;
    let https_addr = free_addr().await;

    for (index, (certificate, expected_error)) in [
        (missing, "could not open TLS certificate chain"),
        (insecure, "insecure permissions"),
    ]
    .into_iter()
    .enumerate()
    {
        let config_path = directory.path().join(format!("invalid-{index}.toml"));
        let settings = format!(
            "https_listen = \"{https_addr}\"\nblocklist_file = \"{}\"",
            blocklist.display()
        );
        let acme = format!(
            "[sites.acme]\ncontact = \"mailto:admin@example.com\"\ndirectory_url = \"https://{acme_addr}/directory\"\nstate_dir = \"{}/acme-{index}\"\ntrusted_root = \"{}\"\n[[sites.routes]]",
            directory.path().display(),
            acme_root.cert_path.display()
        );
        let input = rook_config(http_addr, &[http_addr], &settings, "")
            .replace(
                "hosts = [\"example.com\"]",
                &format!(
                    "hosts = [\"example.com\"]\ntls_cert = \"{}\"\ntls_key = \"{}\"",
                    certificate.cert_path.display(),
                    certificate.key_path.display()
                ),
            )
            .replace("[[sites.routes]]", &acme);
        std::fs::write(&config_path, input).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_rookd"))
            .arg("--config")
            .arg(&config_path)
            .arg("--check")
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "--check accepted invalid certificate material"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(expected_error),
            "expected {expected_error:?}, got {stderr}"
        );
        assert!(
            TcpStream::connect(http_addr).await.is_err(),
            "--check opened the HTTP listener"
        );
        assert!(
            TcpStream::connect(https_addr).await.is_err(),
            "--check opened the HTTPS listener"
        );
    }
    assert!(
        timeout(Duration::from_millis(100), acme_listener.accept())
            .await
            .is_err(),
        "--check contacted the ACME directory"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn check_accepts_shipped_example_configuration() {
    let output = Command::new(env!("CARGO_BIN_EXE_rookd"))
        .arg("--config")
        .arg("rookd.example.toml")
        .arg("--check")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "--check rejected rookd.example.toml: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("Configuration is valid:"));
}

#[tokio::test]
async fn h2_zero_window_client_cannot_hold_upstream_slot_after_idle_timeout() {
    let certificate = TestCertificate::generate("example.com");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let upstream = listener.local_addr().unwrap();
    let (request_tx, request_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.unwrap();
        let _ = read_head(&mut first).await;
        first
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 16777216\r\n\r\n")
            .await
            .unwrap();
        request_tx.send(()).unwrap();
        let chunk = [b'x'; 16 * 1024];
        for _ in 0..1024 {
            if first.write_all(&chunk).await.is_err() {
                break;
            }
        }
        drop(first);

        let (mut second, _) = listener.accept().await.unwrap();
        let _ = read_head(&mut second).await;
        second
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
    });
    let _upstream_task = TaskGuard(upstream_task);
    let rook = spawn_https_rook(
        upstream,
        &certificate,
        "idle_timeout = 1\nmax_connections_per_upstream = 1",
    )
    .await;
    let h2_config = tls_client_config(&[&certificate], TLS13_VERSIONS, &[b"h2"]);
    let http1_config = tls_client_config(&[&certificate], TLS13_VERSIONS, &[b"http/1.1"]);
    let mut stream = timeout(
        IO_TIMEOUT,
        connect_tls(rook.https_addr, "example.com", h2_config),
    )
    .await
    .unwrap()
    .unwrap();
    stream
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .unwrap();
    write_h2_frame(&mut stream, 4, 0, 0, &[0, 4, 0, 0, 0, 0])
        .await
        .unwrap();
    let headers = [
        0x82, 0x87, 0x84, 0x01, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
        b'm',
    ];
    write_h2_frame(&mut stream, 1, 5, 1, &headers)
        .await
        .unwrap();
    let started = Instant::now();
    let h2_task = tokio::spawn(async move {
        let mut stream = stream;
        drive_h2_until_close(&mut stream).await
    });
    timeout(IO_TIMEOUT, request_rx)
        .await
        .expect("HTTP/2 request did not reach the upstream")
        .unwrap();

    let limited = send_tls_http1(
        rook.https_addr,
        "example.com",
        Arc::clone(&http1_config),
        "GET /limited HTTP/1.1\r\nHost: example.com\r\n\r\n",
    )
    .await;
    assert_eq!(limited.status, 503);
    let pings = timeout(Duration::from_secs(3), h2_task)
        .await
        .unwrap()
        .unwrap();
    assert!(pings > 0, "server did not exercise HTTP/2 keepalive");
    assert!(started.elapsed() >= Duration::from_millis(700));
    assert!(started.elapsed() < Duration::from_millis(2500));

    let deadline = Instant::now() + IO_TIMEOUT;
    loop {
        let response = send_tls_http1(
            rook.https_addr,
            "example.com",
            Arc::clone(&http1_config),
            "GET /after HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        .await;
        if response.status == 200 {
            assert_eq!(response.body, b"ok");
            break;
        }
        assert_eq!(response.status, 503);
        assert!(Instant::now() < deadline, "upstream slot stayed exhausted");
        sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn idle_h2_connection_closes_even_when_client_answers_pings() {
    let certificate = TestCertificate::generate("example.com");
    let (upstream, _upstream_task) = spawn_identity_upstream("unused").await;
    let rook = spawn_https_rook(upstream, &certificate, "idle_timeout = 1").await;
    let config = tls_client_config(&[&certificate], TLS13_VERSIONS, &[b"h2"]);
    let mut stream = timeout(
        IO_TIMEOUT,
        connect_tls(rook.https_addr, "example.com", config),
    )
    .await
    .unwrap()
    .unwrap();
    stream
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .unwrap();
    write_h2_frame(&mut stream, 4, 0, 0, &[]).await.unwrap();
    let started = Instant::now();
    let pings = drive_h2_until_close(&mut stream).await;
    assert!(pings > 0, "server did not exercise HTTP/2 keepalive");
    assert!(started.elapsed() >= Duration::from_millis(700));
    assert!(started.elapsed() < Duration::from_millis(2500));
}

#[tokio::test]
async fn silent_post_handshake_clients_close_for_both_alpns() {
    let certificate = TestCertificate::generate("example.com");
    let (upstream, _upstream_task) = spawn_identity_upstream("unused").await;
    let rook = spawn_https_rook(upstream, &certificate, "idle_timeout = 1").await;

    for alpn in [b"http/1.1".as_slice(), b"h2".as_slice()] {
        let config = tls_client_config(&[&certificate], TLS13_VERSIONS, &[alpn]);
        let mut stream = timeout(
            IO_TIMEOUT,
            connect_tls(rook.https_addr, "example.com", config),
        )
        .await
        .unwrap()
        .unwrap();
        let started = Instant::now();
        assert_connection_closed(&mut stream).await;
        assert!(started.elapsed() >= Duration::from_millis(700));
        assert!(started.elapsed() < Duration::from_millis(1800));
    }
}

#[tokio::test]
async fn per_client_upstream_cap_preserves_capacity_for_other_clients() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let upstream = listener.local_addr().unwrap();
    let (release_tx, release_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.unwrap();
        let _ = read_head(&mut first).await;
        first
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhe")
            .await
            .unwrap();

        let (mut second, _) = listener.accept().await.unwrap();
        let _ = read_head(&mut second).await;
        second
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
        release_rx.await.unwrap();
        first.write_all(b"llo").await.unwrap();
    });
    let _upstream_task = TaskGuard(upstream_task);
    let rook = spawn_rook(
        &[upstream],
        "max_connections_per_upstream = 2\nmax_upstream_per_ip = 1\ntrusted_proxies = [\"127.0.0.0/8\"]\ncloudflare_ranges = [\"127.0.0.0/8\"]",
        "",
    )
    .await;
    let mut first = TcpStream::connect(rook.addr).await.unwrap();
    first
        .write_all(
            b"GET /stream HTTP/1.1\r\nHost: example.com\r\nCF-Connecting-IP: 192.0.2.1\r\n\r\n",
        )
        .await
        .unwrap();
    let (head, leftover) = read_head(&mut first).await;
    assert!(String::from_utf8(head).unwrap().starts_with("HTTP/1.1 200"));

    let same_client = send_request(
        rook.addr,
        "GET /same HTTP/1.1\r\nHost: example.com\r\nCF-Connecting-IP: 192.0.2.1\r\n\r\n",
    )
    .await;
    assert_error_response(&same_client, 503, upstream);
    let other_client = send_request(
        rook.addr,
        "GET /other HTTP/1.1\r\nHost: example.com\r\nCF-Connecting-IP: 192.0.2.2\r\n\r\n",
    )
    .await;
    assert_eq!(other_client.status, 200);
    assert_eq!(other_client.body, b"ok");

    release_tx.send(()).unwrap();
    let buffered = leftover.len();
    let mut body = leftover;
    body.resize(5, 0);
    first.read_exact(&mut body[buffered..]).await.unwrap();
    assert_eq!(body, b"hello");
}

#[tokio::test]
async fn h2_split_cookies_are_joined_for_http1_upstream() {
    let certificate = TestCertificate::generate("example.com");
    let (upstream, request_rx, _upstream_task) = spawn_capture_upstream(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_owned(),
    )
    .await;
    let rook = spawn_https_rook(upstream, &certificate, "").await;
    let config = tls_client_config(&[&certificate], TLS13_VERSIONS, &[b"h2"]);
    let stream = timeout(
        IO_TIMEOUT,
        connect_tls(rook.https_addr, "example.com", config),
    )
    .await
    .unwrap()
    .unwrap();
    let (mut sender, connection) = hyper::client::conn::http2::handshake::<_, _, Empty<Bytes>>(
        TokioExecutor::new(),
        TokioIo::new(stream),
    )
    .await
    .unwrap();
    let connection_task = tokio::spawn(async move {
        connection.await.unwrap();
    });
    let _connection_task = TaskGuard(connection_task);
    let request = hyper::Request::builder()
        .method("GET")
        .uri("https://example.com/cookies")
        .header("cookie", "a=1")
        .header("cookie", "b=2")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let response = timeout(IO_TIMEOUT, sender.send_request(request))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        Bytes::from_static(b"ok")
    );
    let request = timeout(IO_TIMEOUT, request_rx).await.unwrap().unwrap();
    assert_eq!(request.header_values("cookie"), ["a=1; b=2"]);
}

#[tokio::test]
async fn progressing_tls_http1_upload_exceeds_idle_timeout() {
    let certificate = TestCertificate::generate("example.com");
    let (upstream, _upstream_task) = spawn_upload_upstream().await;
    let rook = spawn_https_rook(
        upstream,
        &certificate,
        "idle_timeout = 1\nrequest_timeout = 3",
    )
    .await;
    let config = tls_client_config(&[&certificate], TLS13_VERSIONS, &[b"http/1.1"]);
    let response = send_tls_http1_upload(rook.https_addr, config).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"ok");
}

#[tokio::test]
async fn progressing_tls_http2_upload_exceeds_idle_timeout() {
    let certificate = TestCertificate::generate("example.com");
    let (upstream, _upstream_task) = spawn_upload_upstream().await;
    let rook = spawn_https_rook(
        upstream,
        &certificate,
        "idle_timeout = 1\nrequest_timeout = 3",
    )
    .await;
    let config = tls_client_config(&[&certificate], TLS13_VERSIONS, &[b"h2"]);
    let mut stream = timeout(
        IO_TIMEOUT,
        connect_tls(rook.https_addr, "example.com", config),
    )
    .await
    .unwrap()
    .unwrap();
    stream
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .unwrap();
    write_h2_frame(&mut stream, 4, 0, 0, &[]).await.unwrap();
    let headers = [
        0x83, 0x87, 0x84, 0x01, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
        b'm', 0x0f, 0x0d, 0x02, b'1', b'2',
    ];
    write_h2_frame(&mut stream, 1, 4, 1, &headers)
        .await
        .unwrap();

    for (index, chunk) in [b"abc".as_slice(), b"def", b"ghi", b"jkl"]
        .into_iter()
        .enumerate()
    {
        sleep(Duration::from_millis(400)).await;
        let flags = if index == 3 { 1 } else { 0 };
        write_h2_frame(&mut stream, 0, flags, 1, chunk)
            .await
            .unwrap();
        if index == 3 {
            continue;
        }
        loop {
            match timeout(Duration::from_millis(5), read_h2_frame(&mut stream)).await {
                Ok(Ok((6, 0, 0, payload))) => {
                    write_h2_frame(&mut stream, 6, 1, 0, &payload)
                        .await
                        .unwrap();
                }
                Ok(Ok((4, 0, 0, _))) => {
                    write_h2_frame(&mut stream, 4, 1, 0, &[]).await.unwrap();
                }
                Ok(Ok(_)) => {}
                Ok(Err(error)) => panic!("HTTP/2 upload disconnected: {error}"),
                Err(_) => break,
            }
        }
    }

    let mut body = Vec::new();
    let mut saw_headers = false;
    loop {
        let frame = timeout(IO_TIMEOUT, read_h2_frame(&mut stream))
            .await
            .expect("HTTP/2 upload response timed out")
            .unwrap();
        match frame {
            (1, _, 1, payload) => {
                saw_headers = true;
                assert!(payload.contains(&0x88), "response was not HTTP 200");
            }
            (0, flags, 1, payload) => {
                body.extend_from_slice(&payload);
                if flags & 1 != 0 {
                    break;
                }
            }
            (6, 0, 0, payload) => {
                write_h2_frame(&mut stream, 6, 1, 0, &payload)
                    .await
                    .unwrap();
            }
            (4, 0, 0, _) => {
                write_h2_frame(&mut stream, 4, 1, 0, &[]).await.unwrap();
            }
            _ => {}
        }
    }
    assert!(saw_headers);
    assert_eq!(body, b"ok");
}

#[tokio::test]
async fn upstream_headers_may_exceed_idle_timeout_within_request_timeout() {
    let certificate = TestCertificate::generate("example.com");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let upstream = listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _ = read_head(&mut stream).await;
        sleep(Duration::from_millis(1200)).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
    });
    let _upstream_task = TaskGuard(upstream_task);
    let rook = spawn_https_rook(
        upstream,
        &certificate,
        "idle_timeout = 1\nrequest_timeout = 2",
    )
    .await;
    let config = tls_client_config(&[&certificate], TLS13_VERSIONS, &[b"http/1.1"]);
    let response = send_tls_http1(
        rook.https_addr,
        "example.com",
        config,
        "GET /delayed HTTP/1.1\r\nHost: example.com\r\n\r\n",
    )
    .await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"ok");
}

#[tokio::test]
async fn progressing_upload_may_exceed_response_header_deadline() {
    let certificate = TestCertificate::generate("example.com");
    let (upstream, _upstream_task) = spawn_upload_upstream().await;
    let rook = spawn_https_rook(
        upstream,
        &certificate,
        "idle_timeout = 1\nrequest_timeout = 1",
    )
    .await;
    let config = tls_client_config(&[&certificate], TLS13_VERSIONS, &[b"http/1.1"]);
    let response = send_tls_http1_upload(rook.https_addr, config).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"ok");
}

#[cfg(unix)]
#[tokio::test]
async fn check_validates_acme_state_directory_without_modifying_paths() {
    use std::os::unix::fs::PermissionsExt;

    let certificate = TestCertificate::generate("example.com");
    let acme_root = TestCertificate::generate("acme-root.example");
    let directory = tempfile::tempdir().unwrap();
    let http_addr = free_addr().await;
    let https_addr = free_addr().await;
    let write_config = |name: &str, state_dir: &std::path::Path| {
        let config_path = directory.path().join(name);
        let settings = format!("https_listen = \"{https_addr}\"");
        let acme = format!(
            "[sites.acme]\ncontact = \"mailto:admin@example.com\"\ndirectory_url = \"https://127.0.0.1:9/directory\"\nstate_dir = \"{}\"\ntrusted_root = \"{}\"\n[[sites.routes]]",
            state_dir.display(),
            acme_root.cert_path.display()
        );
        let input = rook_config(http_addr, &[http_addr], &settings, "")
            .replace(
                "hosts = [\"example.com\"]",
                &format!(
                    "hosts = [\"example.com\"]\ntls_cert = \"{}\"\ntls_key = \"{}\"",
                    certificate.cert_path.display(),
                    certificate.key_path.display()
                ),
            )
            .replace("[[sites.routes]]", &acme);
        std::fs::write(&config_path, input).unwrap();
        config_path
    };

    let shared = directory.path().join("shared");
    std::fs::create_dir(&shared).unwrap();
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755)).unwrap();
    let config = write_config("shared.toml", &shared);
    let output = Command::new(env!("CARGO_BIN_EXE_rookd"))
        .arg("--config")
        .arg(config)
        .arg("--check")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("insecure permissions"));
    assert_eq!(
        std::fs::metadata(&shared).unwrap().permissions().mode() & 0o777,
        0o755
    );

    let missing = directory.path().join("missing/nested-state");
    let config = write_config("missing.toml", &missing);
    let output = Command::new(env!("CARGO_BIN_EXE_rookd"))
        .arg("--config")
        .arg(config)
        .arg("--check")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "--check rejected a missing ACME state directory: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!missing.exists());
    assert!(!missing.parent().unwrap().exists());
}

#[tokio::test]
async fn complete_http1_post_times_out_waiting_for_response_headers() {
    let certificate = TestCertificate::generate("example.com");
    let (upstream, _upstream_task) = spawn_never_responding_upstream().await;
    let rook = spawn_https_rook(
        upstream,
        &certificate,
        "idle_timeout = 3\nrequest_timeout = 1",
    )
    .await;
    let config = tls_client_config(&[&certificate], TLS13_VERSIONS, &[b"http/1.1"]);
    let mut stream = timeout(
        IO_TIMEOUT,
        connect_tls(rook.https_addr, "example.com", config),
    )
    .await
    .unwrap()
    .unwrap();
    let started = Instant::now();
    stream
        .write_all(b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\ntest")
        .await
        .unwrap();
    let response = read_response(&mut stream).await;
    assert_error_response(&response, 504, upstream);
    assert!(started.elapsed() >= Duration::from_millis(700));
}

#[tokio::test]
async fn complete_http2_post_times_out_waiting_for_response_headers() {
    let certificate = TestCertificate::generate("example.com");
    let (upstream, _upstream_task) = spawn_never_responding_upstream().await;
    let rook = spawn_https_rook(
        upstream,
        &certificate,
        "idle_timeout = 3\nrequest_timeout = 1",
    )
    .await;
    let config = tls_client_config(&[&certificate], TLS13_VERSIONS, &[b"h2"]);
    let stream = timeout(
        IO_TIMEOUT,
        connect_tls(rook.https_addr, "example.com", config),
    )
    .await
    .unwrap()
    .unwrap();
    let (mut sender, connection) = hyper::client::conn::http2::handshake::<_, _, Full<Bytes>>(
        TokioExecutor::new(),
        TokioIo::new(stream),
    )
    .await
    .unwrap();
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let _connection_task = TaskGuard(connection_task);
    let request = hyper::Request::builder()
        .method("POST")
        .uri("https://example.com/upload")
        .body(Full::new(Bytes::from_static(b"test")))
        .unwrap();
    let started = Instant::now();
    let response = timeout(IO_TIMEOUT, sender.send_request(request))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), 504);
    assert!(started.elapsed() >= Duration::from_millis(700));
}

#[tokio::test]
async fn stalled_http1_upload_times_out_and_releases_upstream_slot() {
    let certificate = TestCertificate::generate("example.com");
    let (upstream, _upstream_task) = spawn_stalled_large_upload_upstream().await;
    let rook = spawn_https_rook(
        upstream,
        &certificate,
        "idle_timeout = 1\nrequest_timeout = 5\nmax_connections_per_upstream = 1",
    )
    .await;
    let config = tls_client_config(&[&certificate], TLS13_VERSIONS, &[b"http/1.1"]);
    let mut stream = timeout(
        IO_TIMEOUT,
        connect_tls(rook.https_addr, "example.com", Arc::clone(&config)),
    )
    .await
    .unwrap()
    .unwrap();
    let started = Instant::now();
    stream
        .write_all(
            b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1000000\r\n\r\nabc",
        )
        .await
        .unwrap();
    let response = read_response(&mut stream).await;
    assert_error_response(&response, 504, upstream);
    assert!(started.elapsed() >= Duration::from_millis(700));

    let response = send_tls_http1(
        rook.https_addr,
        "example.com",
        config,
        "GET /after HTTP/1.1\r\nHost: example.com\r\n\r\n",
    )
    .await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"ok");
}

#[tokio::test]
async fn stalled_http2_upload_times_out_and_releases_upstream_slot() {
    let certificate = TestCertificate::generate("example.com");
    let (upstream, _upstream_task) = spawn_stalled_large_upload_upstream().await;
    let rook = spawn_https_rook(
        upstream,
        &certificate,
        "idle_timeout = 1\nrequest_timeout = 5\nmax_connections_per_upstream = 1",
    )
    .await;
    let config = tls_client_config(&[&certificate], TLS13_VERSIONS, &[b"h2"]);
    let stream = timeout(
        IO_TIMEOUT,
        connect_tls(rook.https_addr, "example.com", config),
    )
    .await
    .unwrap()
    .unwrap();
    let (mut sender, connection) = hyper::client::conn::http2::handshake::<_, _, StalledBody>(
        TokioExecutor::new(),
        TokioIo::new(stream),
    )
    .await
    .unwrap();
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let _connection_task = TaskGuard(connection_task);
    let request = hyper::Request::builder()
        .method("POST")
        .uri("https://example.com/upload")
        .body(StalledBody { sent: false })
        .unwrap();
    let started = Instant::now();
    let response = timeout(IO_TIMEOUT, sender.send_request(request))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), 504);
    assert!(started.elapsed() >= Duration::from_millis(700));

    let config = tls_client_config(&[&certificate], TLS13_VERSIONS, &[b"http/1.1"]);
    let response = send_tls_http1(
        rook.https_addr,
        "example.com",
        config,
        "GET /after HTTP/1.1\r\nHost: example.com\r\n\r\n",
    )
    .await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"ok");
}

#[cfg(unix)]
#[tokio::test]
async fn expired_supplied_certificates_are_nonfatal_at_startup_but_strict_for_check() {
    let expired = TestCertificate::generate_expired("expired.example");
    let recovery = TestCertificate::generate_expired("recovery.example");
    let good = TestCertificate::generate("good.example");
    let (upstream, _upstream_task) = spawn_identity_upstream("good").await;
    let directory = tempfile::tempdir().unwrap();
    let http_addr = free_addr().await;
    let https_addr = free_addr().await;
    let input = format!(
        r#"
[server]
listen = "{http_addr}"
https_listen = "{https_addr}"
header_read_timeout = 1
request_timeout = 2
upstream_connect_timeout = 1
idle_timeout = 1
websocket_idle_timeout = 2
websocket_max_lifetime = 5
shutdown_drain = 1

[[sites]]
hosts = ["expired.example"]
tls_cert = "{}"
tls_key = "{}"
[[sites.routes]]
prefix = "/"
upstreams = ["http://{upstream}"]

[[sites]]
hosts = ["recovery.example"]
tls_cert = "{}"
tls_key = "{}"
[sites.acme]
contact = "mailto:admin@example.com"
directory_url = "https://127.0.0.1:9/directory"
state_dir = "{}"
trusted_root = "{}"
[[sites.routes]]
prefix = "/"
upstreams = ["http://{upstream}"]

[[sites]]
hosts = ["good.example"]
tls_cert = "{}"
tls_key = "{}"
[[sites.routes]]
prefix = "/"
upstreams = ["http://{upstream}"]
"#,
        expired.cert_path.display(),
        expired.key_path.display(),
        recovery.cert_path.display(),
        recovery.key_path.display(),
        directory.path().join("acme-state").display(),
        good.cert_path.display(),
        good.cert_path.display(),
        good.key_path.display()
    );
    let config_path = directory.path().join("rookd.toml");
    std::fs::write(&config_path, &input).unwrap();
    let config = Config::parse(&input).unwrap();
    let task = tokio::spawn(async move {
        server::run(config).await.unwrap();
    });
    let _task = TaskGuard(task);
    let deadline = Instant::now() + IO_TIMEOUT;
    loop {
        if let Ok(Ok(stream)) =
            timeout(Duration::from_millis(50), TcpStream::connect(https_addr)).await
        {
            drop(stream);
            break;
        }
        assert!(Instant::now() < deadline, "HTTPS startup failed");
        sleep(Duration::from_millis(10)).await;
    }

    for host in ["expired.example", "recovery.example"] {
        let config = tls_client_config(&[&good], TLS13_VERSIONS, &[b"http/1.1"]);
        let result = timeout(IO_TIMEOUT, connect_tls(https_addr, host, config))
            .await
            .expect("expired-site handshake timed out");
        assert!(result.is_err(), "{host} unexpectedly completed a handshake");
    }
    let output = Command::new(env!("CARGO_BIN_EXE_rookd"))
        .arg("--config")
        .arg(config_path)
        .arg("--check")
        .output()
        .unwrap();
    assert!(!output.status.success(), "--check accepted an expired cert");
    assert!(String::from_utf8_lossy(&output.stderr).contains("not currently valid"));

    let config = tls_client_config(&[&good], TLS13_VERSIONS, &[b"http/1.1"]);
    let response = send_tls_http1(
        https_addr,
        "good.example",
        config,
        "GET / HTTP/1.1\r\nHost: good.example\r\n\r\n",
    )
    .await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"good");
}

#[tokio::test]
async fn rejects_ambiguous_second_request_on_keepalive_connection() {
    let (upstream, mut request_rx, _upstream_task) = spawn_recording_upstream().await;
    let rook = spawn_rook(&[upstream], "", "").await;
    let mut stream = TcpStream::connect(rook.addr).await.unwrap();
    stream
        .write_all(b"GET /first HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let first = read_response(&mut stream).await;
    assert_eq!(first.status, 200, "{}", first.raw_head);
    let forwarded = timeout(IO_TIMEOUT, request_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(forwarded.request_line, "GET /first HTTP/1.1");

    stream
        .write_all(b"POST /second HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
        .await
        .unwrap();
    let second = timeout(Duration::from_millis(500), read_response(&mut stream))
        .await
        .expect("ambiguous second request hung");
    assert_error_response(&second, 400, upstream);
    assert_connection_closed(&mut stream).await;
    assert!(
        request_rx.try_recv().is_err(),
        "ambiguous second request reached the upstream"
    );
}

#[tokio::test]
async fn ambiguous_raw_requests_never_reach_upstream() {
    let (upstream, mut request_rx, _upstream_task) = spawn_recording_upstream().await;
    let rook = spawn_rook(&[upstream], "", "").await;
    let cases = [
        b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\nabc".to_vec(),
        b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc".to_vec(),
        b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabc".to_vec(),
        b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\n".to_vec(),
        b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: xchunked\r\n\r\n0\r\n\r\n".to_vec(),
        b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n".to_vec(),
        b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked, identity\r\n\r\n0\r\n\r\n".to_vec(),
        b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chu\r\n\tcked\r\n\r\n0\r\n\r\n".to_vec(),
        b"GET / HTTP/1.1\nHost: example.com\n\n".to_vec(),
        b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Bad\x01Name: value\r\n\r\n".to_vec(),
        b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Bad-Value: good\x01bad\r\n\r\n".to_vec(),
        b"GET http://other.example/admin HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
        b"GET / HTTP/1.1\r\nHost: example.com\r\nHost: example.com\r\n\r\n".to_vec(),
    ];

    let mut failures = Vec::new();
    for (index, request) in cases.into_iter().enumerate() {
        let response = timeout(Duration::from_millis(500), send_bytes(rook.addr, &request))
            .await
            .unwrap_or_else(|_| panic!("ambiguous request {index} hung"));
        if response.status != 400 {
            failures.push(format!("request {index} returned {}", response.status));
        }
        if let Ok(request) = request_rx.try_recv() {
            failures.push(format!(
                "request {index} reached upstream as {:?}",
                request.request_line
            ));
        }
    }
    assert!(failures.is_empty(), "{failures:?}");
}

#[tokio::test]
async fn deterministic_malformed_path_fuzz_never_hangs_or_reaches_upstream() {
    let (upstream, mut request_rx, _upstream_task) = spawn_recording_upstream().await;
    let rook = spawn_rook(&[upstream], "", "").await;
    let patterns = [
        "%2f", "%2F", "%5c", "%5C", "//", "/./", "/../", "%2e", "%2e%2e", "%00", "%0a", "%", "%0",
        "%GG", "\\",
    ];
    let mut state = 0x4d595df4d0f33173u64;
    for index in 0..300 {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let pattern = patterns[state as usize % patterns.len()];
        let path = format!("/fuzz-{index}/{pattern}/tail");
        let request = format!("GET {path} HTTP/1.1\r\nHost: example.com\r\n\r\n");
        let response = timeout(
            Duration::from_millis(500),
            send_request(rook.addr, &request),
        )
        .await
        .unwrap_or_else(|_| panic!("malformed path {path:?} hung"));
        assert!(
            matches!(response.status, 400 | 404),
            "malformed path {path:?} returned {}",
            response.status
        );
        assert_error_response(&response, response.status, upstream);
        assert!(
            request_rx.try_recv().is_err(),
            "malformed path {path:?} reached the upstream"
        );
    }
}

#[test]
fn deterministic_malformed_config_fuzz_never_panics() {
    for index in 0..300 {
        let input = match index % 6 {
            0 => format!("[server\nlisten = {index}"),
            1 => format!(
                "[[sites]]\nhosts = [\"bad_host_{index}\"]\n[[sites.routes]]\nprefix = \"/\"\nupstreams = [\"http://127.0.0.1:9000\"]\n"
            ),
            2 => format!(
                "[[sites]]\nhosts = [\"example.com\"]\n[[sites.routes]]\nprefix = \"bad/{index}\"\nupstreams = [\"http://127.0.0.1:9000\"]\n"
            ),
            3 => format!(
                "[[sites]]\nhosts = [\"example.com\"]\n[[sites.routes]]\nprefix = \"/\"\nupstreams = [\"ftp://127.0.0.1:{index}\"]\n"
            ),
            4 => "[server]\nmax_connections = 0\n[[sites]]\nhosts = [\"example.com\"]\n[[sites.routes]]\nprefix = \"/\"\nupstreams = [\"http://127.0.0.1:9000\"]\n".to_string(),
            _ => format!(
                "[[sites]]\nhosts = [\"example.com\"]\n[[sites.routes]]\nprefix = \"/%GG{index}\"\nupstreams = [\"http://127.0.0.1:9000\"]\n"
            ),
        };
        assert!(
            Config::parse(&input).is_err(),
            "malformed config {index} was accepted: {input}"
        );
    }
}

#[tokio::test]
async fn unknown_host_strikes_ban_and_log_only_does_not() {
    let (upstream, _guard) = spawn_identity_upstream("ok").await;
    // Enforcing server-wide strikes: threshold 2, short ban.
    let rook = spawn_rook(
        &[upstream],
        "[server.strikes]\nenabled = true\nlog_only = false\nthreshold = 2\nwindow_secs = 60\nban_secs = 60\n",
        "",
    )
    .await;
    for _ in 0..2 {
        let r = send_request(
            rook.addr,
            "GET / HTTP/1.1\r\nHost: unknown.example\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert_eq!(r.status, 404);
    }
    // Third request from the banned client is refused before any work.
    let r = send_request(
        rook.addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(r.status, 403);
}

#[tokio::test]
async fn unknown_host_strikes_log_only_never_bans() {
    let (upstream, _guard) = spawn_identity_upstream("ok").await;
    let rook = spawn_rook(
        &[upstream],
        "[server.strikes]\nenabled = true\nthreshold = 2\nwindow_secs = 60\nban_secs = 60\n",
        "",
    )
    .await;
    for _ in 0..5 {
        let r = send_request(
            rook.addr,
            "GET / HTTP/1.1\r\nHost: unknown.example\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert_eq!(r.status, 404);
    }
    // Past the threshold in log-only mode: the site still answers.
    let r = send_request(
        rook.addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(r.status, 200);
}

#[tokio::test]
async fn trap_paths_strike_the_site_tracker() {
    let (upstream, _guard) = spawn_identity_upstream("ok").await;
    let rook = spawn_rook(
        &[upstream],
        "",
        "\n[sites.strikes]\nenabled = true\nlog_only = false\nthreshold = 1\nwindow_secs = 60\nban_secs = 60\ntrap_paths = [\"/wp-admin\"]\n",
    )
    .await;
    // One touch of the trap path: 404 and a strike; threshold 1 bans.
    let r = send_request(
        rook.addr,
        "GET /wp-admin HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(r.status, 404);
    // The next request to the site is refused.
    let r = send_request(
        rook.addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(r.status, 403);
}

#[tokio::test]
async fn strikes_key_on_the_verified_visitor_not_the_proxy() {
    let (upstream, _guard) = spawn_identity_upstream("ok").await;
    // The "Cloudflare range" here is loopback, so the test's direct peer
    // is trusted; visitors arrive via CF-Connecting-IP.
    let rook = spawn_rook(
        &[upstream],
        "cloudflare_ranges = [\"127.0.0.0/8\"]\n[server.strikes]\nenabled = true\nlog_only = false\nthreshold = 2\nwindow_secs = 60\nban_secs = 60\n",
        "",
    )
    .await;
    // Visitor 1.2.3.4 trips the unknown-host threshold.
    for _ in 0..2 {
        let r = send_request(
            rook.addr,
            "GET / HTTP/1.1\r\nHost: unknown.example\r\nCF-Connecting-IP: 1.2.3.4\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert_eq!(r.status, 404);
    }
    // Visitor 1.2.3.4 is now banned even on the real site.
    let r = send_request(
        rook.addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nCF-Connecting-IP: 1.2.3.4\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(r.status, 403);
    // Visitor 5.6.7.8 is unaffected — and the proxy itself was never
    // struck, or every visitor would be banned now.
    let r = send_request(
        rook.addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nCF-Connecting-IP: 5.6.7.8\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(r.status, 200);
}

/// An upstream that keeps its side of the connection open, so the
/// pool has something to reuse: serves request after request on one
/// connection until the peer goes away.
async fn spawn_keepalive_upstream() -> (SocketAddr, TaskGuard) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                loop {
                    let mut peek = [0u8; 1];
                    match stream.peek(&mut peek).await {
                        Ok(0) | Err(_) => return, // peer closed
                        Ok(_) => {}
                    }
                    let _ = read_head(&mut stream).await;
                    let body = b"ok";
                    let response =
                        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                    if stream.write_all(response.as_bytes()).await.is_err() {
                        return;
                    }
                    if stream.write_all(body).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (addr, TaskGuard(task))
}

/// Scrape a counter off the metrics listener.
async fn metric_value(addr: SocketAddr, name: &str) -> u64 {
    let response = send_request(
        addr,
        "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    let body = String::from_utf8_lossy(&response.body).into_owned();
    body.lines()
        .find_map(|line| line.strip_prefix(name))
        .and_then(|rest| rest.trim().parse().ok())
        .unwrap_or_else(|| panic!("metric {name} missing from {body}"))
}

#[tokio::test]
async fn steady_state_reuses_upstream_connections() {
    // Harry's churn test (saturation window 2026-11-13): at steady
    // state the pool must absorb the load — connections opened per
    // request far below 1% — and must stop growing when load stops.
    let (upstream, _upstream_task) = spawn_keepalive_upstream().await;
    let metrics = free_addr().await;
    let rook = spawn_rook(
        &[upstream],
        // The limiter is not the thing under test; the pool is.
        &format!("requests_per_second = 1000000\nrequest_burst = 1000000\n\n[metrics]\nenabled = true\nlisten = \"{metrics}\"\n"),
        "",
    )
    .await;

    // Warm the pool past the working set.
    for _ in 0..64 {
        let r = send_request(
            rook.addr,
            "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert_eq!(r.status, 200);
    }
    let opened_before = metric_value(metrics, "rook_upstream_connections_opened_total").await;

    // Steady state: 2000 requests, 16 concurrent — inside the default
    // pool of 32, so almost no new upstream connections may open.
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let addr = rook.addr;
        tasks.spawn(async move {
            for _ in 0..125 {
                let r = send_request(
                    addr,
                    "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
                )
                .await;
                assert_eq!(r.status, 200);
            }
        });
    }
    while tasks.join_next().await.is_some() {}

    let opened_after = metric_value(metrics, "rook_upstream_connections_opened_total").await;
    let delta = opened_after - opened_before;
    assert!(
        delta * 100 < 2000,
        "steady state opened {delta} upstream connections for 2000 requests (limit 1%)"
    );

    // And once load stops the pool stops growing: two scrapes a second
    // apart see the same counter.
    sleep(Duration::from_secs(1)).await;
    let idle_a = metric_value(metrics, "rook_upstream_connections_opened_total").await;
    sleep(Duration::from_secs(1)).await;
    let idle_b = metric_value(metrics, "rook_upstream_connections_opened_total").await;
    assert_eq!(idle_a, idle_b, "pool kept opening connections while idle");
}

#[tokio::test]
async fn pooled_connections_expire_after_the_idle_timeout() {
    // Harry's two-assertion test (2026-11-13): the opened counter is
    // the only observable the client exposes, so a warm request must
    // NOT increment it and a post-timeout request MUST. Fails if the
    // timeout is absent (counter stays flat after the idle period) or
    // too short (warm request churns).
    let (upstream, _upstream_task) = spawn_keepalive_upstream().await;
    let metrics = free_addr().await;
    let rook = spawn_rook(
        &[upstream],
        &format!("upstream_pool_idle_timeout = 2\n\n[metrics]\nenabled = true\nlisten = \"{metrics}\"\n"),
        "",
    )
    .await;

    let warm = send_request(
        rook.addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(warm.status, 200);
    let opened_after_warm = metric_value(metrics, "rook_upstream_connections_opened_total").await;

    // Warm pool: the next request reuses the pooled connection.
    let warm2 = send_request(
        rook.addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(warm2.status, 200);
    let opened_warm_again = metric_value(metrics, "rook_upstream_connections_opened_total").await;
    assert_eq!(
        opened_warm_again, opened_after_warm,
        "warm request opened a new upstream connection"
    );

    // Past the idle timeout the pooled connection is gone, so the next
    // request must open exactly one.
    sleep(Duration::from_secs(4)).await;
    let cold = send_request(
        rook.addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(cold.status, 200);
    let opened_after_idle = metric_value(metrics, "rook_upstream_connections_opened_total").await;
    assert_eq!(
        opened_after_idle,
        opened_warm_again + 1,
        "post-timeout request did not open exactly one new upstream connection"
    );
}

#[tokio::test]
async fn upstream_connect_refusal_is_503_with_retry_after() {
    // A dead upstream refuses the connection: that is overload-shaped,
    // so the answer is 503 with Retry-After, not 502 (Thomas,
    // saturation window 2026-11-13).
    let dead = free_addr().await; // bound, then dropped: refuses connects
    let rook = spawn_rook(&[dead], "", "").await;
    let r = send_request(
        rook.addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(r.status, 503);
    assert_eq!(r.header("retry-after"), Some("1"));
}
