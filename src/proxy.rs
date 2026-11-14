use std::{
    collections::HashMap,
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use bytes::Bytes;
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri,
    header::{
        CONNECTION, CONTENT_LENGTH, COOKIE, HOST, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY,
        SEC_WEBSOCKET_VERSION, UPGRADE,
    },
};
use http_body_util::{BodyExt, Full, Limited, combinators::BoxBody};
use hyper::body::{Body, Incoming};
use hyper_util::{
    client::legacy::{Client, Error as ClientError, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo, TokioTimer},
};
use ipnet::IpNet;
use sha1::{Digest, Sha1};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::{Notify, broadcast},
    time::timeout,
};
use tracing::{debug, warn};

use crate::{
    acme::ChallengeStore,
    body::{
        BoxError, IdleBody,
        activity::{ActivityGuard, ConnectionActivity, UploadTracker, UpstreamWaitGuard},
    },
    config::{Config, RouteConfig},
    limit::{
        ClientUpstreamLimiter, ClientUpstreamPermit, ConnectionLimiter, ConnectionPermit,
        RateLimiter, UpstreamLimiter, UpstreamPermit,
    },
    path::{normalize_path, route_matches, upstream_uri},
};

type RequestBody = Pin<Box<dyn Body<Data = Bytes, Error = BoxError> + Send + 'static>>;
pub type ResponseBody = BoxBody<Bytes, BoxError>;
type ProxyClient = Client<GuardedConnector, RequestBody>;
type ProxyResult = Result<Response<ResponseBody>, ProxyError>;

/// An HTTP connector that refuses to dial the metrics listener.
///
/// Thomas's guard: loopback isn't private on a reverse proxy — a route
/// whose upstream resolves to the metrics listener's address would
/// publish `/metrics` through the proxy even though the listener only
/// binds loopback. IP-literal upstreams are rejected at config load
/// (`config::reject_metrics_upstream`); this is the connect-time half
/// for names that resolve to the listener later, and for the WebSocket
/// dial path, which checks the same `blocked` address after
/// `TcpStream::connect`. `None` disables the check (metrics off).
#[derive(Clone)]
pub struct GuardedConnector {
    inner: HttpConnector,
    blocked: Option<SocketAddr>,
    metrics: crate::metrics::Metrics,
}

impl GuardedConnector {
    /// Is this resolved address the metrics listener?
    fn is_blocked(blocked: Option<SocketAddr>, peer: SocketAddr) -> bool {
        blocked.is_some_and(|blocked| {
            blocked.port() == peer.port() && blocked.ip() == peer.ip().to_canonical()
        })
    }

    fn refused() -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "upstream resolved to the metrics listener; refusing to proxy to it",
        )
    }
}

impl tower_service::Service<Uri> for GuardedConnector {
    type Response = TokioIo<TcpStream>;
    type Error = BoxError;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let blocked = self.blocked;
        let metrics = self.metrics.clone();
        let connect = self.inner.call(uri);
        Box::pin(async move {
            let stream = connect.await?;
            // A fresh upstream TCP connection: pooled reuse never
            // reaches the connector, so this counter is the churn
            // meter (connections opened per request, vs the request
            // counter, should sit far below 1 at steady state).
            metrics.upstream_connection_opened();
            let peer = stream.inner().peer_addr()?;
            if Self::is_blocked(blocked, peer) {
                return Err(Self::refused().into());
            }
            Ok(stream)
        })
    }
}

#[derive(Clone)]
pub struct ConnectionLease(pub Arc<ConnectionPermit>);

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum RequestScheme {
    Http,
    Https,
}

#[derive(Clone)]
pub struct TlsServerName(pub String);

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];
/// Upstream response headers stripped because they disclose what runs
/// behind the proxy — a scanner reads the backend's name and version
/// straight off our TLS endpoint. A separate concept from `HOP_BY_HOP`:
/// those must not be forwarded because of framing semantics, these
/// forward fine and are removed for disclosure, which is why the list
/// is named its own thing. A site can opt back in per header with
/// `preserve_upstream_headers` (an app that legitimately surfaces its
/// own `Server`).
pub const DISCLOSURE_HEADERS: &[&str] = &["server", "x-powered-by"];
const FORWARDED: &[&str] = &[
    "forwarded",
    "x-original-url",
    "x-rewrite-url",
    "x-real-ip",
    "cf-connecting-ip",
    "true-client-ip",
    "x-client-ip",
    "x-cluster-client-ip",
    "x-host",
    "front-end-https",
];
const WEBSOCKET_MAGIC: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub struct AppState {
    pub config: Arc<Config>,
    pub metrics: crate::metrics::Metrics,
    sites: HashMap<String, Arc<Site>>,
    client: ProxyClient,
    pub connections: ConnectionLimiter,
    pub acme_challenges: ChallengeStore,
    rates: RateLimiter,
    /// Server-wide strikes: malformed requests, unknown hosts, failed
    /// handshakes (pre-site offences).
    strikes_global: crate::strike::StrikeTracker,
    upstreams: UpstreamLimiter,
    client_upstreams: ClientUpstreamLimiter,
    shutdown: broadcast::Sender<()>,
    active_tunnels: AtomicUsize,
    tunnel_notify: Notify,
}

struct Site {
    routes: Vec<Route>,
    redirect_https: bool,
    /// The site's strike rules; `None` when the site leaves them
    /// disabled.
    strikes: Option<crate::strike::StrikeTracker>,
    /// Normalized trap paths (a set, so the hot path is one lookup).
    trap_paths: std::collections::HashSet<String>,
    /// Disclosure headers this site chose to keep (config-validated).
    preserve_upstream: Arc<[http::HeaderName]>,
}

struct Route {
    id: usize,
    config: RouteConfig,
    next_upstream: AtomicUsize,
}

struct UpstreamPermits {
    _global: UpstreamPermit,
    _client: ClientUpstreamPermit,
}

struct WebSocketUpgrade {
    request: Request<RequestBody>,
    downstream: hyper::upgrade::OnUpgrade,
    base: Uri,
    key: String,
    lease: Option<ConnectionLease>,
    permits: UpstreamPermits,
    activity: Option<ActivityGuard>,
    upload_tracker: UploadTracker,
    upstream_wait: Option<UpstreamWaitGuard>,
    preserve_upstream: Arc<[http::HeaderName]>,
}

struct RequestPreparation {
    uri: Uri,
    host: String,
    client_ip: IpAddr,
    websocket: bool,
    max_body: u64,
    idle: Duration,
    upload_activity: Option<ActivityGuard>,
}

impl AppState {
    pub fn new(config: Config) -> Arc<Self> {
        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(config.server.upstream_connect_timeout));
        connector.enforce_http(true);
        // Nagle off: proxied requests are written whole and the response
        // is wanted immediately; with it on, FreeBSD's delayed ACK adds
        // ~100ms of wall-clock per hop with the CPU idle (measured on the
        // n2 window 2026-11-14: same cell, 10.3k rps vs 7.2k).
        connector.set_nodelay(true);
        let metrics = crate::metrics::Metrics::default();
        let blocked = config.metrics.enabled.then_some(config.metrics.listen);
        let connector = GuardedConnector {
            inner: connector,
            blocked,
            metrics: metrics.clone(),
        };
        let client = Client::builder(TokioExecutor::new())
            .http1_max_buf_size(config.server.max_header_bytes)
            .http1_max_headers(100)
            .pool_max_idle_per_host(config.server.upstream_pool_idle)
            // The timer is what makes the timeout real: without it the
            // pool's idle reaper never runs and expired connections are
            // only cleared on the next checkout (measured on the n2
            // window 2026-11-14: 8,350 sockets parked for minutes after
            // load stopped, reaped instantly by one probe request).
            .pool_idle_timeout(config.server.upstream_pool_idle_timeout)
            .pool_timer(TokioTimer::new())
            .build(connector);

        // The exempt set is the operator allowlist plus the trusted
        // proxies and Cloudflare ranges: a proxy in front of a site must
        // never ban itself and take the site down.
        let strike_exempt: Vec<ipnet::IpNet> = config
            .server
            .strike_allowlist
            .iter()
            .chain(config.server.trusted_proxies.iter())
            .chain(config.server.cloudflare_ranges.iter())
            .cloned()
            .collect();
        let mut sites = HashMap::new();
        let mut route_id = 0;
        for site_config in &config.sites {
            let mut routes: Vec<_> = site_config
                .routes
                .iter()
                .cloned()
                .map(|route| {
                    let id = route_id;
                    route_id += 1;
                    Route {
                        id,
                        config: route,
                        next_upstream: AtomicUsize::new(0),
                    }
                })
                .collect();
            routes.sort_by_key(|route| std::cmp::Reverse(route.config.prefix.len()));
            let strikes = site_config.strikes.enabled.then(|| {
                // The scope label is the site's first configured host:
                // operator-supplied, bounded by the configuration, and
                // never request-derived. Metrics and log lines share it.
                let scope = site_config.hosts.first().cloned().unwrap_or_default();
                let tracker = crate::strike::StrikeTracker::new(
                    crate::strike::StrikeRules::from(&site_config.strikes),
                    config.server.max_tracked_clients,
                    std::time::Duration::from_secs(300),
                    strike_exempt.clone(),
                    scope.clone(),
                );
                metrics.register_strikes(scope, tracker.clone());
                tracker
            });
            let site = Arc::new(Site {
                routes,
                redirect_https: config.server.https_listen.is_some(),
                strikes,
                trap_paths: site_config.strikes.trap_paths.iter().cloned().collect(),
                preserve_upstream: site_config
                    .preserve_upstream_headers
                    .iter()
                    // Config validation restricts entries to known header
                    // names, so this parse cannot fail.
                    .map(|name| http::HeaderName::from_bytes(name.as_bytes()).unwrap())
                    .collect(),
            });
            for host in &site_config.hosts {
                sites.insert(host.clone(), Arc::clone(&site));
            }
        }

        let (shutdown, _) = broadcast::channel(16);
        let upstream_count = config
            .sites
            .iter()
            .flat_map(|site| &site.routes)
            .map(|route| route.upstreams.len())
            .sum();
        let strikes_global = crate::strike::StrikeTracker::new(
            crate::strike::StrikeRules::from(&config.server.strikes),
            config.server.max_tracked_clients,
            std::time::Duration::from_secs(300),
            strike_exempt,
            "global".to_owned(),
        );
        metrics.register_strikes("global".to_owned(), strikes_global.clone());
        Arc::new(Self {
            strikes_global,
            connections: ConnectionLimiter::new(
                config.server.max_connections,
                config.server.max_connections_per_ip,
                config.server.max_tracked_clients,
            ),
            acme_challenges: ChallengeStore::default(),
            rates: RateLimiter::new(config.server.max_tracked_clients),
            upstreams: UpstreamLimiter::new(
                config.server.max_connections_per_upstream,
                upstream_count,
            ),
            client_upstreams: ClientUpstreamLimiter::new(
                config.server.max_upstream_per_ip,
                upstream_count * config.server.max_tracked_clients,
            ),
            shutdown,
            active_tunnels: AtomicUsize::new(0),
            tunnel_notify: Notify::new(),
            config: Arc::new(config),
            sites,
            client,
            metrics,
        })
    }

    /// Open WebSocket tunnels, for the metrics endpoint.
    pub fn active_tunnels(&self) -> usize {
        self.active_tunnels.load(Ordering::Relaxed)
    }

    /// The server-wide strike tracker (failed handshakes strike from the
    /// accept path in `server`).
    pub fn strikes_global(&self) -> crate::strike::StrikeTracker {
        self.strikes_global.clone()
    }

    pub async fn handle(
        self: Arc<Self>,
        peer: SocketAddr,
        request: Request<Incoming>,
    ) -> Result<Response<ResponseBody>, Infallible> {
        self.metrics.request();
        // A globally banned client is dropped before any work. Request-
        // level bans key on the verified client IP — the same value rate
        // limiting trusts — so a Cloudflare-fronted site bans the
        // visitor, not the edge (the edge itself is exempt).
        let client_ip = match verified_client_ip(
            peer.ip().to_canonical(),
            request.headers(),
            &self.config.server.trusted_proxies,
            &self.config.server.cloudflare_ranges,
        ) {
            Ok(ip) => ip,
            Err(error) => {
                // A malformed forwarding header is a malformed request.
                self.strikes_global
                    .strike(peer.ip(), crate::strike::StrikeReason::MalformedRequest);
                let response = error.into_response();
                self.metrics.response(response.status().as_u16());
                return Ok(response);
            }
        };
        if self.strikes_global.is_banned(client_ip) {
            let response = text_response(StatusCode::FORBIDDEN, "banned".to_string());
            self.metrics.response(response.status().as_u16());
            return Ok(response);
        }
        let secure = request
            .extensions()
            .get::<RequestScheme>()
            .is_some_and(|scheme| *scheme == RequestScheme::Https);
        let connection_activity = request.extensions().get::<ConnectionActivity>().cloned();
        let activity = connection_activity
            .as_ref()
            .map(|activity| activity.begin());
        let upload_activity = connection_activity
            .as_ref()
            .map(|activity| activity.begin());
        let upstream_wait = connection_activity
            .as_ref()
            .map(|activity| activity.begin_upstream_wait());
        let config = Arc::clone(&self.config);
        let strikes = self.strikes_global.clone();
        let mut response = match Arc::clone(&self)
            .handle_inner(
                peer,
                client_ip,
                request,
                activity,
                upload_activity,
                upstream_wait,
            )
            .await
        {
            Ok(response) => response,
            Err(error) => {
                // The pre-site offences strike the server-wide tracker.
                match error {
                    ProxyError::BadRequest => {
                        strikes.strike(client_ip, crate::strike::StrikeReason::MalformedRequest);
                    }
                    ProxyError::UnknownHost => {
                        strikes.strike(client_ip, crate::strike::StrikeReason::UnknownHost);
                    }
                    ProxyError::BadGateway
                    | ProxyError::UpstreamUnavailable
                    | ProxyError::Timeout => {
                        self.metrics.upstream_failed();
                    }
                    _ => {}
                }
                error.into_response()
            }
        };
        self.metrics.response(response.status().as_u16());
        if secure {
            apply_hsts(&mut response, &config);
        }
        Ok(response)
    }

    async fn handle_inner(
        self: Arc<Self>,
        peer: SocketAddr,
        client_ip: IpAddr,
        mut request: Request<Incoming>,
        activity: Option<ActivityGuard>,
        upload_activity: Option<ActivityGuard>,
        upstream_wait: Option<UpstreamWaitGuard>,
    ) -> ProxyResult {
        let mut content_lengths = request.headers().get_all(CONTENT_LENGTH).iter();
        let first_length = content_lengths.next();
        if first_length.is_some()
            && (request.headers().contains_key("transfer-encoding")
                || content_lengths.next().is_some()
                || first_length
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok())
                    .is_none())
        {
            return Err(ProxyError::BadRequest);
        }
        if request
            .headers()
            .keys()
            .any(|name| name.as_str().contains('_'))
        {
            return Err(ProxyError::BadRequest);
        }
        let host = request_host(&request)?;
        if request
            .extensions()
            .get::<TlsServerName>()
            .is_some_and(|server_name| {
                server_name
                    .0
                    .strip_suffix('.')
                    .unwrap_or(&server_name.0)
                    .to_ascii_lowercase()
                    != host.name
            })
        {
            return Err(ProxyError::MisdirectedRequest);
        }
        let site = self.sites.get(&host.name).ok_or(ProxyError::UnknownHost)?;
        if let Some(tracker) = &site.strikes
            && tracker.is_banned(client_ip)
        {
            return Err(ProxyError::Banned);
        }
        let path = normalize_path(request.uri().path()).map_err(|_| ProxyError::BadRequest)?;
        if let Some(tracker) = &site.strikes
            && site.trap_paths.contains(&path)
        {
            tracker.strike(client_ip, crate::strike::StrikeReason::TrapPath);
            return Err(ProxyError::NotFound);
        }
        if let Some(token) = path.strip_prefix("/.well-known/acme-challenge/")
            && !token.is_empty()
            && !token.contains('/')
            && let Some(authorization) = self.acme_challenges.get(&host.name, token)
        {
            return Ok(text_response(StatusCode::OK, authorization));
        }
        if site.redirect_https
            && !request
                .extensions()
                .get::<RequestScheme>()
                .is_some_and(|scheme| *scheme == RequestScheme::Https)
        {
            let port = self
                .config
                .server
                .https_listen
                .map(|address| address.port())
                .unwrap_or(443);
            return Ok(https_redirect(
                &host.name,
                &path,
                request.uri().query(),
                port,
            ));
        }
        let route = site.route(&path).ok_or(ProxyError::NotFound)?;
        let rate = route
            .config
            .requests_per_second
            .unwrap_or(self.config.server.requests_per_second);
        let burst = route
            .config
            .request_burst
            .unwrap_or(self.config.server.request_burst);
        if !self.rates.check(client_ip, route.id, rate, burst) {
            return Err(ProxyError::RateLimited);
        }

        let upgrade = websocket_upgrade(&request)?;
        if upgrade && !route.config.websocket {
            return Err(ProxyError::BadRequest);
        }
        let websocket_key = if upgrade {
            validate_websocket(&request, &route.config)?;
            request_key(request.headers())
        } else {
            None
        };
        if request
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|length| length > self.config.server.max_request_body_bytes)
        {
            return Err(ProxyError::BodyTooLarge);
        }

        let (base, permits) = self.select_upstream(route, client_ip)?;
        let uri = upstream_uri(&base, &path, request.uri().query())
            .map_err(|_| ProxyError::BadRequest)?;
        let downstream_upgrade = upgrade.then(|| hyper::upgrade::on(&mut request));
        let connection_lease = upgrade
            .then(|| request.extensions().get::<ConnectionLease>().cloned())
            .flatten();
        let (request, upload_tracker) = prepare_request(
            request,
            RequestPreparation {
                uri,
                host: host.authority,
                client_ip,
                websocket: upgrade,
                max_body: self.config.server.max_request_body_bytes,
                idle: self.config.server.idle_timeout,
                upload_activity,
            },
        )?;

        // End the borrow of `self` (site, route) before the branches
        // below move the `Arc<Self>` receiver.
        let preserve_upstream = site.preserve_upstream.clone();
        if upgrade {
            self.proxy_websocket(WebSocketUpgrade {
                request,
                downstream: downstream_upgrade.expect("checked above"),
                base,
                key: websocket_key.expect("validated above"),
                lease: connection_lease,
                permits,
                activity,
                upload_tracker: upload_tracker.clone(),
                upstream_wait,
                preserve_upstream,
            })
            .await
        } else {
            self.proxy_http(
                request,
                permits,
                activity,
                upload_tracker,
                upstream_wait,
                preserve_upstream,
            )
            .await
        }
    }

    fn select_upstream(
        &self,
        route: &Route,
        client_ip: IpAddr,
    ) -> Result<(Uri, UpstreamPermits), ProxyError> {
        for _ in 0..route.config.upstreams.len() {
            let index = route.next_upstream_index();
            if let Some(global) = self.upstreams.acquire(route.id, index)
                && let Some(client) = self.client_upstreams.acquire(client_ip, route.id, index)
            {
                return Ok((
                    route.config.upstreams[index].clone(),
                    UpstreamPermits {
                        _global: global,
                        _client: client,
                    },
                ));
            }
        }
        Err(ProxyError::UpstreamUnavailable)
    }

    async fn proxy_http(
        &self,
        request: Request<RequestBody>,
        permits: UpstreamPermits,
        activity: Option<ActivityGuard>,
        upload_tracker: UploadTracker,
        upstream_wait: Option<UpstreamWaitGuard>,
        preserve_upstream: Arc<[http::HeaderName]>,
    ) -> ProxyResult {
        let _upstream_wait = upstream_wait;
        let started = std::time::Instant::now();
        let response = with_upload_timeout(
            &upload_tracker,
            self.config.server.request_timeout,
            self.config.server.idle_timeout,
            self.client.request(request),
        )
        .await;
        // Success or failure, the observation lands in the histogram:
        // a success-only latency flatters a degrading upstream.
        self.metrics
            .upstream_latency(crate::metrics::UpstreamKind::Http, started.elapsed());
        let response = response?.map_err(upstream_client_error)?;
        Ok(map_response(
            response,
            self.config.server.idle_timeout,
            Some(permits),
            activity,
            &preserve_upstream,
        ))
    }

    async fn proxy_websocket(self: Arc<Self>, upgrade: WebSocketUpgrade) -> ProxyResult {
        let WebSocketUpgrade {
            request,
            downstream,
            base,
            key: websocket_key,
            lease: connection_lease,
            permits: upstream_permits,
            activity,
            upload_tracker,
            upstream_wait,
            preserve_upstream,
        } = upgrade;
        let _upstream_wait = upstream_wait;
        let authority = base.authority().ok_or(ProxyError::BadGateway)?.clone();
        let started = std::time::Instant::now();
        let stream = match timeout(
            self.config.server.upstream_connect_timeout,
            TcpStream::connect(authority.as_str()),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            result => {
                // Connect failures land in the latency histogram too —
                // a success-only distribution flatters a degrading
                // upstream (Harry, review of PR #8).
                self.metrics
                    .upstream_latency(crate::metrics::UpstreamKind::WebSocket, started.elapsed());
                return match result {
                    Ok(Err(_)) => Err(ProxyError::BadGateway),
                    _ => Err(ProxyError::Timeout),
                };
            }
        };
        // Small frames travel this leg interactively; Nagle would stall
        // each unacknowledged segment against delayed ACK (Harry, #19).
        let _ = stream.set_nodelay(true);
        // Tunnels carry no forwarding headers, so the metrics handler's
        // header guard can never fire for them: the connect-time check
        // is the only thing between a tunnel and the metrics listener.
        // It must fail CLOSED — an unnamed peer on an established socket
        // is anomalous (Thomas, review of PR #7), so an error refuses
        // the tunnel and is recorded, not silently passed. No test can
        // reach the error arm through the public path: a connected
        // socket's peer_addr does not fail on demand.
        let blocked = self
            .config
            .metrics
            .enabled
            .then_some(self.config.metrics.listen);
        match stream.peer_addr() {
            Ok(peer) if GuardedConnector::is_blocked(blocked, peer) => {
                debug!(%peer, "WebSocket upstream resolved to the metrics listener; refusing");
                self.metrics.upstream_failed();
                return Err(ProxyError::BadGateway);
            }
            Ok(_) => {}
            Err(error) => {
                warn!(%error, "WebSocket upstream has no peer address; refusing the tunnel");
                self.metrics.upstream_failed();
                return Err(ProxyError::BadGateway);
            }
        }
        let (mut sender, connection) =
            match hyper::client::conn::http1::handshake(TokioIo::new(stream)).await {
                Ok(parts) => parts,
                Err(_) => {
                    self.metrics.upstream_latency(
                        crate::metrics::UpstreamKind::WebSocket,
                        started.elapsed(),
                    );
                    return Err(ProxyError::BadGateway);
                }
            };
        let connection_task = tokio::spawn(async move {
            if let Err(error) = connection.with_upgrades().await {
                debug!(error = %error, "WebSocket upstream connection ended");
            }
        });

        let (mut parts, body) = request.into_parts();
        parts.uri = parts
            .uri
            .path_and_query()
            .cloned()
            .map(Uri::from)
            .ok_or(ProxyError::BadRequest)?;
        let request = Request::from_parts(parts, body);
        let response = with_upload_timeout(
            &upload_tracker,
            self.config.server.request_timeout,
            self.config.server.idle_timeout,
            sender.send_request(request),
        )
        .await;
        self.metrics
            .upstream_latency(crate::metrics::UpstreamKind::WebSocket, started.elapsed());
        let mut response = match response {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                connection_task.abort();
                return Err(upstream_request_error(error));
            }
            Err(_) => {
                connection_task.abort();
                return Err(ProxyError::Timeout);
            }
        };

        if response.status() != StatusCode::SWITCHING_PROTOCOLS {
            return Ok(map_response(
                response,
                self.config.server.idle_timeout,
                Some(upstream_permits),
                activity,
                &preserve_upstream,
            ));
        }
        if !valid_websocket_upgrade(response.headers(), &websocket_key) {
            connection_task.abort();
            return Err(ProxyError::BadGateway);
        }

        let upstream = hyper::upgrade::on(&mut response);
        let idle = self.config.server.websocket_idle_timeout;
        let lifetime = self.config.server.websocket_max_lifetime;
        let state = Arc::clone(&self);
        state.active_tunnels.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(async move {
            let _connection_lease = connection_lease;
            let _upstream_permits = upstream_permits;
            let _activity = activity;
            let _guard = TunnelGuard {
                state: Arc::clone(&state),
            };
            let mut shutdown = state.shutdown.subscribe();
            tokio::select! {
                result = timeout(lifetime, tunnel(downstream, upstream, idle)) => {
                    match result {
                        Ok(Ok(())) => debug!("WebSocket tunnel closed"),
                        Ok(Err(error)) => debug!(error = %error, "WebSocket tunnel ended with an error"),
                        Err(_) => debug!("WebSocket tunnel reached its maximum lifetime"),
                    }
                }
                _ = shutdown.recv() => debug!("WebSocket tunnel closed during shutdown"),
            }
            connection_task.abort();
        });
        Ok(map_response(response, idle, None, None, &preserve_upstream))
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown.send(());
    }

    pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown.subscribe()
    }

    pub async fn wait_for_tunnels(&self) {
        loop {
            let notified = self.tunnel_notify.notified();
            if self.active_tunnels.load(Ordering::Relaxed) == 0 {
                return;
            }
            notified.await;
        }
    }
}

struct TunnelGuard {
    state: Arc<AppState>,
}

impl Drop for TunnelGuard {
    fn drop(&mut self) {
        self.state.active_tunnels.fetch_sub(1, Ordering::Relaxed);
        self.state.tunnel_notify.notify_waiters();
    }
}

impl Site {
    fn route(&self, path: &str) -> Option<&Route> {
        self.routes
            .iter()
            .find(|route| route_matches(&route.config.prefix, path))
    }
}

impl Route {
    fn next_upstream_index(&self) -> usize {
        self.next_upstream.fetch_add(1, Ordering::Relaxed) % self.config.upstreams.len()
    }
}

#[derive(Debug)]
enum ProxyError {
    BadRequest,
    MisdirectedRequest,
    UnknownHost,
    /// The client is banned at this site.
    Banned,
    NotFound,
    Forbidden,
    RateLimited,
    BodyTooLarge,
    BadGateway,
    UpstreamUnavailable,
    Timeout,
}

impl ProxyError {
    fn into_response(self) -> Response<ResponseBody> {
        let status = match self {
            Self::BadRequest => StatusCode::BAD_REQUEST,
            Self::MisdirectedRequest => StatusCode::MISDIRECTED_REQUEST,
            Self::UnknownHost | Self::NotFound => StatusCode::NOT_FOUND,
            Self::Banned => StatusCode::FORBIDDEN,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::BadGateway => StatusCode::BAD_GATEWAY,
            Self::UpstreamUnavailable => {
                let mut response = empty_response(StatusCode::SERVICE_UNAVAILABLE);
                // Static and cheap: the point is that well-behaved
                // clients back off, not precision about the deadline.
                response.headers_mut().insert(
                    http::header::RETRY_AFTER,
                    http::HeaderValue::from_static("1"),
                );
                return response;
            }
            Self::Timeout => StatusCode::GATEWAY_TIMEOUT,
        };
        empty_response(status)
    }
}

struct RequestHost {
    name: String,
    authority: String,
}

fn request_host(request: &Request<Incoming>) -> Result<RequestHost, ProxyError> {
    let mut hosts = request.headers().get_all(HOST).iter();
    let host_header = hosts.next();
    if hosts.next().is_some() {
        return Err(ProxyError::BadRequest);
    }
    let host_header = host_header
        .map(|value| value.to_str().map_err(|_| ProxyError::BadRequest))
        .transpose()?;
    let uri_authority = request
        .uri()
        .authority()
        .map(|authority| authority.as_str());
    if let (Some(host), Some(authority)) = (host_header, uri_authority)
        && normalize_authority(host)? != normalize_authority(authority)?
    {
        return Err(ProxyError::BadRequest);
    }
    let authority = host_header
        .or(uri_authority)
        .ok_or(ProxyError::BadRequest)?;
    Ok(RequestHost {
        name: normalize_authority(authority)?,
        authority: authority.to_owned(),
    })
}

fn normalize_authority(value: &str) -> Result<String, ProxyError> {
    let value = value.trim();
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(ProxyError::BadRequest);
    }
    let host = if let Some(rest) = value.strip_prefix('[') {
        let end = rest.find(']').ok_or(ProxyError::BadRequest)?;
        let suffix = &rest[end + 1..];
        if !suffix.is_empty()
            && (!suffix.starts_with(':')
                || suffix.len() == 1
                || !suffix[1..].bytes().all(|byte| byte.is_ascii_digit()))
        {
            return Err(ProxyError::BadRequest);
        }
        &rest[..end]
    } else {
        match value.rsplit_once(':') {
            Some((host, port))
                if !host.contains(':')
                    && !port.is_empty()
                    && port.bytes().all(|byte| byte.is_ascii_digit()) =>
            {
                host
            }
            Some(_) => return Err(ProxyError::BadRequest),
            None => value,
        }
    };
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || !host.is_ascii() {
        return Err(ProxyError::BadRequest);
    }
    Ok(host.to_ascii_lowercase())
}

// `trusted_proxies` means "proxies we run that faithfully pass on the
// visitor's address". A host allowed through pf but not listed here reaches
// Rook as itself and cannot claim another identity through any header.
// `cloudflare_ranges` is the subset permitted to speak CF-Connecting-IP on
// the visitor's behalf; the trusted-peer test covers the UNION of both
// lists, so a Cloudflare edge is still walked past in X-Forwarded-For even
// when the operator keeps the two lists separate.
fn verified_client_ip(
    peer: IpAddr,
    headers: &HeaderMap,
    trusted: &[IpNet],
    cloudflare: &[IpNet],
) -> Result<IpAddr, ProxyError> {
    let peer = peer.to_canonical();
    let is_trusted = |ip: IpAddr| {
        trusted
            .iter()
            .chain(cloudflare.iter())
            .any(|network| network.contains(&ip))
    };
    if !is_trusted(peer) {
        return Ok(peer);
    }

    // Peer membership first: a non-Cloudflare peer's CF-Connecting-IP is
    // ignored without being parsed, so junk in that header never turns a
    // legitimate trusted peer's traffic into 400s.
    if cloudflare.iter().any(|network| network.contains(&peer)) {
        let mut cloudflare_header = headers.get_all("cf-connecting-ip").iter();
        if let Some(value) = cloudflare_header.next() {
            if cloudflare_header.next().is_some() {
                return Err(ProxyError::BadRequest);
            }
            return value
                .to_str()
                .map_err(|_| ProxyError::BadRequest)?
                .parse::<IpAddr>()
                .map(|ip| ip.to_canonical())
                .map_err(|_| ProxyError::BadRequest);
        }
    }

    let mut addresses = Vec::new();
    for value in headers.get_all("x-forwarded-for") {
        let value = value.to_str().map_err(|_| ProxyError::BadRequest)?;
        for part in value.split(',') {
            addresses.push(
                part.trim()
                    .parse::<IpAddr>()
                    .map(|ip| ip.to_canonical())
                    .map_err(|_| ProxyError::BadRequest)?,
            );
        }
    }
    for address in addresses.iter().rev() {
        if !is_trusted(*address) {
            return Ok(*address);
        }
    }
    Ok(peer)
}

fn websocket_upgrade(request: &Request<Incoming>) -> Result<bool, ProxyError> {
    let connection_upgrade = connection_has_upgrade(request.headers());
    let upgrade = request.headers().get(UPGRADE);
    if upgrade.is_some() || connection_upgrade {
        let websocket = connection_upgrade
            && upgrade
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
        if !websocket {
            return Err(ProxyError::BadRequest);
        }
        return Ok(true);
    }
    Ok(false)
}

fn connection_has_upgrade(headers: &HeaderMap) -> bool {
    headers.get_all(CONNECTION).iter().any(|value| {
        value.to_str().ok().is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        })
    })
}

fn validate_websocket(request: &Request<Incoming>, route: &RouteConfig) -> Result<(), ProxyError> {
    if request.method() != Method::GET
        || request
            .headers()
            .get(SEC_WEBSOCKET_VERSION)
            .and_then(|value| value.to_str().ok())
            != Some("13")
    {
        return Err(ProxyError::BadRequest);
    }
    let valid_key = request
        .headers()
        .get(SEC_WEBSOCKET_KEY)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| BASE64.decode(value).ok())
        .is_some_and(|key| key.len() == 16);
    if !valid_key {
        return Err(ProxyError::BadRequest);
    }
    if !route.origins.is_empty() {
        let origin = request
            .headers()
            .get("origin")
            .and_then(|value| value.to_str().ok());
        if !origin.is_some_and(|origin| route.origins.iter().any(|allowed| allowed == origin)) {
            return Err(ProxyError::Forbidden);
        }
    }
    Ok(())
}

fn prepare_request(
    request: Request<Incoming>,
    preparation: RequestPreparation,
) -> Result<(Request<RequestBody>, UploadTracker), ProxyError> {
    let RequestPreparation {
        uri,
        host,
        client_ip,
        websocket,
        max_body,
        idle,
        upload_activity,
    } = preparation;
    let secure = request
        .extensions()
        .get::<RequestScheme>()
        .is_some_and(|scheme| *scheme == RequestScheme::Https);
    let (mut parts, body) = request.into_parts();
    let cookies: Vec<_> = parts.headers.get_all(COOKIE).iter().collect();
    if cookies.len() > 1 {
        let mut joined = Vec::new();
        for (index, value) in cookies.iter().enumerate() {
            if index > 0 {
                joined.extend_from_slice(b"; ");
            }
            joined.extend_from_slice(value.as_bytes());
        }
        parts.headers.insert(
            COOKIE,
            HeaderValue::from_bytes(&joined).map_err(|_| ProxyError::BadRequest)?,
        );
    }
    let mut connection_headers = Vec::new();
    for value in parts.headers.get_all(CONNECTION) {
        let value = value.to_str().map_err(|_| ProxyError::BadRequest)?;
        for name in value.split(',') {
            if let Ok(name) = HeaderName::from_bytes(name.trim().as_bytes()) {
                connection_headers.push(name);
            }
        }
    }
    for name in &connection_headers {
        if (websocket && (*name == CONNECTION || *name == UPGRADE)) || protected_header(name) {
            continue;
        }
        parts.headers.remove(name);
    }
    for name in HOP_BY_HOP {
        if websocket && (*name == "connection" || *name == "upgrade") {
            continue;
        }
        parts.headers.remove(*name);
    }
    for name in FORWARDED {
        parts.headers.remove(*name);
    }
    let forwarded_headers: Vec<_> = parts
        .headers
        .keys()
        .filter(|name| name.as_str().starts_with("x-forwarded-"))
        .cloned()
        .collect();
    for name in forwarded_headers {
        parts.headers.remove(name);
    }
    let ip = HeaderValue::from_str(&client_ip.to_string()).map_err(|_| ProxyError::BadRequest)?;
    parts.headers.insert("x-real-ip", ip.clone());
    parts.headers.insert("x-forwarded-for", ip);
    parts.headers.insert(
        "x-forwarded-proto",
        HeaderValue::from_static(if secure { "https" } else { "http" }),
    );
    parts.headers.insert(
        HOST,
        HeaderValue::from_str(&host).map_err(|_| ProxyError::BadRequest)?,
    );
    parts.uri = uri;
    parts.version = http::Version::HTTP_11;
    let limit = usize::try_from(max_body).unwrap_or(usize::MAX);
    let tracker = UploadTracker::new(body.is_end_stream());
    let mut idle_body =
        IdleBody::new(Limited::new(body, limit), idle).with_upload_tracker(tracker.clone());
    if let Some(upload_activity) = upload_activity {
        idle_body = idle_body.with_activity(upload_activity);
    }
    let body: RequestBody = Box::pin(idle_body);
    Ok((Request::from_parts(parts, body), tracker))
}

fn protected_header(name: &HeaderName) -> bool {
    *name == HOST
        || *name == CONTENT_LENGTH
        || matches!(
            name.as_str(),
            "authorization"
                | "cookie"
                | "sec-websocket-key"
                | "sec-websocket-version"
                | "sec-websocket-protocol"
                | "sec-websocket-extensions"
        )
}

/// Errors from the pooled client: a connect failure is the upstream
/// refusing load — answer 503 with Retry-After so overload reads as a
/// refusal, not a failure (Thomas, saturation window 2026-11-13).
/// Errors after the request was accepted stay 502.
fn upstream_client_error(error: ClientError) -> ProxyError {
    if error.is_connect() {
        debug!(error = %error, "upstream refused the connection");
        return ProxyError::UpstreamUnavailable;
    }
    upstream_request_error(error)
}

fn upstream_request_error(error: impl std::error::Error) -> ProxyError {
    debug!(error = %error, "upstream request failed");
    let mut source = std::error::Error::source(&error);
    while let Some(error) = source {
        if let Some(error) = error.downcast_ref::<std::io::Error>()
            && error.kind() == std::io::ErrorKind::TimedOut
        {
            return ProxyError::Timeout;
        }
        source = error.source();
    }
    ProxyError::BadGateway
}

async fn with_upload_timeout<F, T>(
    tracker: &UploadTracker,
    duration: Duration,
    idle: Duration,
    future: F,
) -> Result<T, ProxyError>
where
    F: std::future::Future<Output = T>,
{
    tokio::pin!(future);
    tokio::select! {
        result = future => Ok(result),
        _ = tracker.wait_for_timeout(duration) => Err(ProxyError::Timeout),
        _ = async {
            if tracker.wait_for_idle_timeout(idle).await.is_ok() {
                std::future::pending::<()>().await
            }
        } => Err(ProxyError::Timeout),
    }
}

async fn tunnel(
    downstream: hyper::upgrade::OnUpgrade,
    upstream: hyper::upgrade::OnUpgrade,
    idle: Duration,
) -> Result<(), BoxError> {
    let (downstream, upstream) = tokio::try_join!(downstream, upstream)?;
    let (downstream_read, downstream_write) = tokio::io::split(TokioIo::new(downstream));
    let (upstream_read, upstream_write) = tokio::io::split(TokioIo::new(upstream));
    let client_to_upstream = copy_with_idle(downstream_read, upstream_write, idle);
    let upstream_to_client = copy_with_idle(upstream_read, downstream_write, idle);
    let _ = tokio::join!(client_to_upstream, upstream_to_client);
    Ok(())
}

async fn copy_with_idle<R, W>(mut reader: R, mut writer: W, idle: Duration) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0; 16 * 1024];
    loop {
        let read = timeout(idle, reader.read(&mut buffer)).await??;
        if read == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        timeout(idle, writer.write_all(&buffer[..read])).await??;
    }
}

fn request_key(headers: &HeaderMap) -> Option<String> {
    headers
        .get(SEC_WEBSOCKET_KEY)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

fn valid_websocket_upgrade(headers: &HeaderMap, key: &str) -> bool {
    let connection_valid = connection_has_upgrade(headers);
    let upgrade_valid = headers
        .get(UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    let expected = BASE64.encode(Sha1::digest(format!("{key}{WEBSOCKET_MAGIC}").as_bytes()));
    let accept_valid = headers
        .get(SEC_WEBSOCKET_ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == expected);
    connection_valid && upgrade_valid && accept_valid
}

fn map_response(
    response: Response<Incoming>,
    idle: Duration,
    upstream_permits: Option<UpstreamPermits>,
    activity: Option<ActivityGuard>,
    preserve_upstream: &[http::HeaderName],
) -> Response<ResponseBody> {
    let (mut parts, body) = response.into_parts();
    // Disclosure headers come off every response, including a 101: they
    // are not framing, so the switching-protocols exception below does
    // not cover them. A site only keeps the ones it explicitly named.
    for name in DISCLOSURE_HEADERS {
        if !preserve_upstream.iter().any(|keep| keep.as_str() == *name) {
            parts.headers.remove(*name);
        }
    }
    if parts.status != StatusCode::SWITCHING_PROTOCOLS {
        let mut connection_headers = Vec::new();
        for value in parts.headers.get_all(CONNECTION) {
            if let Ok(value) = value.to_str() {
                for name in value.split(',') {
                    if let Ok(name) = HeaderName::from_bytes(name.trim().as_bytes()) {
                        connection_headers.push(name);
                    }
                }
            }
        }
        for name in &connection_headers {
            if !protected_header(name) {
                parts.headers.remove(name);
            }
        }
        for name in HOP_BY_HOP {
            parts.headers.remove(*name);
        }
        let underscore_headers: Vec<_> = parts
            .headers
            .keys()
            .filter(|name| name.as_str().contains('_'))
            .cloned()
            .collect();
        for name in underscore_headers {
            parts.headers.remove(name);
        }
    }
    let body = IdleBody::new(body, idle);
    let body = match upstream_permits {
        Some(permits) => body
            .with_upstream_permit(permits._global)
            .with_client_upstream_permit(permits._client),
        None => body,
    };
    let body = match activity {
        Some(activity) => body.with_activity(activity),
        None => body,
    };
    Response::from_parts(parts, body.map_err(Into::into).boxed())
}

fn apply_hsts(response: &mut Response<ResponseBody>, config: &Config) {
    let server = &config.server;
    if server.hsts_max_age == 0 || response.headers().contains_key("strict-transport-security") {
        return;
    }
    let mut value = format!("max-age={}", server.hsts_max_age);
    if server.hsts_include_subdomains {
        value.push_str("; includeSubDomains");
    }
    if server.hsts_preload {
        value.push_str("; preload");
    }
    if let Ok(value) = HeaderValue::from_str(&value) {
        response
            .headers_mut()
            .insert("strict-transport-security", value);
    }
}

fn https_redirect(
    host: &str,
    path: &str,
    query: Option<&str>,
    port: u16,
) -> Response<ResponseBody> {
    let authority = if port == 443 {
        host.to_owned()
    } else {
        format!("{host}:{port}")
    };
    let mut target = format!("https://{authority}{path}");
    if let Some(query) = query {
        target.push('?');
        target.push_str(query);
    }
    let mut response = empty_response(StatusCode::PERMANENT_REDIRECT);
    if let Ok(location) = HeaderValue::from_str(&target) {
        response.headers_mut().insert("location", location);
    }
    response
}

fn text_response(status: StatusCode, text: String) -> Response<ResponseBody> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(
            Full::new(Bytes::from(text))
                .map_err(|never| match never {})
                .boxed(),
        )
        .expect("static response is valid")
}

pub fn empty_response(status: StatusCode) -> Response<ResponseBody> {
    Response::builder()
        .status(status)
        .body(
            Full::new(Bytes::new())
                .map_err(|never| match never {})
                .boxed(),
        )
        .expect("static response is valid")
}
