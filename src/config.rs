use std::{
    collections::HashMap,
    fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use http::Uri;
use ipnet::IpNet;
use serde::Deserialize;
use thiserror::Error;

/// Complete proxy configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub server: ServerConfig,
    pub sites: Vec<SiteConfig>,
    pub metrics: MetricsConfig,
}

/// The loopback-only operational metrics endpoint (plan §8).
///
/// Disabled by default. The listener only ever binds a loopback
/// address: a non-loopback `listen` is a config error even while the
/// endpoint is disabled, so no edit can turn the file into a public
/// metrics listener. `listen` parses as a numeric `SocketAddr`, so a
/// hostname that might resolve differently on different hosts is a
/// parse error, not a loophole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub listen: SocketAddr,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 9188)),
        }
    }
}

/// Server-wide connection, request, and timeout limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub https_listen: Option<SocketAddr>,
    pub allow_tls12: bool,
    pub hsts_max_age: u64,
    pub hsts_include_subdomains: bool,
    pub hsts_preload: bool,
    pub blocklist_file: Option<PathBuf>,
    pub max_connections: usize,
    pub max_connections_per_ip: usize,
    pub max_connections_per_upstream: usize,
    pub max_upstream_per_ip: usize,
    pub max_tracked_clients: usize,
    pub requests_per_second: u32,
    pub request_burst: u32,
    pub max_header_bytes: usize,
    pub max_request_body_bytes: u64,
    pub header_read_timeout: Duration,
    pub request_timeout: Duration,
    pub upstream_connect_timeout: Duration,
    pub idle_timeout: Duration,
    pub websocket_idle_timeout: Duration,
    pub websocket_max_lifetime: Duration,
    pub shutdown_drain: Duration,
    pub trusted_proxies: Vec<IpNet>,
    pub cloudflare_ranges: Vec<IpNet>,
    /// Server-wide strike rules for the pre-site offences (malformed
    /// requests, unknown hosts, failed handshakes).
    pub strikes: StrikeRulesConfig,
    /// Addresses that are never struck or banned (operator allowlist).
    /// The trusted proxies and Cloudflare ranges are exempt on top of
    /// this, always.
    pub strike_allowlist: Vec<IpNet>,
}

/// Per-site ACME certificate management settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeConfig {
    pub contact: String,
    pub directory_url: String,
    pub state_dir: PathBuf,
    pub trusted_root: PathBuf,
    pub renew_before_days: u32,
}

/// Virtual host and its ordered routes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteConfig {
    pub acme: Option<AcmeConfig>,
    pub hosts: Vec<String>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub routes: Vec<RouteConfig>,
    pub strikes: StrikeRulesConfig,
}

/// Per-site strike/ban rules (plan §6). `None` disables the tracker for
/// the site; present-but-`log_only` is the default way to turn it on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrikeRulesConfig {
    pub enabled: bool,
    pub log_only: bool,
    pub threshold: u32,
    pub window_secs: u64,
    pub ban_secs: u64,
    pub trap_paths: Vec<String>,
}

impl Default for StrikeRulesConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            log_only: true,
            threshold: 10,
            window_secs: 600,
            ban_secs: 3600,
            trap_paths: Vec::new(),
        }
    }
}

/// Route matching and upstream policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteConfig {
    pub prefix: String,
    pub upstreams: Vec<Uri>,
    pub websocket: bool,
    pub origins: Vec<String>,
    pub allow_remote_http: bool,
    pub requests_per_second: Option<u32>,
    pub request_burst: Option<u32>,
}

/// Configuration loading, decoding, or validation failure.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("could not read configuration {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("could not parse configuration TOML: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid {field}: {message}")]
    Validation { field: String, message: String },
}

impl Config {
    /// Read, parse, and validate a TOML configuration file.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let input = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&input)
    }

    /// Parse and validate TOML configuration. Durations are integer seconds.
    pub fn parse(input: &str) -> Result<Config, ConfigError> {
        let raw = toml::from_str::<RawConfig>(input)?;
        raw.try_into()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    server: RawServerConfig,
    #[serde(default)]
    sites: Vec<RawSiteConfig>,
    #[serde(default)]
    metrics: RawMetricsConfig,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawMetricsConfig {
    enabled: bool,
    listen: String,
}

impl Default for RawMetricsConfig {
    fn default() -> Self {
        let d = MetricsConfig::default();
        Self {
            enabled: d.enabled,
            listen: d.listen.to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawServerConfig {
    listen: String,
    https_listen: Option<String>,
    allow_tls12: bool,
    hsts_max_age: u64,
    hsts_include_subdomains: bool,
    hsts_preload: bool,
    blocklist_file: Option<String>,
    max_connections: usize,
    max_connections_per_ip: usize,
    max_connections_per_upstream: usize,
    max_upstream_per_ip: usize,
    max_tracked_clients: usize,
    requests_per_second: u32,
    request_burst: u32,
    max_header_bytes: usize,
    max_request_body_bytes: u64,
    header_read_timeout: u64,
    request_timeout: u64,
    upstream_connect_timeout: u64,
    idle_timeout: u64,
    websocket_idle_timeout: u64,
    websocket_max_lifetime: u64,
    shutdown_drain: u64,
    trusted_proxies: Vec<String>,
    cloudflare_ranges: Vec<String>,
    strikes: Option<RawStrikeRulesConfig>,
    strike_allowlist: Vec<String>,
}

impl Default for RawServerConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:80".to_owned(),
            https_listen: None,
            allow_tls12: false,
            hsts_max_age: 31536000,
            hsts_include_subdomains: false,
            hsts_preload: false,
            blocklist_file: None,
            max_connections: 4096,
            max_connections_per_ip: 256,
            max_connections_per_upstream: 1024,
            max_upstream_per_ip: 64,
            max_tracked_clients: 10000,
            requests_per_second: 100,
            request_burst: 200,
            max_header_bytes: 32768,
            max_request_body_bytes: 1048576,
            header_read_timeout: 10,
            request_timeout: 30,
            upstream_connect_timeout: 5,
            idle_timeout: 60,
            websocket_idle_timeout: 300,
            websocket_max_lifetime: 3600,
            shutdown_drain: 15,
            trusted_proxies: Vec::new(),
            cloudflare_ranges: Vec::new(),
            strikes: None,
            strike_allowlist: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawAcmeConfig {
    contact: String,
    directory_url: String,
    state_dir: String,
    trusted_root: String,
    renew_before_days: u32,
}

impl Default for RawAcmeConfig {
    fn default() -> Self {
        Self {
            contact: String::new(),
            directory_url: "https://acme-v02.api.letsencrypt.org/directory".to_owned(),
            state_dir: "./rookd-acme".to_owned(),
            trusted_root: String::new(),
            renew_before_days: 30,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawSiteConfig {
    acme: Option<RawAcmeConfig>,
    hosts: Vec<String>,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    routes: Vec<RawRouteConfig>,
    strikes: Option<RawStrikeRulesConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawStrikeRulesConfig {
    enabled: bool,
    log_only: bool,
    threshold: u32,
    window_secs: u64,
    ban_secs: u64,
    trap_paths: Vec<String>,
}

impl Default for RawStrikeRulesConfig {
    fn default() -> Self {
        let d = StrikeRulesConfig::default();
        Self {
            enabled: d.enabled,
            log_only: d.log_only,
            threshold: d.threshold,
            window_secs: d.window_secs,
            ban_secs: d.ban_secs,
            trap_paths: d.trap_paths,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawRouteConfig {
    prefix: String,
    upstreams: Vec<String>,
    websocket: bool,
    origins: Vec<String>,
    allow_remote_http: bool,
    requests_per_second: Option<u32>,
    request_burst: Option<u32>,
}

impl TryFrom<RawConfig> for Config {
    type Error = ConfigError;

    fn try_from(raw: RawConfig) -> Result<Self, Self::Error> {
        let server = parse_server(raw.server)?;
        let metrics = parse_metrics(raw.metrics)?;
        if raw.sites.is_empty() {
            return Err(validation("sites", "at least one site is required"));
        }

        let mut sites = Vec::with_capacity(raw.sites.len());
        let mut hosts_seen = HashMap::new();
        for (site_index, raw_site) in raw.sites.into_iter().enumerate() {
            let site = parse_site(site_index, raw_site, &server, &mut hosts_seen)?;
            sites.push(site);
        }
        reject_metrics_upstream(&metrics, &sites)?;

        Ok(Self {
            server,
            sites,
            metrics,
        })
    }
}

fn parse_metrics(raw: RawMetricsConfig) -> Result<MetricsConfig, ConfigError> {
    // `SocketAddr` parsing never resolves hostnames: "localhost:9188"
    // is an error here, which is what keeps the loopback check below
    // from depending on DNS.
    let listen = raw.listen.parse::<SocketAddr>().map_err(|error| {
        validation("metrics.listen", format!("invalid socket address: {error}"))
    })?;
    if !listen.ip().is_loopback() {
        return Err(validation(
            "metrics.listen",
            "metrics only binds loopback addresses; a public metrics listener is never allowed",
        ));
    }
    Ok(MetricsConfig {
        enabled: raw.enabled,
        listen,
    })
}

/// Thomas's guard: a route or tunnel whose upstream *is* the metrics
/// listener would publish `/metrics` through the proxy even though the
/// listener itself is loopback-only. Reject the literal case at load;
/// names that resolve to the listener later are refused at connect
/// time by the guarded connector (see `proxy::GuardedConnector`).
fn reject_metrics_upstream(
    metrics: &MetricsConfig,
    sites: &[SiteConfig],
) -> Result<(), ConfigError> {
    if !metrics.enabled {
        return Ok(());
    }
    for (site_index, site) in sites.iter().enumerate() {
        for (route_index, route) in site.routes.iter().enumerate() {
            for (upstream_index, upstream) in route.upstreams.iter().enumerate() {
                if upstream_matches_listener(upstream, metrics.listen) {
                    return Err(validation(
                        format!(
                            "sites[{site_index}].routes[{route_index}].upstreams[{upstream_index}]"
                        ),
                        "upstream is the metrics listener; proxying to it would publish /metrics",
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Does this upstream URL address the metrics listener exactly? Only
/// IP literals answer here; names that resolve to the listener later
/// are refused at connect time (`proxy::GuardedConnector`). The port
/// defaults by scheme (Harry, review of PR #7: `https:` with no port
/// means 443 at connect time, so the two guards must agree).
fn upstream_matches_listener(upstream: &Uri, listen: SocketAddr) -> bool {
    let Some(host) = upstream.host() else {
        return false;
    };
    // Uri::host() keeps the brackets on IPv6 literals.
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    let Ok(ip) = unbracketed.parse::<std::net::IpAddr>() else {
        return false;
    };
    let default_port = if upstream.scheme_str() == Some("https") {
        443
    } else {
        80
    };
    let port = upstream.port_u16().unwrap_or(default_port);
    ip.to_canonical() == listen.ip() && port == listen.port()
}

fn parse_server(raw: RawServerConfig) -> Result<ServerConfig, ConfigError> {
    let listen = raw
        .listen
        .parse::<SocketAddr>()
        .map_err(|error| validation("server.listen", format!("invalid socket address: {error}")))?;
    let https_listen = raw
        .https_listen
        .as_deref()
        .map(|address| {
            address.parse::<SocketAddr>().map_err(|error| {
                validation(
                    "server.https_listen",
                    format!("invalid socket address: {error}"),
                )
            })
        })
        .transpose()?;
    let blocklist_file = parse_tls_path(raw.blocklist_file.as_deref(), "server.blocklist_file")?;
    let mut trusted_proxies = Vec::with_capacity(raw.trusted_proxies.len());
    for (index, proxy) in raw.trusted_proxies.iter().enumerate() {
        let network = proxy.parse::<IpNet>().map_err(|error| {
            validation(
                format!("server.trusted_proxies[{index}]"),
                format!("invalid IP network or CIDR: {error}"),
            )
        })?;
        trusted_proxies.push(network);
    }
    let mut cloudflare_ranges = Vec::with_capacity(raw.cloudflare_ranges.len());
    for (index, range) in raw.cloudflare_ranges.iter().enumerate() {
        let network = range.parse::<IpNet>().map_err(|error| {
            validation(
                format!("server.cloudflare_ranges[{index}]"),
                format!("invalid IP network or CIDR: {error}"),
            )
        })?;
        cloudflare_ranges.push(network);
    }
    let mut strike_allowlist = Vec::with_capacity(raw.strike_allowlist.len());
    for (index, entry) in raw.strike_allowlist.iter().enumerate() {
        let network = entry.parse::<IpNet>().map_err(|error| {
            validation(
                format!("server.strike_allowlist[{index}]"),
                format!("invalid IP network or CIDR: {error}"),
            )
        })?;
        strike_allowlist.push(network);
    }
    let strikes = match raw.strikes {
        Some(raw_strikes) => {
            if raw_strikes.threshold == 0 {
                return Err(validation(
                    "server.strikes.threshold".to_string(),
                    "must be at least 1",
                ));
            }
            if raw_strikes.window_secs == 0 || raw_strikes.ban_secs == 0 {
                return Err(validation(
                    "server.strikes".to_string(),
                    "window_secs and ban_secs must be non-zero",
                ));
            }
            StrikeRulesConfig {
                enabled: raw_strikes.enabled,
                log_only: raw_strikes.log_only,
                threshold: raw_strikes.threshold,
                window_secs: raw_strikes.window_secs,
                ban_secs: raw_strikes.ban_secs,
                trap_paths: raw_strikes.trap_paths,
            }
        }
        None => StrikeRulesConfig::default(),
    };

    let server = ServerConfig {
        listen,
        https_listen,
        allow_tls12: raw.allow_tls12,
        hsts_max_age: raw.hsts_max_age,
        hsts_include_subdomains: raw.hsts_include_subdomains,
        hsts_preload: raw.hsts_preload,
        blocklist_file,
        max_connections: raw.max_connections,
        max_connections_per_ip: raw.max_connections_per_ip,
        max_connections_per_upstream: raw.max_connections_per_upstream,
        max_upstream_per_ip: raw.max_upstream_per_ip,
        max_tracked_clients: raw.max_tracked_clients,
        requests_per_second: raw.requests_per_second,
        request_burst: raw.request_burst,
        max_header_bytes: raw.max_header_bytes,
        max_request_body_bytes: raw.max_request_body_bytes,
        header_read_timeout: Duration::from_secs(raw.header_read_timeout),
        request_timeout: Duration::from_secs(raw.request_timeout),
        upstream_connect_timeout: Duration::from_secs(raw.upstream_connect_timeout),
        idle_timeout: Duration::from_secs(raw.idle_timeout),
        websocket_idle_timeout: Duration::from_secs(raw.websocket_idle_timeout),
        websocket_max_lifetime: Duration::from_secs(raw.websocket_max_lifetime),
        shutdown_drain: Duration::from_secs(raw.shutdown_drain),
        trusted_proxies,
        cloudflare_ranges,
        strikes,
        strike_allowlist,
    };
    server.validate()?;
    Ok(server)
}

impl ServerConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        macro_rules! nonzero_limits {
            ($($field:ident),+ $(,)?) => {
                $(
                    if self.$field == 0 {
                        return Err(validation(
                            concat!("server.", stringify!($field)),
                            "must be greater than zero",
                        ));
                    }
                )+
            };
        }
        nonzero_limits!(
            max_connections,
            max_connections_per_ip,
            max_connections_per_upstream,
            max_upstream_per_ip,
            max_tracked_clients,
            requests_per_second,
            request_burst,
            max_header_bytes,
            max_request_body_bytes,
        );
        if !(8192..=16 * 1024 * 1024).contains(&self.max_header_bytes) {
            return Err(validation(
                "server.max_header_bytes",
                "must be between 8192 and 16777216 bytes",
            ));
        }

        macro_rules! nonzero_timeouts {
            ($($field:ident),+ $(,)?) => {
                $(
                    if self.$field == Duration::ZERO {
                        return Err(validation(
                            concat!("server.", stringify!($field)),
                            "must be greater than zero seconds",
                        ));
                    }
                )+
            };
        }
        nonzero_timeouts!(
            header_read_timeout,
            request_timeout,
            upstream_connect_timeout,
            idle_timeout,
            websocket_idle_timeout,
            websocket_max_lifetime,
            shutdown_drain,
        );

        if self.request_burst < self.requests_per_second {
            return Err(validation(
                "server.request_burst",
                "must be greater than or equal to server.requests_per_second",
            ));
        }
        if self.hsts_preload && !self.hsts_include_subdomains {
            return Err(validation(
                "server.hsts_preload",
                "requires server.hsts_include_subdomains = true",
            ));
        }
        if self.hsts_preload && self.hsts_max_age < 31536000 {
            return Err(validation(
                "server.hsts_preload",
                "requires server.hsts_max_age to be at least 31536000",
            ));
        }
        Ok(())
    }
}

fn parse_site(
    site_index: usize,
    raw: RawSiteConfig,
    server: &ServerConfig,
    hosts_seen: &mut HashMap<String, (usize, usize)>,
) -> Result<SiteConfig, ConfigError> {
    if raw.hosts.is_empty() {
        return Err(validation(
            format!("sites[{site_index}].hosts"),
            "at least one host is required",
        ));
    }
    if raw.routes.is_empty() {
        return Err(validation(
            format!("sites[{site_index}].routes"),
            "at least one route is required",
        ));
    }

    let tls_cert = parse_tls_path(
        raw.tls_cert.as_deref(),
        &format!("sites[{site_index}].tls_cert"),
    )?;
    let tls_key = parse_tls_path(
        raw.tls_key.as_deref(),
        &format!("sites[{site_index}].tls_key"),
    )?;
    let acme = raw
        .acme
        .map(|config| parse_acme(site_index, config))
        .transpose()?;
    match (tls_cert.is_some(), tls_key.is_some()) {
        (true, false) => {
            return Err(validation(
                format!("sites[{site_index}].tls_key"),
                "is required when tls_cert is provided",
            ));
        }
        (false, true) => {
            return Err(validation(
                format!("sites[{site_index}].tls_cert"),
                "is required when tls_key is provided",
            ));
        }
        _ => {}
    }
    if server.https_listen.is_some() && tls_cert.is_none() && acme.is_none() {
        return Err(validation(
            format!("sites[{site_index}].tls_cert"),
            "each HTTPS site requires acme or a tls_cert/tls_key pair",
        ));
    }
    if server.https_listen.is_none() && tls_cert.is_some() {
        return Err(validation(
            format!("sites[{site_index}].tls_cert"),
            "TLS certificates require server.https_listen to be set",
        ));
    }
    if server.https_listen.is_none() && acme.is_some() {
        return Err(validation(
            format!("sites[{site_index}].acme"),
            "ACME requires server.https_listen to be set",
        ));
    }

    let mut hosts = Vec::with_capacity(raw.hosts.len());
    for (host_index, host) in raw.hosts.iter().enumerate() {
        let field = format!("sites[{site_index}].hosts[{host_index}]");
        let normalized =
            normalize_host(host).map_err(|message| validation(field.clone(), message))?;
        if let Some(&(other_site, other_host)) = hosts_seen.get(&normalized) {
            return Err(validation(
                field,
                format!(
                    "duplicate host {normalized:?}; already used by sites[{other_site}].hosts[{other_host}]"
                ),
            ));
        }
        hosts_seen.insert(normalized.clone(), (site_index, host_index));
        hosts.push(normalized);
    }

    let mut routes = Vec::with_capacity(raw.routes.len());
    let mut prefixes_seen = HashMap::new();
    for (route_index, raw_route) in raw.routes.into_iter().enumerate() {
        let route = parse_route(site_index, route_index, raw_route, server)?;
        if let Some(&other_route) = prefixes_seen.get(&route.prefix) {
            return Err(validation(
                format!("sites[{site_index}].routes[{route_index}].prefix"),
                format!(
                    "duplicate route prefix {:?}; already used by routes[{other_route}]",
                    route.prefix
                ),
            ));
        }
        prefixes_seen.insert(route.prefix.clone(), route_index);
        routes.push(route);
    }

    let strikes = match raw.strikes {
        Some(raw_strikes) => {
            let base = format!("sites[{site_index}].strikes");
            if raw_strikes.threshold == 0 {
                return Err(validation(
                    format!("{base}.threshold"),
                    "must be at least 1",
                ));
            }
            if raw_strikes.window_secs == 0 {
                return Err(validation(
                    format!("{base}.window_secs"),
                    "must be non-zero; zero would silently disable counting",
                ));
            }
            if raw_strikes.ban_secs == 0 {
                return Err(validation(
                    format!("{base}.ban_secs"),
                    "must be non-zero; zero would silently disable bans",
                ));
            }
            let mut trap_paths = Vec::with_capacity(raw_strikes.trap_paths.len());
            for (i, path) in raw_strikes.trap_paths.iter().enumerate() {
                if !path.starts_with('/') || path.contains('?') || path.contains('#') {
                    return Err(validation(
                        format!("{base}.trap_paths[{i}]"),
                        "must be an absolute path without query or fragment",
                    ));
                }
                // Normalized the same way request paths are, so a
                // configured trap can always match.
                let normalized = crate::path::normalize_path(path).map_err(|_| {
                    validation(
                        format!("{base}.trap_paths[{i}]"),
                        "is not a normalizable path".to_string(),
                    )
                })?;
                trap_paths.push(normalized);
            }
            StrikeRulesConfig {
                enabled: raw_strikes.enabled,
                log_only: raw_strikes.log_only,
                threshold: raw_strikes.threshold,
                window_secs: raw_strikes.window_secs,
                ban_secs: raw_strikes.ban_secs,
                trap_paths,
            }
        }
        None => StrikeRulesConfig::default(),
    };

    Ok(SiteConfig {
        acme,
        hosts,
        tls_cert,
        tls_key,
        routes,
        strikes,
    })
}

fn parse_acme(site_index: usize, raw: RawAcmeConfig) -> Result<AcmeConfig, ConfigError> {
    let base = format!("sites[{site_index}].acme");
    if raw.contact.is_empty() {
        return Err(validation(
            format!("{base}.contact"),
            "is required and must not be empty",
        ));
    }
    if !raw.contact.starts_with("mailto:") {
        return Err(validation(
            format!("{base}.contact"),
            "must start with mailto:",
        ));
    }
    if raw.trusted_root.is_empty() {
        return Err(validation(
            format!("{base}.trusted_root"),
            "is required and must not be empty",
        ));
    }
    if raw.state_dir.is_empty() {
        return Err(validation(
            format!("{base}.state_dir"),
            "path must not be empty",
        ));
    }
    if raw.directory_url.contains('#') {
        return Err(validation(
            format!("{base}.directory_url"),
            "must not contain a fragment",
        ));
    }
    let directory = raw.directory_url.parse::<Uri>().map_err(|error| {
        validation(
            format!("{base}.directory_url"),
            format!("invalid ACME directory URL: {error}"),
        )
    })?;
    validate_absolute_http_uri(&directory)
        .map_err(|message| validation(format!("{base}.directory_url"), message))?;
    if directory.scheme_str() != Some("https") {
        return Err(validation(
            format!("{base}.directory_url"),
            "must be an absolute HTTPS URL",
        ));
    }
    if directory.query().is_some() {
        return Err(validation(
            format!("{base}.directory_url"),
            "must not contain a query",
        ));
    }
    if !(1..=60).contains(&raw.renew_before_days) {
        return Err(validation(
            format!("{base}.renew_before_days"),
            "must be between 1 and 60 days",
        ));
    }

    Ok(AcmeConfig {
        contact: raw.contact,
        directory_url: raw.directory_url,
        state_dir: PathBuf::from(raw.state_dir),
        trusted_root: PathBuf::from(raw.trusted_root),
        renew_before_days: raw.renew_before_days,
    })
}

fn parse_tls_path(path: Option<&str>, field: &str) -> Result<Option<PathBuf>, ConfigError> {
    match path {
        Some("") => Err(validation(field, "path must not be empty")),
        Some(path) => Ok(Some(PathBuf::from(path))),
        None => Ok(None),
    }
}

fn normalize_host(host: &str) -> Result<String, String> {
    if host.is_empty() {
        return Err("host must not be empty".to_owned());
    }
    if host.chars().any(char::is_control) {
        return Err("host must not contain control characters".to_owned());
    }
    if host.contains('*') {
        return Err("wildcards are not allowed".to_owned());
    }
    if host.contains(':') || host.contains('[') || host.contains(']') {
        return Err("ports and bracketed hosts are not allowed".to_owned());
    }

    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() {
        return Err("host must contain a name".to_owned());
    }
    if !host.is_ascii() {
        return Err("host must use ASCII (use punycode for international names)".to_owned());
    }
    if host.len() > 253 {
        return Err("host exceeds 253 characters".to_owned());
    }
    for label in host.split('.') {
        if label.is_empty() {
            return Err("host contains an empty DNS label".to_owned());
        }
        if label.len() > 63 {
            return Err("host contains a DNS label longer than 63 characters".to_owned());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("DNS labels must not start or end with '-'".to_owned());
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(
                "host must contain only ASCII letters, digits, dots, and hyphens".to_owned(),
            );
        }
    }
    Ok(host.to_ascii_lowercase())
}

fn parse_route(
    site_index: usize,
    route_index: usize,
    raw: RawRouteConfig,
    server: &ServerConfig,
) -> Result<RouteConfig, ConfigError> {
    let base = format!("sites[{site_index}].routes[{route_index}]");
    validate_prefix(&raw.prefix)
        .map_err(|message| validation(format!("{base}.prefix"), message))?;
    let prefix = crate::path::normalize_path(&raw.prefix).map_err(|_| {
        validation(
            format!("{base}.prefix"),
            "must be a normalized request path",
        )
    })?;
    if raw.upstreams.is_empty() {
        return Err(validation(
            format!("{base}.upstreams"),
            "at least one upstream is required",
        ));
    }

    let mut upstreams = Vec::with_capacity(raw.upstreams.len());
    for (upstream_index, upstream) in raw.upstreams.iter().enumerate() {
        let uri = parse_upstream(upstream, raw.allow_remote_http).map_err(|message| {
            validation(format!("{base}.upstreams[{upstream_index}]"), message)
        })?;
        upstreams.push(uri);
    }

    for (origin_index, origin) in raw.origins.iter().enumerate() {
        validate_origin(origin)
            .map_err(|message| validation(format!("{base}.origins[{origin_index}]"), message))?;
    }

    if raw.requests_per_second == Some(0) {
        return Err(validation(
            format!("{base}.requests_per_second"),
            "must be greater than zero",
        ));
    }
    if raw.request_burst == Some(0) {
        return Err(validation(
            format!("{base}.request_burst"),
            "must be greater than zero",
        ));
    }
    let rate = raw
        .requests_per_second
        .unwrap_or(server.requests_per_second);
    let burst = raw.request_burst.unwrap_or(server.request_burst);
    if burst < rate {
        return Err(validation(
            format!("{base}.request_burst"),
            format!(
                "effective burst {burst} must be greater than or equal to effective rate {rate}"
            ),
        ));
    }

    Ok(RouteConfig {
        prefix,
        upstreams,
        websocket: raw.websocket,
        origins: raw.origins,
        allow_remote_http: raw.allow_remote_http,
        requests_per_second: raw.requests_per_second,
        request_burst: raw.request_burst,
    })
}

fn validate_prefix(prefix: &str) -> Result<(), String> {
    if !prefix.starts_with('/') {
        return Err("route prefix must start with '/'".to_owned());
    }
    if prefix.chars().any(char::is_control) {
        return Err("route prefix must not contain control characters".to_owned());
    }
    if prefix.contains(['?', '#']) {
        return Err("route prefix must not contain a query or fragment".to_owned());
    }
    if prefix.contains('\\') {
        return Err("route prefix must not contain backslashes".to_owned());
    }
    if prefix.as_bytes().windows(2).any(|pair| pair == b"//") {
        return Err("route prefix must not contain repeated '/'".to_owned());
    }

    for segment in prefix.split('/').skip(1) {
        let decoded = decode_path_segment(segment)?;
        if decoded == b"." || decoded == b".." {
            return Err("route prefix must not contain dot segments".to_owned());
        }
    }
    Ok(())
}

fn decode_path_segment(segment: &str) -> Result<Vec<u8>, String> {
    let bytes = segment.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err("route prefix contains an incomplete percent escape".to_owned());
        }
        let high = hex_value(bytes[index + 1]);
        let low = hex_value(bytes[index + 2]);
        let (Some(high), Some(low)) = (high, low) else {
            return Err("route prefix contains a non-hexadecimal percent escape".to_owned());
        };
        let byte = (high << 4) | low;
        if matches!(byte, b'/' | b'\\') {
            return Err(
                "route prefix must not contain percent-encoded slashes or backslashes".to_owned(),
            );
        }
        if byte.is_ascii_control() {
            return Err(
                "route prefix must not contain percent-encoded control characters".to_owned(),
            );
        }
        decoded.push(byte);
        index += 3;
    }
    Ok(decoded)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn parse_upstream(value: &str, allow_remote_http: bool) -> Result<Uri, String> {
    if value.contains('#') {
        return Err("URI must not contain a fragment".to_owned());
    }
    let uri = value
        .parse::<Uri>()
        .map_err(|error| format!("invalid absolute HTTP URI: {error}"))?;
    validate_absolute_http_uri(&uri)?;
    if uri.scheme_str() != Some("http") {
        return Err("HTTPS upstreams are not implemented yet".to_owned());
    }
    if uri
        .path_and_query()
        .is_some_and(|path| path.query().is_some())
    {
        return Err("upstream must not contain a query".to_owned());
    }
    if !allow_remote_http && !uri.host().is_some_and(is_loopback_host) {
        return Err("non-loopback HTTP upstream requires allow_remote_http = true".to_owned());
    }
    Ok(uri)
}

fn validate_absolute_http_uri(uri: &Uri) -> Result<(), String> {
    let Some(scheme) = uri.scheme() else {
        return Err("URI must be absolute and include an http or https scheme".to_owned());
    };
    if scheme != "http" && scheme != "https" {
        return Err("URI scheme must be http or https".to_owned());
    }
    let Some(authority) = uri.authority() else {
        return Err("URI must include a host".to_owned());
    };
    if uri.host().is_none() {
        return Err("URI must include a host".to_owned());
    }
    if authority.as_str().contains('@') {
        return Err("URI must not contain userinfo".to_owned());
    }
    Ok(())
}

fn is_loopback_host(host: &str) -> bool {
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    if unbracketed
        .parse::<IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
    {
        return true;
    }
    let hostname = unbracketed.strip_suffix('.').unwrap_or(unbracketed);
    hostname.eq_ignore_ascii_case("localhost")
        || hostname
            .rsplit_once('.')
            .is_some_and(|(_, suffix)| suffix.eq_ignore_ascii_case("localhost"))
}

fn validate_origin(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("origin must not be empty".to_owned());
    }
    if value.contains('#') {
        return Err("URI must not contain a fragment".to_owned());
    }
    let uri = value
        .parse::<Uri>()
        .map_err(|error| format!("invalid HTTP(S) origin: {error}"))?;
    validate_absolute_http_uri(&uri)?;
    if uri.path() != "/" {
        return Err("origin must not contain a path".to_owned());
    }
    if uri.query().is_some() {
        return Err("origin must not contain a query".to_owned());
    }
    Ok(())
}

fn validation(field: impl Into<String>, message: impl Into<String>) -> ConfigError {
    ConfigError::Validation {
        field: field.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_FULL: &str = r#"
[server]
listen = "127.0.0.1:8080"
https_listen = "127.0.0.1:8443"
allow_tls12 = true
hsts_max_age = 63072000
hsts_include_subdomains = true
hsts_preload = true
blocklist_file = "/etc/rookd/acme-blocklist.pem"
max_connections = 1000
max_connections_per_ip = 50
max_connections_per_upstream = 100
max_upstream_per_ip = 25
max_tracked_clients = 5000
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

[[sites]]
hosts = ["Example.COM.", "api.example.com"]
tls_cert = "/etc/rookd/example.com.crt"
tls_key = "/etc/rookd/example.com.key"

[[sites.routes]]
prefix = "/api"
upstreams = ["http://127.0.0.1:9000/base", "http://127.0.0.1:9001"]
websocket = true
origins = ["https://app.example.com", "http://localhost:3000"]
allow_remote_http = false
requests_per_second = 10
request_burst = 20
"#;

    fn minimal_config() -> &'static str {
        r#"
[[sites]]
hosts = ["example.com"]

[[sites.routes]]
prefix = "/"
upstreams = ["http://127.0.0.1:8080"]
"#
    }

    fn config_with_route(prefix: &str) -> String {
        format!(
            "[[sites]]\nhosts = ['example.com']\n[[sites.routes]]\nprefix = '{prefix}'\nupstreams = ['http://127.0.0.1:8080']\n"
        )
    }

    fn config_with_upstream(upstream: &str) -> String {
        format!(
            "[[sites]]\nhosts = ['example.com']\n[[sites.routes]]\nprefix = '/'\nupstreams = ['{upstream}']\n"
        )
    }

    fn config_with_acme(settings: &str) -> String {
        format!(
            "[server]\nhttps_listen = '127.0.0.1:8443'\n[[sites]]\nhosts = ['example.com']\n[sites.acme]\n{settings}\n[[sites.routes]]\nprefix = '/'\nupstreams = ['http://127.0.0.1:8080']\n"
        )
    }

    #[test]
    fn parses_valid_full_config() {
        let config = Config::parse(VALID_FULL).unwrap();
        assert_eq!(config.server.listen, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(
            config.server.https_listen,
            Some("127.0.0.1:8443".parse().unwrap())
        );
        assert!(config.server.allow_tls12);
        assert_eq!(config.server.hsts_max_age, 63072000);
        assert!(config.server.hsts_include_subdomains);
        assert!(config.server.hsts_preload);
        assert_eq!(
            config.server.blocklist_file,
            Some(PathBuf::from("/etc/rookd/acme-blocklist.pem"))
        );
        assert_eq!(config.server.max_connections, 1000);
        assert_eq!(config.server.max_connections_per_ip, 50);
        assert_eq!(config.server.max_connections_per_upstream, 100);
        assert_eq!(config.server.max_upstream_per_ip, 25);
        assert_eq!(config.server.max_tracked_clients, 5000);
        assert_eq!(config.server.requests_per_second, 20);
        assert_eq!(config.server.request_burst, 40);
        assert_eq!(config.server.max_header_bytes, 16384);
        assert_eq!(config.server.max_request_body_bytes, 2097152);
        assert_eq!(config.server.header_read_timeout, Duration::from_secs(11));
        assert_eq!(config.server.request_timeout, Duration::from_secs(31));
        assert_eq!(
            config.server.upstream_connect_timeout,
            Duration::from_secs(6)
        );
        assert_eq!(config.server.idle_timeout, Duration::from_secs(61));
        assert_eq!(
            config.server.websocket_idle_timeout,
            Duration::from_secs(301)
        );
        assert_eq!(
            config.server.websocket_max_lifetime,
            Duration::from_secs(3601)
        );
        assert_eq!(config.server.shutdown_drain, Duration::from_secs(16));
        assert_eq!(config.server.trusted_proxies.len(), 2);
        assert_eq!(config.sites[0].hosts, ["example.com", "api.example.com"]);
        assert_eq!(
            config.sites[0].tls_cert,
            Some(PathBuf::from("/etc/rookd/example.com.crt"))
        );
        assert_eq!(
            config.sites[0].tls_key,
            Some(PathBuf::from("/etc/rookd/example.com.key"))
        );
        let route = &config.sites[0].routes[0];
        assert_eq!(route.prefix, "/api");
        assert_eq!(route.upstreams.len(), 2);
        assert!(route.websocket);
        assert_eq!(route.origins.len(), 2);
        assert!(!route.allow_remote_http);
        assert_eq!(route.requests_per_second, Some(10));
        assert_eq!(route.request_burst, Some(20));
    }

    #[test]
    fn applies_all_defaults() {
        let config = Config::parse(minimal_config()).unwrap();
        let server = config.server;
        assert_eq!(server.listen, "0.0.0.0:80".parse().unwrap());
        assert_eq!(server.https_listen, None);
        assert!(!server.allow_tls12);
        assert_eq!(server.hsts_max_age, 31536000);
        assert!(!server.hsts_include_subdomains);
        assert!(!server.hsts_preload);
        assert_eq!(server.blocklist_file, None);
        assert_eq!(server.max_connections, 4096);
        assert_eq!(server.max_connections_per_ip, 256);
        assert_eq!(server.max_connections_per_upstream, 1024);
        assert_eq!(server.max_upstream_per_ip, 64);
        assert_eq!(server.max_tracked_clients, 10000);
        assert_eq!(server.requests_per_second, 100);
        assert_eq!(server.request_burst, 200);
        assert_eq!(server.max_header_bytes, 32768);
        assert_eq!(server.max_request_body_bytes, 1048576);
        assert_eq!(server.header_read_timeout, Duration::from_secs(10));
        assert_eq!(server.request_timeout, Duration::from_secs(30));
        assert_eq!(server.upstream_connect_timeout, Duration::from_secs(5));
        assert_eq!(server.idle_timeout, Duration::from_secs(60));
        assert_eq!(server.websocket_idle_timeout, Duration::from_secs(300));
        assert_eq!(server.websocket_max_lifetime, Duration::from_secs(3600));
        assert_eq!(server.shutdown_drain, Duration::from_secs(15));
        assert!(server.trusted_proxies.is_empty());

        assert_eq!(config.sites[0].acme, None);
        assert_eq!(config.sites[0].tls_cert, None);
        assert_eq!(config.sites[0].tls_key, None);
        let route = &config.sites[0].routes[0];
        assert!(!route.websocket);
        assert!(route.origins.is_empty());
        assert!(!route.allow_remote_http);
        assert_eq!(route.requests_per_second, None);
        assert_eq!(route.request_burst, None);
    }

    #[test]
    fn rejects_duplicate_hosts_after_normalization() {
        let input = r#"
[[sites]]
hosts = ["Example.com."]
[[sites.routes]]
prefix = "/"
upstreams = ["http://127.0.0.1"]
[[sites]]
hosts = ["example.COM"]
[[sites.routes]]
prefix = "/"
upstreams = ["http://127.0.0.1"]
"#;
        let error = Config::parse(input).unwrap_err().to_string();
        assert!(error.contains("sites[1].hosts[0]"), "{error}");
        assert!(error.contains("duplicate host"), "{error}");
    }

    #[test]
    fn rejects_duplicate_route_prefixes_within_a_site() {
        let input = r#"
[[sites]]
hosts = ["example.com"]
[[sites.routes]]
prefix = "/api"
upstreams = ["http://127.0.0.1"]
[[sites.routes]]
prefix = "/api"
upstreams = ["http://127.0.0.1"]
"#;
        let error = Config::parse(input).unwrap_err().to_string();
        assert!(error.contains("sites[0].routes[1].prefix"), "{error}");
        assert!(error.contains("duplicate route prefix"), "{error}");
    }

    #[test]
    fn rejects_bad_route_paths() {
        let bad_prefixes = [
            "api",
            "/api//v1",
            "/api?query=yes",
            "/api#fragment",
            "/api\\v1",
            "/api/%2f",
            "/api/%5C",
            "/api/./v1",
            "/api/%2e%2e/v1",
            "/api/%",
            "/api/%xz",
            "/api/%00",
        ];
        for prefix in bad_prefixes {
            let error = Config::parse(&config_with_route(prefix))
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("sites[0].routes[0].prefix"),
                "prefix {prefix:?}: {error}"
            );
        }
    }

    #[test]
    fn remote_http_requires_explicit_opt_in() {
        let remote = config_with_upstream("http://upstream.example.com");
        let error = Config::parse(&remote).unwrap_err().to_string();
        assert!(error.contains("allow_remote_http = true"), "{error}");

        let opted_in = remote.replace("upstreams =", "allow_remote_http = true\nupstreams =");
        assert!(Config::parse(&opted_in).is_ok());
        assert!(Config::parse(&config_with_upstream("http://127.0.0.1:8080")).is_ok());
        assert!(Config::parse(&config_with_upstream("http://[::1]:8080")).is_ok());
        assert!(Config::parse(&config_with_upstream("http://localhost:8080")).is_ok());
        assert!(Config::parse(&config_with_upstream("https://upstream.example.com")).is_err());
    }

    #[test]
    fn rejects_invalid_upstreams() {
        let invalid = [
            "127.0.0.1:8080",
            "/relative",
            "ftp://127.0.0.1",
            "http://",
            "http://user@127.0.0.1",
            "http://127.0.0.1/path?query=yes",
            "http://127.0.0.1/#fragment",
        ];
        for upstream in invalid {
            let error = Config::parse(&config_with_upstream(upstream))
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("sites[0].routes[0].upstreams[0]"),
                "upstream {upstream:?}: {error}"
            );
        }

        let empty =
            minimal_config().replace("upstreams = [\"http://127.0.0.1:8080\"]", "upstreams = []");
        let error = Config::parse(&empty).unwrap_err().to_string();
        assert!(error.contains("at least one upstream"), "{error}");
    }

    #[test]
    fn rejects_invalid_limits_and_timeouts() {
        let invalid_server_values = [
            "blocklist_file = ''",
            "https_listen = 'not-an-address'",
            "hsts_preload = true",
            "hsts_preload = true\nhsts_include_subdomains = true\nhsts_max_age = 31535999",
            "max_connections = 0",
            "max_connections_per_ip = 0",
            "max_connections_per_upstream = 0",
            "max_upstream_per_ip = 0",
            "max_tracked_clients = 0",
            "requests_per_second = 0",
            "request_burst = 0",
            "max_header_bytes = 0",
            "max_header_bytes = 8191",
            "max_header_bytes = 16777217",
            "max_request_body_bytes = 0",
            "header_read_timeout = 0",
            "request_timeout = 0",
            "upstream_connect_timeout = 0",
            "idle_timeout = 0",
            "websocket_idle_timeout = 0",
            "websocket_max_lifetime = 0",
            "shutdown_drain = 0",
            "requests_per_second = 201",
        ];
        for setting in invalid_server_values {
            let input = format!("[server]\n{setting}\n{}", minimal_config());
            let error = Config::parse(&input).unwrap_err().to_string();
            assert!(error.contains("server."), "setting {setting:?}: {error}");
        }

        let zero_route_rate =
            minimal_config().replace("upstreams =", "requests_per_second = 0\nupstreams =");
        assert!(Config::parse(&zero_route_rate).is_err());
        let zero_route_burst =
            minimal_config().replace("upstreams =", "request_burst = 0\nupstreams =");
        assert!(Config::parse(&zero_route_burst).is_err());
        let unbalanced_route = minimal_config().replace(
            "upstreams =",
            "requests_per_second = 10\nrequest_burst = 9\nupstreams =",
        );
        assert!(Config::parse(&unbalanced_route).is_err());
        let unbalanced_inherited_burst =
            minimal_config().replace("upstreams =", "requests_per_second = 201\nupstreams =");
        assert!(Config::parse(&unbalanced_inherited_burst).is_err());
    }

    #[test]
    fn enforces_tls_certificate_schema() {
        let tls_case = |server: &str, site: &str| {
            format!(
                "[server]\n{server}\n[[sites]]\nhosts = ['example.com']\n{site}\n[[sites.routes]]\nprefix = '/'\nupstreams = ['http://127.0.0.1:8080']\n"
            )
        };
        let https = "https_listen = '127.0.0.1:8443'";
        let cert = "tls_cert = '/etc/rookd/example.com.crt'";
        let key = "tls_key = '/etc/rookd/example.com.key'";
        let pair =
            "tls_cert = '/etc/rookd/example.com.crt'\ntls_key = '/etc/rookd/example.com.key'";

        for (server, site, field) in [
            (https, cert, "sites[0].tls_key"),
            (https, key, "sites[0].tls_cert"),
            (https, "", "sites[0].tls_cert"),
            ("", pair, "sites[0].tls_cert"),
            (https, "tls_cert = ''\ntls_key = 'key'", "sites[0].tls_cert"),
            (https, "tls_cert = 'cert'\ntls_key = ''", "sites[0].tls_key"),
        ] {
            let error = Config::parse(&tls_case(server, site))
                .unwrap_err()
                .to_string();
            assert!(error.contains(field), "{error}");
        }

        let mut missing_second_pair = tls_case(https, pair);
        missing_second_pair.push_str(
            "[[sites]]\nhosts = ['other.example.com']\n[[sites.routes]]\nprefix = '/'\nupstreams = ['http://127.0.0.1:8080']\n",
        );
        let error = Config::parse(&missing_second_pair).unwrap_err().to_string();
        assert!(error.contains("sites[1].tls_cert"), "{error}");

        let config = Config::parse(&tls_case(https, pair)).unwrap();
        assert_eq!(
            config.sites[0].tls_cert,
            Some(PathBuf::from("/etc/rookd/example.com.crt"))
        );
        assert_eq!(
            config.sites[0].tls_key,
            Some(PathBuf::from("/etc/rookd/example.com.key"))
        );
    }

    #[test]
    fn parses_valid_acme_config_with_certificate_fallback() {
        let input = config_with_acme(
            "contact = 'mailto:admin@example.com'\ndirectory_url = 'https://acme.example.com/directory'\nstate_dir = '/var/lib/rookd/acme'\ntrusted_root = '/etc/ssl/acme-root.pem'\nrenew_before_days = 45",
        )
        .replace(
            "hosts = ['example.com']",
            "hosts = ['example.com']\ntls_cert = '/etc/rookd/example.com.crt'\ntls_key = '/etc/rookd/example.com.key'",
        );
        let config = Config::parse(&input).unwrap();
        let acme = config.sites[0].acme.as_ref().unwrap();
        assert_eq!(acme.contact, "mailto:admin@example.com");
        assert_eq!(acme.directory_url, "https://acme.example.com/directory");
        assert_eq!(acme.state_dir, PathBuf::from("/var/lib/rookd/acme"));
        assert_eq!(acme.trusted_root, PathBuf::from("/etc/ssl/acme-root.pem"));
        assert_eq!(acme.renew_before_days, 45);
        assert!(config.sites[0].tls_cert.is_some());
        assert!(config.sites[0].tls_key.is_some());
    }

    #[test]
    fn applies_acme_defaults_when_table_is_present() {
        let input = config_with_acme(
            "contact = 'mailto:admin@example.com'\ntrusted_root = '/etc/ssl/acme-root.pem'",
        );
        let config = Config::parse(&input).unwrap();
        let acme = config.sites[0].acme.as_ref().unwrap();
        assert_eq!(
            acme.directory_url,
            "https://acme-v02.api.letsencrypt.org/directory"
        );
        assert_eq!(acme.state_dir, PathBuf::from("./rookd-acme"));
        assert_eq!(acme.renew_before_days, 30);
        assert_eq!(config.sites[0].tls_cert, None);
        assert_eq!(config.sites[0].tls_key, None);
    }

    #[test]
    fn rejects_invalid_acme_configuration() {
        for (settings, field) in [
            ("trusted_root = '/root.pem'", "sites[0].acme.contact"),
            (
                "contact = ''\ntrusted_root = '/root.pem'",
                "sites[0].acme.contact",
            ),
            (
                "contact = 'admin@example.com'\ntrusted_root = '/root.pem'",
                "sites[0].acme.contact",
            ),
            (
                "contact = 'mailto:admin@example.com'",
                "sites[0].acme.trusted_root",
            ),
            (
                "contact = 'mailto:admin@example.com'\ntrusted_root = ''",
                "sites[0].acme.trusted_root",
            ),
            (
                "contact = 'mailto:admin@example.com'\ntrusted_root = '/root.pem'\nstate_dir = ''",
                "sites[0].acme.state_dir",
            ),
            (
                "contact = 'mailto:admin@example.com'\ntrusted_root = '/root.pem'\nrenew_before_days = 0",
                "sites[0].acme.renew_before_days",
            ),
            (
                "contact = 'mailto:admin@example.com'\ntrusted_root = '/root.pem'\nrenew_before_days = 61",
                "sites[0].acme.renew_before_days",
            ),
        ] {
            let error = Config::parse(&config_with_acme(settings))
                .unwrap_err()
                .to_string();
            assert!(error.contains(field), "{error}");
        }

        for url in [
            "",
            "http://example.com/directory",
            "/directory",
            "https:///directory",
            "https://example.com/directory?x=1",
            "https://example.com/directory#fragment",
        ] {
            let settings = format!(
                "contact = 'mailto:admin@example.com'\ntrusted_root = '/root.pem'\ndirectory_url = '{url}'"
            );
            let error = Config::parse(&config_with_acme(&settings))
                .unwrap_err()
                .to_string();
            assert!(error.contains("sites[0].acme.directory_url"), "{error}");
        }

        let without_https =
            config_with_acme("contact = 'mailto:admin@example.com'\ntrusted_root = '/root.pem'")
                .replace("[server]\nhttps_listen = '127.0.0.1:8443'\n", "");
        let error = Config::parse(&without_https).unwrap_err().to_string();
        assert!(error.contains("sites[0].acme"), "{error}");
    }

    #[test]
    fn accepts_valid_hsts_modes() {
        let disabled = format!("[server]\nhsts_max_age = 0\n{}", minimal_config());
        let config = Config::parse(&disabled).unwrap();
        assert_eq!(config.server.hsts_max_age, 0);

        let preload = format!(
            "[server]\nhsts_max_age = 31536000\nhsts_include_subdomains = true\nhsts_preload = true\n{}",
            minimal_config()
        );
        assert!(Config::parse(&preload).is_ok());
    }

    #[test]
    fn rejects_invalid_hosts_proxies_and_origins() {
        assert!(Config::parse("").unwrap_err().to_string().contains("sites"));

        let no_routes = "[[sites]]\nhosts = ['example.com']";
        assert!(Config::parse(no_routes).is_err());

        let bad_host = minimal_config().replace("example.com", "example.com:443");
        assert!(Config::parse(&bad_host).is_err());

        let bad_proxy = minimal_config().replace(
            "[[sites]]",
            "[server]\ntrusted_proxies = ['not-a-cidr']\n[[sites]]",
        );
        let error = Config::parse(&bad_proxy).unwrap_err().to_string();
        assert!(error.contains("server.trusted_proxies[0]"), "{error}");

        for origin in ["", "https://example.com/path", "https://example.com?x=1"] {
            let input = minimal_config().replace(
                "upstreams =",
                &format!("origins = ['{origin}']\nupstreams ="),
            );
            let error = Config::parse(&input).unwrap_err().to_string();
            assert!(error.contains("sites[0].routes[0].origins[0]"), "{error}");
        }
    }

    #[test]
    fn metrics_defaults_to_disabled_on_loopback() {
        let config = Config::parse(minimal_config()).unwrap();
        assert!(!config.metrics.enabled);
        assert_eq!(config.metrics.listen, "127.0.0.1:9188".parse().unwrap());
    }

    #[test]
    fn metrics_accepts_only_loopback() {
        for (listen, ok) in [
            ("127.0.0.1:9188", true),
            ("[::1]:9188", true),
            // The two that look harmless but publish to everyone.
            ("0.0.0.0:9188", false),
            ("[::]:9188", false),
            ("192.0.2.1:9188", false),
        ] {
            let input = format!(
                "[metrics]\nenabled = true\nlisten = '{listen}'\n{}",
                minimal_config()
            );
            let parsed = Config::parse(&input);
            assert_eq!(parsed.is_ok(), ok, "listen = {listen}");
            if let Err(error) = parsed {
                assert!(error.to_string().contains("metrics.listen"), "{error}");
            }
        }
    }

    #[test]
    fn metrics_rejects_a_non_loopback_listen_even_when_disabled() {
        let input = format!("[metrics]\nlisten = '0.0.0.0:9188'\n{}", minimal_config());
        assert!(Config::parse(&input).is_err());
    }

    #[test]
    fn metrics_listen_never_resolves_hostnames() {
        // "localhost" happens to resolve to loopback on most hosts, so a
        // resolving parser would accept it; a SocketAddr parser does not.
        let input = format!(
            "[metrics]\nenabled = true\nlisten = 'localhost:9188'\n{}",
            minimal_config()
        );
        assert!(Config::parse(&input).is_err());
    }

    #[test]
    fn metrics_upstream_match_defaults_the_port_by_scheme() {
        // Harry's review point: the load-time guard must default the
        // port the way the connector does, or an https upstream with no
        // port would slip past it onto a listener on 443.
        let listen_443: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let listen_80: SocketAddr = "127.0.0.1:80".parse().unwrap();
        assert!(upstream_matches_listener(
            &"https://127.0.0.1".parse().unwrap(),
            listen_443
        ));
        assert!(!upstream_matches_listener(
            &"http://127.0.0.1".parse().unwrap(),
            listen_443
        ));
        assert!(upstream_matches_listener(
            &"http://127.0.0.1".parse().unwrap(),
            listen_80
        ));
        assert!(upstream_matches_listener(
            &"https://127.0.0.1:443".parse().unwrap(),
            listen_443
        ));
        assert!(!upstream_matches_listener(
            &"https://127.0.0.1:444".parse().unwrap(),
            listen_443
        ));
        assert!(!upstream_matches_listener(
            &"https://127.0.0.2".parse().unwrap(),
            listen_443
        ));
        // Names never answer here; the connect-time guard owns them.
        assert!(!upstream_matches_listener(
            &"http://localhost:80".parse().unwrap(),
            listen_80
        ));
    }

    #[test]
    fn metrics_rejects_an_upstream_that_is_the_listener() {
        let upstream = config_with_upstream("http://127.0.0.1:9188");
        let enabled = format!("[metrics]\nenabled = true\n{upstream}");
        let error = Config::parse(&enabled).unwrap_err().to_string();
        assert!(error.contains("upstreams[0]"), "{error}");

        // Disabled metrics: nothing is listening, so the route stands.
        assert!(Config::parse(&upstream).is_ok());
        // A different port is a different service.
        let other_port = format!(
            "[metrics]\nenabled = true\n{}",
            config_with_upstream("http://127.0.0.1:9189")
        );
        assert!(Config::parse(&other_port).is_ok());
        // An IPv4-mapped literal is the same listener (allow_remote_http
        // so the route itself validates and the metrics guard is the
        // thing under test).
        let mapped = "[metrics]\nenabled = true\n[[sites]]\nhosts = ['example.com']\n[[sites.routes]]\nprefix = '/'\nupstreams = ['http://[::ffff:127.0.0.1]:9188']\nallow_remote_http = true\n";
        let error = Config::parse(mapped).unwrap_err().to_string();
        assert!(error.contains("upstreams[0]"), "{error}");
        // Default ports count: http://127.0.0.1 is port 80.
        let portless = format!(
            "[metrics]\nenabled = true\nlisten = '127.0.0.1:80'\n{}",
            config_with_upstream("http://127.0.0.1")
        );
        assert!(Config::parse(&portless).is_err());
    }
}
