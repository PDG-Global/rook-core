use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use hyper::{StatusCode, server::conn::http1, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder as AutoBuilder,
};
use rustls::ServerConfig;
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::{interval, sleep, timeout},
};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::{
    body::activity::{ConnectionActivity, wait_for_idle_timeout},
    certificates::CertificateStore,
    config::Config,
    framing::FramingGuardIo,
    io::WriteTimeoutIo,
    proxy::{AppState, ConnectionLease, RequestScheme, TlsServerName},
};

pub fn validate_local(config: &Config) -> Result<()> {
    let trust = crate::trust::TrustPolicy::load(config.server.blocklist_file.as_deref())?;
    if config.server.https_listen.is_some() {
        let certificates = CertificateStore::load_strict(&config.sites)?;
        certificates.server_config(config.server.allow_tls12)?;
        for acme in config.sites.iter().filter_map(|site| site.acme.as_ref()) {
            trust.acme_account_builder(&acme.trusted_root)?;
            crate::acme::validate_state_directory(&acme.state_dir)?;
        }
    }
    Ok(())
}

pub async fn run(config: Config) -> Result<()> {
    let state = AppState::new(config.clone());
    let trust = crate::trust::TrustPolicy::load(config.server.blocklist_file.as_deref())?;
    let tls = match config.server.https_listen {
        Some(_) => {
            let certificates = CertificateStore::load(&config.sites)?;
            let server_config = certificates.server_config(config.server.allow_tls12)?;
            Some((certificates, server_config))
        }
        None => None,
    };

    let mut servers = JoinSet::new();
    servers.spawn(run_http(Arc::clone(&state)));
    if config.server.blocklist_file.is_some() {
        servers.spawn(run_trust_reload(Arc::clone(&state), Arc::clone(&trust)));
    }
    if let Some((certificates, server_config)) = tls {
        for site in config.sites.iter().filter(|site| site.acme.is_some()) {
            let site = site.clone();
            let state = Arc::clone(&state);
            let certificates = Arc::clone(&certificates);
            let trust = Arc::clone(&trust);
            servers.spawn(async move {
                crate::acme::run_site(site, state, certificates, trust).await;
                Ok(())
            });
        }
        servers.spawn(run_https(Arc::clone(&state), certificates, server_config));
    }

    let mut first_error = None;
    while let Some(result) = servers.join_next().await {
        state.shutdown();
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(anyhow::Error::new(error));
                }
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

async fn run_trust_reload(
    state: Arc<AppState>,
    trust: Arc<crate::trust::TrustPolicy>,
) -> Result<()> {
    let mut reload = interval(Duration::from_secs(2));
    let mut shutdown = state.subscribe_shutdown();
    loop {
        tokio::select! {
            _ = shutdown.recv() => return Ok(()),
            _ = reload.tick() => trust.reload(),
        }
    }
}

async fn run_http(state: Arc<AppState>) -> Result<()> {
    let listener = TcpListener::bind(state.config.server.listen)
        .await
        .with_context(|| format!("could not bind {}", state.config.server.listen))?;
    info!(listen = %state.config.server.listen, "Rook HTTP is listening");

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        if let Some(delay) = accept_retry_delay(&error) {
                            warn!(error = %error, "HTTP accept failed; retrying");
                            sleep(delay).await;
                        } else {
                            debug!(error = %error, "HTTP accept failed; retrying immediately");
                        }
                        continue;
                    }
                };
                let peer = canonical_peer(peer);
                let Some(permit) = state.connections.acquire(peer.ip()) else {
                    debug!(%peer, "Connection rejected by limit");
                    continue;
                };
                spawn_http_connection(&mut connections, &state, stream, peer, permit);
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = completed {
                    warn!(error = %error, "HTTP connection task failed");
                }
            }
        }
    }

    state.shutdown();
    drain(&mut connections, &state, state.config.server.shutdown_drain).await;
    Ok(())
}

fn spawn_http_connection(
    connections: &mut JoinSet<()>,
    state: &Arc<AppState>,
    stream: TcpStream,
    peer: std::net::SocketAddr,
    permit: crate::limit::ConnectionPermit,
) {
    let permit = Arc::new(permit);
    let service_permit = Arc::clone(&permit);
    let service_state = Arc::clone(state);
    let connection_state = Arc::clone(state);
    let max_header_bytes = state.config.server.max_header_bytes;
    let header_read_timeout = state.config.server.header_read_timeout;
    let idle_timeout = state.config.server.idle_timeout;
    let strikes = state.strikes_global();
    connections.spawn(async move {
        let _permit = permit;
        if !ready_for_http(&stream, header_read_timeout).await {
            debug!(%peer, "Connection closed before sending a complete first byte");
            return;
        }
        let io = FramingGuardIo::new(
            WriteTimeoutIo::new(TokioIo::new(stream), idle_timeout),
            max_header_bytes,
        );
        let framing_control = io.control();
        let io = Box::pin(io);
        let service = service_fn(move |mut request| {
            request
                .extensions_mut()
                .insert(ConnectionLease(Arc::clone(&service_permit)));
            request.extensions_mut().insert(RequestScheme::Http);
            let framing_control = framing_control.clone();
            let service_state = Arc::clone(&service_state);
            async move {
                let response = service_state.handle(peer, request).await;
                if response
                    .as_ref()
                    .is_ok_and(|response| response.status() == StatusCode::SWITCHING_PROTOCOLS)
                {
                    framing_control.disable();
                }
                response
            }
        });
        let mut builder = http1::Builder::new();
        builder
            .max_buf_size(max_header_bytes)
            .max_headers(100)
            .header_read_timeout(header_read_timeout)
            .timer(TokioTimer::new());
        let connection = builder.serve_connection(io, service).with_upgrades();
        tokio::pin!(connection);
        let mut shutdown = connection_state.subscribe_shutdown();
        tokio::select! {
            result = &mut connection => {
                if let Err(error) = result {
                    debug!(%peer, error = %error, "HTTP connection ended");
                }
            }
            _ = shutdown.recv() => {
                connection.as_mut().graceful_shutdown();
                if let Err(error) = connection.await {
                    debug!(%peer, error = %error, "HTTP connection ended during shutdown");
                }
            }
        }
    });
}

async fn run_https(
    state: Arc<AppState>,
    certificates: Arc<CertificateStore>,
    server_config: Arc<ServerConfig>,
) -> Result<()> {
    let listen = state
        .config
        .server
        .https_listen
        .context("HTTPS listener is not configured")?;
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("could not bind {listen}"))?;
    let acceptor = TlsAcceptor::from(server_config);
    info!(%listen, "Rook HTTPS is listening");

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    let mut reload = interval(Duration::from_secs(2));
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            _ = reload.tick() => certificates.reload(),
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        if let Some(delay) = accept_retry_delay(&error) {
                            warn!(error = %error, "HTTPS accept failed; retrying");
                            sleep(delay).await;
                        } else {
                            debug!(error = %error, "HTTPS accept failed; retrying immediately");
                        }
                        continue;
                    }
                };
                let peer = canonical_peer(peer);
                let Some(permit) = state.connections.acquire(peer.ip()) else {
                    debug!(%peer, "Connection rejected by limit");
                    continue;
                };
                spawn_https_connection(
                    &mut connections,
                    &state,
                    acceptor.clone(),
                    stream,
                    peer,
                    permit,
                );
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = completed {
                    warn!(error = %error, "HTTPS connection task failed");
                }
            }
        }
    }

    state.shutdown();
    drain(&mut connections, &state, state.config.server.shutdown_drain).await;
    Ok(())
}

fn spawn_https_connection(
    connections: &mut JoinSet<()>,
    state: &Arc<AppState>,
    acceptor: TlsAcceptor,
    stream: TcpStream,
    peer: std::net::SocketAddr,
    permit: crate::limit::ConnectionPermit,
) {
    let permit = Arc::new(permit);
    let service_permit = Arc::clone(&permit);
    let service_state = Arc::clone(state);
    let connection_state = Arc::clone(state);
    let max_header_bytes = state.config.server.max_header_bytes;
    let header_read_timeout = state.config.server.header_read_timeout;
    let idle_timeout = state.config.server.idle_timeout;
    let strikes = state.strikes_global();
    connections.spawn(async move {
        let _permit = permit;
        if !ready_for_http(&stream, header_read_timeout).await {
            debug!(%peer, "HTTPS connection closed before its first byte");
            return;
        }
        let stream = match timeout(header_read_timeout, acceptor.accept(stream)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                debug!(%peer, error = %error, "TLS handshake failed");
                // A failed handshake on a direct connection strikes. A
                // trusted-proxy peer is exempt (it cannot be attributed
                // to a visitor), which the tracker enforces itself.
                strikes.strike(peer.ip(), crate::strike::StrikeReason::FailedHandshake);
                return;
            }
            Err(_) => {
                debug!(%peer, "TLS handshake timed out");
                strikes.strike(peer.ip(), crate::strike::StrikeReason::FailedHandshake);
                return;
            }
        };
        let server_name = stream.get_ref().1.server_name().map(ToOwned::to_owned);
        let http2 = stream.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
        let mut io = FramingGuardIo::new(
            WriteTimeoutIo::new(TokioIo::new(stream), idle_timeout),
            max_header_bytes,
        );
        if http2 {
            io.disable();
        }
        let framing_control = io.control();
        let io = Box::pin(io);
        let activity = ConnectionActivity::default();
        let service_activity = activity.clone();
        let service = service_fn(move |mut request| {
            request
                .extensions_mut()
                .insert(ConnectionLease(Arc::clone(&service_permit)));
            request.extensions_mut().insert(RequestScheme::Https);
            request.extensions_mut().insert(service_activity.clone());
            if let Some(server_name) = &server_name {
                request
                    .extensions_mut()
                    .insert(TlsServerName(server_name.clone()));
            }
            let framing_control = framing_control.clone();
            let service_state = Arc::clone(&service_state);
            async move {
                let response = service_state.handle(peer, request).await;
                if response
                    .as_ref()
                    .is_ok_and(|response| response.status() == StatusCode::SWITCHING_PROTOCOLS)
                {
                    framing_control.disable();
                }
                response
            }
        });
        let mut builder = AutoBuilder::new(TokioExecutor::new());
        builder
            .http1()
            .max_buf_size(max_header_bytes)
            .max_headers(100)
            .header_read_timeout(header_read_timeout)
            .timer(TokioTimer::new());
        builder
            .http2()
            .max_header_list_size(max_header_bytes as u32)
            .max_concurrent_streams(100)
            .keep_alive_interval(Some(idle_timeout / 2))
            .keep_alive_timeout(idle_timeout)
            .timer(TokioTimer::new());
        let connection = builder.serve_connection_with_upgrades(io, service);
        tokio::pin!(connection);
        let mut shutdown = connection_state.subscribe_shutdown();
        tokio::select! {
            result = &mut connection => {
                if let Err(error) = result {
                    debug!(%peer, error = %error, "HTTPS connection ended");
                }
            }
            _ = shutdown.recv() => {
                connection.as_mut().graceful_shutdown();
                if let Err(error) = connection.await {
                    debug!(%peer, error = %error, "HTTPS connection ended during shutdown");
                }
            }
            _ = wait_for_idle_timeout(&activity, idle_timeout) => {
                connection.as_mut().graceful_shutdown();
                debug!(%peer, "HTTPS connection exceeded its idle deadline");
            }
        }
    });
}

fn accept_retry_delay(error: &std::io::Error) -> Option<Duration> {
    match error.kind() {
        std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::Interrupted => None,
        _ => Some(Duration::from_millis(100)),
    }
}

fn canonical_peer(peer: std::net::SocketAddr) -> std::net::SocketAddr {
    std::net::SocketAddr::new(peer.ip().to_canonical(), peer.port())
}

async fn ready_for_http(stream: &TcpStream, duration: Duration) -> bool {
    let mut first_byte = [0; 1];
    matches!(
        timeout(duration, stream.peek(&mut first_byte)).await,
        Ok(Ok(1))
    )
}

async fn drain(connections: &mut JoinSet<()>, state: &AppState, duration: Duration) {
    let finished = timeout(duration, async {
        while let Some(result) = connections.join_next().await {
            if let Err(error) = result {
                debug!(error = %error, "Connection task ended during shutdown");
            }
        }
        state.wait_for_tunnels().await;
    })
    .await;
    if finished.is_err() {
        warn!("Shutdown drain deadline reached; closing remaining connections and tunnels");
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
}

#[cfg(unix)]
async fn shutdown_signal() -> std::io::Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> std::io::Result<()> {
    tokio::signal::ctrl_c().await
}

#[cfg(test)]
mod tests {
    use std::{io, time::Duration};

    use super::accept_retry_delay;

    #[test]
    fn accept_retry_delay_skips_connection_specific_errors() {
        for kind in [io::ErrorKind::ConnectionAborted, io::ErrorKind::Interrupted] {
            assert_eq!(accept_retry_delay(&io::Error::from(kind)), None);
        }
        assert_eq!(
            accept_retry_delay(&io::Error::from(io::ErrorKind::OutOfMemory)),
            Some(Duration::from_millis(100))
        );
        assert_eq!(
            accept_retry_delay(&io::Error::from_raw_os_error(24)),
            Some(Duration::from_millis(100))
        );
    }
}
