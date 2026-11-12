use std::{
    collections::{BTreeSet, HashMap},
    fs,
    io::Write,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, anyhow, bail};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use tokio::time::{sleep, timeout};
use tracing::{info, warn};
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

use crate::{
    certificates::{CertificateStore, acme_certificate_paths, validate_certificate_pair},
    config::{AcmeConfig, SiteConfig},
    proxy::AppState,
    trust::TrustPolicy,
};

const MAX_CHALLENGES: usize = 1024;
const DAILY: Duration = Duration::from_secs(24 * 60 * 60);
const ATTEMPT_DEADLINE: Duration = Duration::from_secs(5 * 60);
const INITIAL_RETRY: Duration = Duration::from_secs(60);
const MAX_RETRY: Duration = Duration::from_secs(60 * 60);
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);
static JITTER_COUNTER: AtomicU64 = AtomicU64::new(0);
static VERSION_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Default)]
pub struct ChallengeStore {
    challenges: RwLock<HashMap<(String, String), String>>,
}

impl ChallengeStore {
    pub fn insert(&self, host: &str, token: &str, key_authorization: String) -> bool {
        let key = (normalize_host(host), token.to_owned());
        let mut challenges = self
            .challenges
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if challenges.len() >= MAX_CHALLENGES && !challenges.contains_key(&key) {
            return false;
        }
        challenges.insert(key, key_authorization);
        true
    }

    pub fn get(&self, host: &str, token: &str) -> Option<String> {
        let challenges = self
            .challenges
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        challenges
            .get(&(normalize_host(host), token.to_owned()))
            .cloned()
    }

    pub fn remove(&self, host: &str, token: &str) -> Option<String> {
        let mut challenges = self
            .challenges
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        challenges.remove(&(normalize_host(host), token.to_owned()))
    }

    pub fn clear_host(&self, host: &str) {
        let host = normalize_host(host);
        let mut challenges = self
            .challenges
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        challenges.retain(|(challenge_host, _), _| challenge_host != &host);
    }
}

pub async fn issue_site(
    site: SiteConfig,
    state: Arc<AppState>,
    certificates: Arc<CertificateStore>,
    trust: Arc<TrustPolicy>,
) -> Result<(), anyhow::Error> {
    match timeout(
        ATTEMPT_DEADLINE,
        issue_site_inner(site, state, certificates, trust),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => bail!("ACME issuance attempt exceeded the five-minute deadline"),
    }
}

async fn issue_site_inner(
    site: SiteConfig,
    state: Arc<AppState>,
    certificates: Arc<CertificateStore>,
    trust: Arc<TrustPolicy>,
) -> Result<(), anyhow::Error> {
    let acme = site
        .acme
        .as_ref()
        .ok_or_else(|| anyhow!("ACME is not configured for this site"))?;
    if site.hosts.is_empty() {
        bail!("cannot issue an ACME certificate without configured hosts");
    }

    ensure_private_directory(&acme.state_dir)?;
    let account = load_or_create_account(acme, &trust).await?;
    let identifiers = site
        .hosts
        .iter()
        .map(|host| Identifier::Dns(host.clone()))
        .collect::<Vec<_>>();
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .context("could not create ACME order")?;
    let mut registered = RegisteredChallenges::new(Arc::clone(&state));

    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authorization = result.context("could not retrieve ACME authorization")?;
            match authorization.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                status => bail!("unexpected ACME authorization status: {status:?}"),
            }

            let mut challenge = authorization
                .challenge(ChallengeType::Http01)
                .ok_or_else(|| anyhow!("ACME authorization has no HTTP-01 challenge"))?;
            let host = normalize_host(&challenge.identifier().to_string());
            if !site
                .hosts
                .iter()
                .any(|configured| normalize_host(configured) == host)
            {
                bail!("ACME returned an authorization for unconfigured host {host:?}");
            }
            let token = challenge.token.clone();
            let key_authorization = challenge.key_authorization().as_str().to_owned();
            registered.insert(&host, &token, key_authorization)?;
            challenge
                .set_ready()
                .await
                .with_context(|| format!("could not start HTTP-01 challenge for {host}"))?;
        }
    }

    let status = order
        .poll_ready(&RetryPolicy::default())
        .await
        .context("ACME order did not become ready")?;
    if status != OrderStatus::Ready {
        bail!("unexpected ACME order status: {status:?}");
    }

    let private_key = order
        .finalize()
        .await
        .context("could not finalize ACME order")?;
    let certificate = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .context("ACME certificate was not issued")?;
    publish_certificate(&site, &certificate, &private_key)?;
    certificates.reload();
    info!(hosts = ?site.hosts, "ACME certificate issued and loaded");
    Ok(())
}

fn publish_certificate(
    site: &SiteConfig,
    certificate: &str,
    private_key: &str,
) -> Result<(), anyhow::Error> {
    let (current_certificate, _) = acme_certificate_paths(site)
        .ok_or_else(|| anyhow!("could not derive ACME certificate paths"))?;
    let host_directory = current_certificate
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| anyhow!("could not derive the ACME host directory"))?;
    ensure_private_directory(host_directory)?;
    let versions_directory = host_directory.join("versions");
    ensure_private_directory(&versions_directory)?;
    let version_directory = create_version_directory(&versions_directory)?;
    let certificate_path = version_directory.join("cert.pem");
    let key_path = version_directory.join("key.pem");

    let staged = (|| -> Result<(), anyhow::Error> {
        atomic_write(&key_path, private_key.as_bytes())?;
        atomic_write(&certificate_path, certificate.as_bytes())?;
        validate_certificate_pair(&certificate_path, &key_path)
            .context("ACME returned an invalid certificate/private key pair")
    })();
    if let Err(error) = staged {
        let _ = fs::remove_dir_all(&version_directory);
        return Err(error);
    }
    if let Err(error) = publish_current(host_directory, &version_directory) {
        let _ = fs::remove_dir_all(&version_directory);
        return Err(error);
    }

    sync_directory(&version_directory)?;
    sync_directory(&versions_directory)?;
    sync_directory(host_directory)?;
    prune_versions(host_directory, &versions_directory);
    sync_directory(&versions_directory)?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), anyhow::Error> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("could not sync ACME directory {}", path.display()))
}

fn prune_versions(host_directory: &Path, versions_directory: &Path) {
    if let Err(error) = prune_versions_inner(host_directory, versions_directory) {
        warn!(
            path = %versions_directory.display(),
            %error,
            "could not prune old ACME certificate versions"
        );
    }
}

fn prune_versions_inner(host_directory: &Path, versions_directory: &Path) -> std::io::Result<()> {
    let active = fs::canonicalize(host_directory.join("current"))?;
    let mut versions = Vec::new();
    for entry in fs::read_dir(versions_directory)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let path = entry.path();
        if fs::canonicalize(&path)? == active {
            continue;
        }
        let modified = entry.metadata()?.modified().unwrap_or(UNIX_EPOCH);
        versions.push((path, modified));
    }
    versions.sort_by(|left, right| {
        right
            .1
            .cmp(&left.1)
            .then_with(|| right.0.file_name().cmp(&left.0.file_name()))
    });

    for (path, _) in versions.into_iter().skip(1) {
        let active_now = match fs::canonicalize(host_directory.join("current")) {
            Ok(active) => active,
            Err(error) => {
                warn!(path = %path.display(), %error, "skipping ACME version pruning");
                continue;
            }
        };
        match fs::canonicalize(&path) {
            Ok(candidate) if candidate == active || candidate == active_now => continue,
            Ok(_) => {}
            Err(error) => {
                warn!(path = %path.display(), %error, "could not inspect old ACME certificate version");
                continue;
            }
        }
        if let Err(error) = fs::remove_dir_all(&path) {
            warn!(path = %path.display(), %error, "could not remove old ACME certificate version");
        }
    }
    Ok(())
}

fn create_version_directory(versions_directory: &Path) -> Result<PathBuf, anyhow::Error> {
    for _ in 0..128 {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let sequence = VERSION_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            versions_directory.join(format!("{timestamp}-{}-{sequence}", std::process::id()));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "could not create ACME certificate version in {}",
                        versions_directory.display()
                    )
                });
            }
        }
    }
    bail!(
        "could not allocate an ACME certificate version in {}",
        versions_directory.display()
    )
}

#[cfg(unix)]
fn publish_current(host_directory: &Path, version_directory: &Path) -> Result<(), anyhow::Error> {
    use std::os::unix::fs::symlink;

    let version_name = version_directory
        .file_name()
        .ok_or_else(|| anyhow!("ACME certificate version has no directory name"))?;
    let target = Path::new("versions").join(version_name);
    let current = host_directory.join("current");
    for _ in 0..128 {
        let sequence = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temporary =
            host_directory.join(format!(".current.{}.{sequence}.tmp", std::process::id()));
        match symlink(&target, &temporary) {
            Ok(()) => {
                if let Err(error) = fs::rename(&temporary, &current) {
                    let _ = fs::remove_file(&temporary);
                    return Err(error).with_context(|| {
                        format!("could not publish ACME certificate {}", current.display())
                    });
                }
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "could not create ACME publication symlink in {}",
                        host_directory.display()
                    )
                });
            }
        }
    }
    bail!(
        "could not allocate an ACME publication symlink in {}",
        host_directory.display()
    )
}

#[cfg(not(unix))]
fn publish_current(_host_directory: &Path, _version_directory: &Path) -> Result<(), anyhow::Error> {
    bail!("atomic ACME certificate publication requires Unix symlink support")
}

pub async fn run_site(
    site: SiteConfig,
    state: Arc<AppState>,
    certificates: Arc<CertificateStore>,
    trust: Arc<TrustPolicy>,
) {
    let Some(renew_before_days) = site.acme.as_ref().map(|acme| acme.renew_before_days) else {
        return;
    };
    let Some((certificate_path, key_path)) = acme_certificate_paths(&site) else {
        return;
    };
    let renew_before = Duration::from_secs(u64::from(renew_before_days) * 24 * 60 * 60);
    let mut shutdown = state.subscribe_shutdown();
    let mut failures = 0_u32;

    loop {
        let mut next_check = DAILY;
        if certificate_needs_renewal(
            &certificate_path,
            &key_path,
            &site.hosts,
            renew_before,
            SystemTime::now(),
        ) {
            let result = tokio::select! {
                biased;
                _ = shutdown.recv() => return,
                result = issue_site(
                    site.clone(),
                    Arc::clone(&state),
                    Arc::clone(&certificates),
                    Arc::clone(&trust),
                ) => result,
            };
            match result {
                Ok(()) => {
                    failures = 0;
                    state.metrics.acme_renewal(true);
                }
                Err(error) => {
                    failures = failures.saturating_add(1);
                    state.metrics.acme_renewal(false);
                    next_check = retry_delay(failures);
                    warn!(
                        hosts = ?site.hosts,
                        retry_seconds = next_check.as_secs(),
                        %error,
                        "ACME certificate issuance failed; keeping the last valid certificate"
                    );
                }
            }
        }

        tokio::select! {
            biased;
            _ = shutdown.recv() => return,
            _ = sleep(next_check) => {}
        }
    }
}

async fn load_or_create_account(
    acme: &AcmeConfig,
    trust: &TrustPolicy,
) -> Result<Account, anyhow::Error> {
    let path = acme.state_dir.join("account.json");
    let credentials = match fs::read(&path) {
        Ok(contents) => match serde_json::from_slice::<AccountCredentials>(&contents) {
            Ok(credentials) => Some(credentials),
            Err(error) => {
                warn!(path = %path.display(), %error, "ignoring invalid ACME account credentials");
                None
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error).with_context(|| {
                format!("could not read ACME account credentials {}", path.display())
            });
        }
    };

    if let Some(credentials) = credentials {
        return trust
            .acme_account_builder(&acme.trusted_root)
            .context("could not configure the ACME TLS trust root")?
            .from_credentials(credentials)
            .await
            .context("could not restore the ACME account");
    }

    let (account, credentials) = trust
        .acme_account_builder(&acme.trusted_root)
        .context("could not configure the ACME TLS trust root")?
        .create(
            &NewAccount {
                contact: &[acme.contact.as_str()],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            acme.directory_url.clone(),
            None,
        )
        .await
        .context("could not create ACME account")?;
    let encoded = serde_json::to_vec(&credentials).context("could not encode ACME credentials")?;
    atomic_write(&path, &encoded)?;
    Ok(account)
}

struct RegisteredChallenges {
    state: Arc<AppState>,
    challenges: Vec<(String, String)>,
}

impl RegisteredChallenges {
    fn new(state: Arc<AppState>) -> Self {
        Self {
            state,
            challenges: Vec::new(),
        }
    }

    fn insert(
        &mut self,
        host: &str,
        token: &str,
        key_authorization: String,
    ) -> Result<(), anyhow::Error> {
        if !self
            .state
            .acme_challenges
            .insert(host, token, key_authorization)
        {
            bail!("ACME HTTP-01 challenge store is full");
        }
        self.challenges
            .push((normalize_host(host), token.to_owned()));
        Ok(())
    }
}

impl Drop for RegisteredChallenges {
    fn drop(&mut self) {
        for (host, token) in self.challenges.drain(..) {
            self.state.acme_challenges.remove(&host, &token);
        }
    }
}

fn normalize_host(host: &str) -> String {
    host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase()
}

pub fn validate_state_directory(path: &Path) -> Result<(), anyhow::Error> {
    match fs::metadata(path) {
        Ok(metadata) => validate_directory_metadata(path, &metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("could not inspect ACME state directory {}", path.display())),
    }
}

fn ensure_private_directory(path: &Path) -> Result<(), anyhow::Error> {
    match fs::metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(path).with_context(|| {
                format!("could not create ACME state directory {}", path.display())
            })?;
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!("could not inspect ACME state directory {}", path.display())
            });
        }
    }

    let metadata = fs::metadata(path)
        .with_context(|| format!("could not inspect ACME state directory {}", path.display()))?;
    validate_directory_metadata(path, &metadata)
}

fn validate_directory_metadata(path: &Path, metadata: &fs::Metadata) -> Result<(), anyhow::Error> {
    if !metadata.is_dir() {
        bail!("ACME state path is not a directory: {}", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            bail!(
                "ACME state directory {} has insecure permissions {mode:#o}; remove all group and other permissions",
                path.display()
            );
        }
    }
    Ok(())
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), anyhow::Error> {
    let parent = path.parent().filter(|path| !path.as_os_str().is_empty());
    let parent = parent.unwrap_or_else(|| Path::new("."));
    ensure_private_directory(parent)?;
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("ACME output path has no file name: {}", path.display()))?;

    let (temporary_path, mut file) = create_temporary_file(parent, file_name)?;
    let write_result = (|| -> std::io::Result<()> {
        file.write_all(contents)?;
        file.sync_all()
    })();
    drop(file);
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary_path);
        return Err(error).with_context(|| {
            format!("could not write temporary ACME file for {}", path.display())
        });
    }
    if let Err(error) = fs::rename(&temporary_path, path) {
        let _ = fs::remove_file(&temporary_path);
        return Err(error)
            .with_context(|| format!("could not atomically replace {}", path.display()));
    }
    Ok(())
}

fn create_temporary_file(
    parent: &Path,
    file_name: &std::ffi::OsStr,
) -> Result<(PathBuf, fs::File), anyhow::Error> {
    for _ in 0..128 {
        let sequence = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(
            ".{}.{}.{}.tmp",
            file_name.to_string_lossy(),
            std::process::id(),
            sequence
        ));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "could not create temporary ACME file in {}",
                        parent.display()
                    )
                });
            }
        }
    }
    bail!(
        "could not allocate a temporary ACME file in {}",
        parent.display()
    )
}

fn certificate_needs_renewal(
    certificate_path: &Path,
    key_path: &Path,
    hosts: &[String],
    renew_before: Duration,
    now: SystemTime,
) -> bool {
    if validate_certificate_pair(certificate_path, key_path).is_err() {
        return true;
    }
    let contents = match fs::read(certificate_path) {
        Ok(contents) => contents,
        Err(_) => return true,
    };
    let certificate = match CertificateDer::from_pem_slice(&contents) {
        Ok(certificate) => certificate,
        Err(_) => return true,
    };
    let parsed = match parse_x509_certificate(certificate.as_ref()) {
        Ok((_, certificate)) => certificate,
        Err(_) => return true,
    };
    if expiry_requires_renewal(parsed.validity().not_after.timestamp(), now, renew_before) {
        return true;
    }

    let san = match parsed.subject_alternative_name() {
        Ok(Some(san)) => san,
        _ => return true,
    };
    let expected = hosts
        .iter()
        .map(|host| normalize_host(host))
        .collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    for name in &san.value.general_names {
        let name = match name {
            GeneralName::DNSName(host) => normalize_host(host),
            GeneralName::IPAddress(bytes) => {
                let address = match bytes.len() {
                    4 => IpAddr::from(<[u8; 4]>::try_from(*bytes).unwrap()),
                    16 => IpAddr::from(<[u8; 16]>::try_from(*bytes).unwrap()),
                    _ => return true,
                };
                address.to_string()
            }
            _ => return true,
        };
        actual.insert(name);
    }
    actual != expected
}

fn expiry_requires_renewal(not_after: i64, now: SystemTime, renew_before: Duration) -> bool {
    let now = match now.duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        Err(error) => -i64::try_from(error.duration().as_secs()).unwrap_or(i64::MAX),
    };
    let renew_before = i64::try_from(renew_before.as_secs()).unwrap_or(i64::MAX);
    not_after <= now.saturating_add(renew_before)
}

fn retry_delay(failures: u32) -> Duration {
    let exponent = failures.saturating_sub(1).min(10);
    let base = INITIAL_RETRY
        .saturating_mul(1_u32 << exponent)
        .min(MAX_RETRY);
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let sequence = JITTER_COUNTER.fetch_add(1, Ordering::Relaxed) as u32;
    let jitter = 512 + u64::from(time ^ sequence) % 513;
    let millis = base.as_millis() as u64 * jitter / 1024;
    Duration::from_millis(millis)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDFTCCAf2gAwIBAgIUIM7M/LmYo1zh9SCphXlS+IAX/OwwDQYJKoZIhvcNAQEL\n\
BQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wHhcNMjYxMTAxMjAyNzIyWhcNMzYx\n\
MDI5MjAyNzIyWjAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTCCASIwDQYJKoZIhvcN\n\
AQEBBQADggEPADCCAQoCggEBANp24jE8vHwK8rWQahDmDmrsK3XXgh4qDOxOpXef\n\
1fjF1YURTJTSwbXeDOnlToWnDG/PJhED9SCtB8fFPRo764MF55Q58R5rlbmv1LVQ\n\
G6UnOliNNhW7+ZFg6Z2KVCi5ym619bMbsPQLnaJsL4fD7HScWoByh0vBb/nMENDm\n\
PTxQLsYAy1fYAWhCnehtblD593Wc8u+14x0T2qD+mQkpMLu9YqMc6wUcWaaiHvMX\n\
gcwvV9I8nc0Uh6uJ/QVspF4yEN0MJPq6Hnh7fqUw/agLowAViz9FY9He62DfYt1p\n\
g+bEtyHC7McTK/QqGRztIzWS42R9qkjzvv/6lidKJgMrL2sCAwEAAaNbMFkwHQYD\n\
VR0OBBYEFGs6Q8f6HjMLEGcaFTwI5gTYKx3GMA8GA1UdEwEB/wQFMAMBAf8wJwYD\n\
VR0RBCAwHoILZXhhbXBsZS5jb22CD2FwaS5leGFtcGxlLmNvbTANBgkqhkiG9w0B\n\
AQsFAAOCAQEATpUi0+IQhSbpr7hBYssNPF+HrTygklTUKivczJ9R2f9iyRCpJPvL\n\
YpWIfzMTQBCLkn2F2Gvx5XaPkpsCsspQEg3k9ogC38qoEH444qFU9mh6OD0u/vf6\n\
zvcDe8jKEd6Dmp9uNMpXBhoCoOTaG7aDPAAzZj5zc6mJ3lWY+mNwoOHVicxW5y9h\n\
aRjDlQ//42ZfLZ3yLPHfncr4BbGvDnioWUuSfMaVu08aoNblee4yTnsIH74fMVOB\n\
MCdlkT8qcFCjXO7aZfVaLNUeLozWW25FKxk3HhohWLAOHznBYvysuc8dptne+MfF\n\
ivpnyPJUO3zTJr4+WaSr+WQ4geg+8ogUIQ==\n\
-----END CERTIFICATE-----\n";
    const TEST_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDaduIxPLx8CvK1\n\
kGoQ5g5q7Ct114IeKgzsTqV3n9X4xdWFEUyU0sG13gzp5U6FpwxvzyYRA/UgrQfH\n\
xT0aO+uDBeeUOfEea5W5r9S1UBulJzpYjTYVu/mRYOmdilQoucputfWzG7D0C52i\n\
bC+Hw+x0nFqAcodLwW/5zBDQ5j08UC7GAMtX2AFoQp3obW5Q+fd1nPLvteMdE9qg\n\
/pkJKTC7vWKjHOsFHFmmoh7zF4HML1fSPJ3NFIerif0FbKReMhDdDCT6uh54e36l\n\
MP2oC6MAFYs/RWPR3utg32LdaYPmxLchwuzHEyv0Khkc7SM1kuNkfapI877/+pYn\n\
SiYDKy9rAgMBAAECggEAKsBjCVGibP/TeVZ2ezIaFjB7XMc8rlx6RPArD1rXC6Tj\n\
YPP+sY0A3W9Dxa3bDOqg02yNPX0xxiA2SpC9oVmif/Ry2h3wooxZM4pGLOktT8d6\n\
coPH1r7/WsTFUtAUIhghlkLDfzZnDYsMYRGcx4u+xR8n0sUW1utW12Jo1AiKaTfH\n\
L6Rlk/ybR/JgoUSC0B2JNVHgkOl/ZDrUBnXcY74K8YmvJW6A8xp+WuX3gLlBe2/e\n\
pMtdpWl1LWZIL4+sxO+sd0flv7/zDEGwLQT1oWN5MiZLh29EoCRUrDmV2J/NJ++8\n\
33fo4SnS2BNpsdEkdZrZTDUKqJ/pxUP8Tsh+hUHOSQKBgQDuZaWgW2hwNbP1mcW5\n\
9sZRugq9SISCtIGr3xiErb/TmcKt94pRdP7yFVYr3PBf+kjvdj+Cw1f8Q5spZqzX\n\
Z2AnzuFDhQDDVSAP2bEDN3Yiz2HBqROWi2NVRb1T623vM0yze25IqGT1jtvi3HDo\n\
l53JbDhGqtg87++DE2bwbYkOzQKBgQDqmHR0QVuFXpkbAqQHsnFCtYBTqKD4+dfI\n\
F5f5ngNKGSn6z5bdKKXopcpLdcp4DsEPGbKuols5DLjM6pV6CK0dO/2g5J0OKhG/\n\
gM2X/DBySPHz1GCMoiUE5gL6SAqs/7O4sSdh7XuIBLBnnGOXcNbh5fCoRSty8thc\n\
stIyS8BHFwKBgElWacJP/GvwiWD3ojUYLmA77EvYgDM5Vl7KLd+7F7T/qz0bVqjC\n\
Zh+Q4sZxnFzaQQ+xf845S9rl7ViqJmfJfHIimXfM9bQhftCBdov3xtbklz0dR1Jb\n\
pP45iwnC9jnMvT7FrOKbMxu7i/dZOz7CTZ8GNLXAnu74HOVk1ZkHCU/NAoGAYCiT\n\
e1+a0wUefsrLT3heInjhG+l/6e4G+7ZoDeIt+P5tjafvb8GMl9r1G48xqZpqmfTv\n\
n9Nezvie+yegk3/g7Z28bWmn0rl9wuBZ5VVyyjWKL2a7GIoR4Hsjd1F2Rskc8rRy\n\
rxo3y14YrK+Wxulyuu+UgHSxxZEzDHQj4ofYTYsCgYAyWRF3OEqyslNhJh8v0myp\n\
/fW+GCoZvn5SRNqLgGUKrh/QYBtqC4eJxPeC9ctSa1y0Pg+qFdnvjlWqUX3KGjfk\n\
PBU0gcD3kQT2VvHSYVcBmgMTfj5wcNOajJLtTQfhA5bdHDnZ2u5586JTMyuM7va5\n\
43UPfow6ExGEf5hjYwyadA==\n\
-----END PRIVATE KEY-----\n";

    fn test_site(directory: &Path) -> SiteConfig {
        SiteConfig {
            acme: Some(AcmeConfig {
                contact: String::new(),
                directory_url: String::new(),
                state_dir: directory.to_path_buf(),
                trusted_root: PathBuf::new(),
                renew_before_days: 30,
            }),
            hosts: vec!["example.com".to_owned(), "api.example.com".to_owned()],
            tls_cert: None,
            tls_key: None,
            routes: Vec::new(),
            strikes: crate::config::StrikeRulesConfig::default(),
            preserve_upstream_headers: Vec::new(),
        }
    }

    #[test]
    fn challenge_store_normalizes_and_isolates_hosts() {
        let store = ChallengeStore::default();
        assert!(store.insert("Example.COM.", "token", "authorization".to_owned()));
        assert_eq!(
            store.get("example.com", "token").as_deref(),
            Some("authorization")
        );
        assert!(store.insert("other.example.com", "token", "other".to_owned()));

        store.clear_host("EXAMPLE.com.");
        assert_eq!(store.get("example.com", "token"), None);
        assert_eq!(
            store.get("other.example.com", "token").as_deref(),
            Some("other")
        );
        assert_eq!(
            store.remove("OTHER.EXAMPLE.COM.", "token").as_deref(),
            Some("other")
        );
    }

    #[test]
    fn challenge_store_enforces_its_bound_but_allows_replacement() {
        let store = ChallengeStore::default();
        for index in 0..MAX_CHALLENGES {
            assert!(store.insert("example.com", &index.to_string(), index.to_string()));
        }
        assert!(!store.insert("example.com", "overflow", "rejected".to_owned()));
        assert!(store.insert("EXAMPLE.COM.", "0", "replacement".to_owned()));
        assert_eq!(
            store.get("example.com", "0").as_deref(),
            Some("replacement")
        );
        assert_eq!(store.get("example.com", "overflow"), None);
    }

    #[test]
    fn atomic_write_replaces_files_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state/account.json");
        atomic_write(&path, b"first").unwrap();
        atomic_write(&path, b"second").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(path.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn publishes_complete_versioned_pairs_before_switching_current() {
        let directory = tempfile::tempdir().unwrap();
        let site = test_site(directory.path());
        publish_certificate(&site, TEST_CERTIFICATE, TEST_PRIVATE_KEY).unwrap();

        let (certificate_path, key_path) = acme_certificate_paths(&site).unwrap();
        validate_certificate_pair(&certificate_path, &key_path).unwrap();
        let current = directory.path().join("example.com/current");
        assert!(
            fs::symlink_metadata(&current)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        let first_target = fs::read_link(&current).unwrap();
        let first_version = fs::canonicalize(&current).unwrap();

        publish_certificate(&site, TEST_CERTIFICATE, TEST_PRIVATE_KEY).unwrap();
        let second_target = fs::read_link(&current).unwrap();
        assert_ne!(first_target, second_target);
        assert_ne!(first_version, fs::canonicalize(&current).unwrap());
        validate_certificate_pair(&certificate_path, &key_path).unwrap();

        assert!(publish_certificate(&site, "invalid certificate", TEST_PRIVATE_KEY).is_err());
        assert_eq!(fs::read_link(&current).unwrap(), second_target);
        validate_certificate_pair(&certificate_path, &key_path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn prunes_stale_versions_but_keeps_active_and_previous_keys() {
        let directory = tempfile::tempdir().unwrap();
        let site = test_site(directory.path());
        let current = directory.path().join("example.com/current");

        publish_certificate(&site, TEST_CERTIFICATE, TEST_PRIVATE_KEY).unwrap();
        let first_version = fs::canonicalize(&current).unwrap();
        publish_certificate(&site, TEST_CERTIFICATE, TEST_PRIVATE_KEY).unwrap();
        let previous_version = fs::canonicalize(&current).unwrap();
        publish_certificate(&site, TEST_CERTIFICATE, TEST_PRIVATE_KEY).unwrap();
        let active_version = fs::canonicalize(&current).unwrap();

        let versions_directory = directory.path().join("example.com/versions");
        let mut remaining = fs::read_dir(&versions_directory)
            .unwrap()
            .map(|entry| fs::canonicalize(entry.unwrap().path()).unwrap())
            .collect::<Vec<_>>();
        remaining.sort();
        let mut expected = vec![active_version.clone(), previous_version.clone()];
        expected.sort();
        assert_eq!(remaining, expected);
        assert!(!first_version.exists());
        assert!(active_version.join("key.pem").is_file());
        assert!(previous_version.join("key.pem").is_file());
    }

    #[cfg(unix)]
    #[test]
    fn san_host_mismatch_and_invalid_pair_require_renewal() {
        let directory = tempfile::tempdir().unwrap();
        let site = test_site(directory.path());
        publish_certificate(&site, TEST_CERTIFICATE, TEST_PRIVATE_KEY).unwrap();
        let (certificate_path, key_path) = acme_certificate_paths(&site).unwrap();
        let now = SystemTime::now();
        assert!(!certificate_needs_renewal(
            &certificate_path,
            &key_path,
            &site.hosts,
            Duration::ZERO,
            now,
        ));

        let removed_host = vec!["example.com".to_owned()];
        assert!(certificate_needs_renewal(
            &certificate_path,
            &key_path,
            &removed_host,
            Duration::ZERO,
            now,
        ));
        let mut added_host = site.hosts.clone();
        added_host.push("new.example.com".to_owned());
        assert!(certificate_needs_renewal(
            &certificate_path,
            &key_path,
            &added_host,
            Duration::ZERO,
            now,
        ));

        fs::write(&key_path, "mismatched key").unwrap();
        assert!(certificate_needs_renewal(
            &certificate_path,
            &key_path,
            &site.hosts,
            Duration::ZERO,
            now,
        ));
    }

    #[cfg(unix)]
    #[test]
    fn refuses_shared_existing_state_directory_without_changing_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let shared = directory.path().join("shared");
        fs::create_dir(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(ensure_private_directory(&shared).is_err());
        assert!(validate_state_directory(&shared).is_err());
        assert_eq!(
            fs::metadata(&shared).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[cfg(unix)]
    #[test]
    fn state_directory_validation_does_not_create_or_modify_paths() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing/state");
        validate_state_directory(&missing).unwrap();
        assert!(!missing.exists());
        assert!(!missing.parent().unwrap().exists());

        let private = directory.path().join("private");
        ensure_private_directory(&private).unwrap();
        validate_state_directory(&private).unwrap();
        assert_eq!(
            fs::metadata(&private).unwrap().permissions().mode() & 0o777,
            0o700
        );

        let file = directory.path().join("file");
        fs::write(&file, "not a directory").unwrap();
        assert!(validate_state_directory(&file).is_err());
    }

    #[test]
    fn renewal_threshold_includes_expiry_boundary() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        assert!(!expiry_requires_renewal(1_000_001, now, Duration::ZERO));
        assert!(expiry_requires_renewal(1_000_000, now, Duration::ZERO));
        assert!(expiry_requires_renewal(
            1_000_100,
            now,
            Duration::from_secs(100)
        ));
        assert!(!expiry_requires_renewal(
            1_000_101,
            now,
            Duration::from_secs(100)
        ));
    }

    #[test]
    fn retry_backoff_is_bounded_with_jitter() {
        for failures in [1, 2, 10, 100, u32::MAX] {
            let delay = retry_delay(failures);
            assert!(delay >= INITIAL_RETRY / 2);
            assert!(delay <= MAX_RETRY);
        }
    }
}
