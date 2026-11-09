use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufReader},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};

use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use thiserror::Error;
use tracing::warn;
use x509_parser::{
    der_parser::der::{DerObjectContent, parse_der},
    parse_x509_certificate,
};

use crate::config::SiteConfig;

#[derive(Debug, Error)]
pub enum CertificateError {
    #[error("site {site} has no configured hosts")]
    NoHosts { site: usize },
    #[error("site {site} has an empty TLS host name")]
    EmptyHost { site: usize },
    #[error("TLS host {host:?} is configured for both site {first_site} and site {site}")]
    DuplicateHost {
        host: String,
        first_site: usize,
        site: usize,
    },
    #[error("site {site} ({host}) has no TLS certificate path configured")]
    MissingCertificate { site: usize, host: String },
    #[error("site {site} ({host}) has no TLS private key path configured")]
    MissingPrivateKey { site: usize, host: String },
    #[error("could not open TLS certificate chain {path}: {source}")]
    ReadCertificate {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("could not parse TLS certificate chain {path}: {source}")]
    ParseCertificate {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("TLS certificate chain {path} contains no certificates")]
    EmptyCertificateChain { path: PathBuf },
    #[error("could not parse leaf TLS certificate {path}: {message}")]
    ParseLeafCertificate { path: PathBuf, message: String },
    #[error(
        "TLS leaf certificate {path} is not currently valid (not_before={not_before}, not_after={not_after})"
    )]
    CertificateNotCurrentlyValid {
        path: PathBuf,
        not_before: String,
        not_after: String,
    },
    #[error("could not open TLS private key {path}: {source}")]
    ReadPrivateKey {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("could not inspect TLS private key {path}: {source}")]
    PrivateKeyMetadata {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(
        "TLS private key {path} has insecure permissions {mode:#o}; remove all group and other permissions"
    )]
    InsecureKeyPermissions { path: PathBuf, mode: u32 },
    #[error("could not parse TLS private key {path}: {source}")]
    ParsePrivateKey {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("TLS private key file {path} contains no PKCS8, RSA, or EC private key")]
    NoPrivateKey { path: PathBuf },
    #[error("could not decode RSA private key {path}: {message}")]
    InvalidRsaKey { path: PathBuf, message: String },
    #[error("RSA private key {path} is only {bits} bits; at least 2048 bits are required")]
    WeakRsaKey { path: PathBuf, bits: usize },
    #[error("TLS private key {path} is not supported by the rustls ring provider: {source}")]
    UnsupportedPrivateKey {
        path: PathBuf,
        #[source]
        source: rustls::Error,
    },
    #[error(
        "TLS certificate {certificate_path} and private key {key_path} are not a valid matching pair: {source}"
    )]
    InvalidKeyPair {
        certificate_path: PathBuf,
        key_path: PathBuf,
        #[source]
        source: rustls::Error,
    },
    #[error("could not construct the TLS server configuration: {0}")]
    ServerConfig(#[source] rustls::Error),
}

pub fn acme_certificate_paths(site: &SiteConfig) -> Option<(PathBuf, PathBuf)> {
    let host = site.hosts.first()?;
    let directory = site.acme.as_ref()?.state_dir.join(host).join("current");
    Some((directory.join("cert.pem"), directory.join("key.pem")))
}

#[derive(Debug)]
struct CertificatePaths {
    certificate: PathBuf,
    key: PathBuf,
}

#[derive(Debug, Default)]
struct CertificateErrorState(Mutex<Option<String>>);

impl CertificateErrorState {
    fn note(&self, error: String) -> bool {
        let mut last_error = match self.0.lock() {
            Ok(last_error) => last_error,
            Err(poisoned) => poisoned.into_inner(),
        };
        if last_error.as_deref() == Some(error.as_str()) {
            return false;
        }
        *last_error = Some(error);
        true
    }

    fn clear(&self) {
        let mut last_error = match self.0.lock() {
            Ok(last_error) => last_error,
            Err(poisoned) => poisoned.into_inner(),
        };
        last_error.take();
    }
}

#[derive(Debug)]
struct CertificateSource {
    site: usize,
    hosts: Vec<String>,
    supplied: Option<CertificatePaths>,
    acme: Option<CertificatePaths>,
    error_state: CertificateErrorState,
}

#[derive(Debug)]
pub struct CertificateStore {
    certificates: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    sources: Vec<CertificateSource>,
}

impl CertificateStore {
    pub fn load(sites: &[SiteConfig]) -> Result<Arc<Self>, CertificateError> {
        Self::load_with_mode(sites, false)
    }

    pub fn load_strict(sites: &[SiteConfig]) -> Result<Arc<Self>, CertificateError> {
        Self::load_with_mode(sites, true)
    }

    fn load_with_mode(sites: &[SiteConfig], strict: bool) -> Result<Arc<Self>, CertificateError> {
        let mut certificates = HashMap::new();
        let mut host_sites = HashMap::new();
        let mut sources = Vec::with_capacity(sites.len());

        for (site_index, site) in sites.iter().enumerate() {
            let Some(first_host) = site.hosts.first() else {
                return Err(CertificateError::NoHosts { site: site_index });
            };
            let supplied =
                if site.tls_cert.is_some() || site.tls_key.is_some() {
                    let certificate = site.tls_cert.clone().ok_or_else(|| {
                        CertificateError::MissingCertificate {
                            site: site_index,
                            host: first_host.clone(),
                        }
                    })?;
                    let key = site.tls_key.clone().ok_or_else(|| {
                        CertificateError::MissingPrivateKey {
                            site: site_index,
                            host: first_host.clone(),
                        }
                    })?;
                    Some(CertificatePaths { certificate, key })
                } else {
                    None
                };
            let acme = acme_certificate_paths(site)
                .map(|(certificate, key)| CertificatePaths { certificate, key });
            if supplied.is_none() && acme.is_none() {
                return Err(CertificateError::MissingCertificate {
                    site: site_index,
                    host: first_host.clone(),
                });
            }
            let mut source = CertificateSource {
                site: site_index,
                hosts: Vec::with_capacity(site.hosts.len()),
                supplied,
                acme,
                error_state: CertificateErrorState::default(),
            };
            let certified_key = match load_source_certificate(&source) {
                Ok(key) => key.map(Arc::new),
                Err(error) if !strict => {
                    warn!(
                        site = site_index,
                        %error,
                        "TLS certificate loading failed; leaving the site's hosts without a certificate"
                    );
                    None
                }
                Err(error) => return Err(error),
            };

            for host in &site.hosts {
                let host = normalize_host(host);
                if host.is_empty() {
                    return Err(CertificateError::EmptyHost { site: site_index });
                }
                if let Some(&first_site) = host_sites.get(&host) {
                    return Err(CertificateError::DuplicateHost {
                        host,
                        first_site,
                        site: site_index,
                    });
                }
                host_sites.insert(host.clone(), site_index);
                if let Some(certified_key) = &certified_key {
                    certificates.insert(host.clone(), Arc::clone(certified_key));
                }
                source.hosts.push(host);
            }

            sources.push(source);
        }

        Ok(Arc::new(Self {
            certificates: RwLock::new(certificates),
            sources,
        }))
    }

    pub fn server_config(
        self: &Arc<Self>,
        allow_tls12: bool,
    ) -> Result<Arc<ServerConfig>, CertificateError> {
        let versions: &[&rustls::SupportedProtocolVersion] = if allow_tls12 {
            &[&rustls::version::TLS13, &rustls::version::TLS12]
        } else {
            &[&rustls::version::TLS13]
        };
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(versions)
                .map_err(CertificateError::ServerConfig)?
                .with_no_client_auth()
                .with_cert_resolver(self.clone());
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }

    pub fn reload(&self) {
        for source in &self.sources {
            let certified_key = match load_source_certificate(source) {
                Ok(Some(key)) => Arc::new(key),
                Ok(None) => continue,
                Err(error) => {
                    warn!(
                        site = source.site,
                        %error,
                        "TLS certificate reload failed; keeping the last valid certificate"
                    );
                    continue;
                }
            };

            let mut certificates = match self.certificates.write() {
                Ok(certificates) => certificates,
                Err(poisoned) => poisoned.into_inner(),
            };
            for host in &source.hosts {
                certificates.insert(host.clone(), Arc::clone(&certified_key));
            }
        }
    }
}

impl ResolvesServerCert for CertificateStore {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let host = normalize_host(client_hello.server_name()?);
        let certificates = match self.certificates.read() {
            Ok(certificates) => certificates,
            Err(poisoned) => poisoned.into_inner(),
        };
        certificates.get(&host).cloned()
    }
}

fn normalize_host(host: &str) -> String {
    host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase()
}

pub fn validate_certificate_pair(
    certificate_path: &Path,
    key_path: &Path,
) -> Result<(), CertificateError> {
    load_certified_key(certificate_path, key_path).map(|_| ())
}

fn load_source_certificate(
    source: &CertificateSource,
) -> Result<Option<CertifiedKey>, CertificateError> {
    if let Some(paths) = &source.acme {
        match load_certified_key(&paths.certificate, &paths.key) {
            Ok(key) => {
                source.error_state.clear();
                return Ok(Some(key));
            }
            Err(error) => {
                if source.error_state.note(error.to_string()) {
                    warn!(
                        site = source.site,
                        certificate = %paths.certificate.display(),
                        private_key = %paths.key.display(),
                        %error,
                        "ACME certificate is missing or invalid; using the supplied certificate if configured"
                    );
                }
            }
        }
    }

    match &source.supplied {
        Some(paths) => load_certified_key(&paths.certificate, &paths.key).map(Some),
        None => Ok(None),
    }
}

fn load_certified_key(
    certificate_path: &Path,
    key_path: &Path,
) -> Result<CertifiedKey, CertificateError> {
    let certificate_file =
        File::open(certificate_path).map_err(|source| CertificateError::ReadCertificate {
            path: certificate_path.to_path_buf(),
            source,
        })?;
    let certificates = CertificateDer::pem_reader_iter(BufReader::new(certificate_file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| CertificateError::ParseCertificate {
            path: certificate_path.to_path_buf(),
            source: io::Error::new(io::ErrorKind::InvalidData, error),
        })?;
    if certificates.is_empty() {
        return Err(CertificateError::EmptyCertificateChain {
            path: certificate_path.to_path_buf(),
        });
    }
    validate_certificate_validity(&certificates[0], certificate_path)?;

    let private_key = read_private_key(key_path)?;
    validate_private_key_strength(&private_key, key_path)?;
    let signing_key =
        rustls::crypto::ring::sign::any_supported_type(&private_key).map_err(|source| {
            CertificateError::UnsupportedPrivateKey {
                path: key_path.to_path_buf(),
                source,
            }
        })?;
    let certified_key = CertifiedKey::new(certificates, signing_key);
    certified_key
        .keys_match()
        .map_err(|source| CertificateError::InvalidKeyPair {
            certificate_path: certificate_path.to_path_buf(),
            key_path: key_path.to_path_buf(),
            source,
        })?;
    Ok(certified_key)
}

fn validate_certificate_validity(
    certificate: &CertificateDer<'_>,
    path: &Path,
) -> Result<(), CertificateError> {
    let (_, parsed) = parse_x509_certificate(certificate.as_ref()).map_err(|error| {
        CertificateError::ParseLeafCertificate {
            path: path.to_path_buf(),
            message: error.to_string(),
        }
    })?;
    let validity = parsed.validity();
    let not_before = validity.not_before.timestamp();
    let not_after = validity.not_after.timestamp();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
        });
    if !certificate_valid_at(not_before, not_after, now) {
        return Err(CertificateError::CertificateNotCurrentlyValid {
            path: path.to_path_buf(),
            not_before: validity.not_before.to_string(),
            not_after: validity.not_after.to_string(),
        });
    }
    Ok(())
}

fn certificate_valid_at(not_before: i64, not_after: i64, now: i64) -> bool {
    not_before <= now && now <= not_after
}

fn read_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, CertificateError> {
    let file = File::open(path).map_err(|source| CertificateError::ReadPrivateKey {
        path: path.to_path_buf(),
        source,
    })?;
    check_key_permissions(&file, path)?;
    PrivateKeyDer::from_pem_reader(BufReader::new(file)).map_err(|error| match error {
        rustls::pki_types::pem::Error::NoItemsFound => CertificateError::NoPrivateKey {
            path: path.to_path_buf(),
        },
        error => CertificateError::ParsePrivateKey {
            path: path.to_path_buf(),
            source: io::Error::new(io::ErrorKind::InvalidData, error),
        },
    })
}

#[cfg(unix)]
fn check_key_permissions(file: &File, path: &Path) -> Result<(), CertificateError> {
    use std::os::unix::fs::PermissionsExt;

    let mode = file
        .metadata()
        .map_err(|source| CertificateError::PrivateKeyMetadata {
            path: path.to_path_buf(),
            source,
        })?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(CertificateError::InsecureKeyPermissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_key_permissions(_file: &File, _path: &Path) -> Result<(), CertificateError> {
    Ok(())
}

fn validate_private_key_strength(
    key: &PrivateKeyDer<'_>,
    path: &Path,
) -> Result<(), CertificateError> {
    let bits = match key {
        PrivateKeyDer::Pkcs1(key) => {
            Some(rsa_modulus_bits(key.secret_pkcs1_der()).ok_or_else(|| {
                CertificateError::InvalidRsaKey {
                    path: path.to_path_buf(),
                    message: "could not parse the RSA private key".to_owned(),
                }
            })?)
        }
        PrivateKeyDer::Pkcs8(key) => rsa_modulus_bits(key.secret_pkcs8_der()),
        _ => None,
    };
    if let Some(bits) = bits {
        validate_rsa_strength(bits, path)?;
    }
    Ok(())
}

fn validate_rsa_strength(bits: usize, path: &Path) -> Result<(), CertificateError> {
    if bits < 2048 {
        return Err(CertificateError::WeakRsaKey {
            path: path.to_path_buf(),
            bits,
        });
    }
    Ok(())
}

fn rsa_modulus_bits(der: &[u8]) -> Option<usize> {
    let (_, object) = parse_der(der).ok()?;
    let DerObjectContent::Sequence(items) = object.content else {
        return None;
    };
    if let Some(DerObjectContent::Integer(modulus)) = items.get(1).map(|item| &item.content) {
        return unsigned_integer_bits(modulus);
    }
    if let Some(DerObjectContent::OctetString(nested)) = items.get(2).map(|item| &item.content) {
        return rsa_modulus_bits(nested);
    }
    None
}

fn unsigned_integer_bits(mut bytes: &[u8]) -> Option<usize> {
    while bytes.first() == Some(&0) {
        bytes = &bytes[1..];
    }
    let first = *bytes.first()?;
    Some((bytes.len() - 1) * 8 + (8 - first.leading_zeros() as usize))
}

#[cfg(test)]
mod tests {
    use std::fs;

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

    fn write_pair(directory: &Path, name: &str, certificate: &str) -> (PathBuf, PathBuf) {
        let certificate_path = directory.join(format!("{name}-cert.pem"));
        let key_path = directory.join(format!("{name}-key.pem"));
        fs::write(&certificate_path, certificate).unwrap();
        fs::write(&key_path, TEST_PRIVATE_KEY).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        (certificate_path, key_path)
    }

    fn supplied_site(host: &str, paths: &(PathBuf, PathBuf)) -> SiteConfig {
        SiteConfig {
            acme: None,
            hosts: vec![host.to_owned()],
            tls_cert: Some(paths.0.clone()),
            tls_key: Some(paths.1.clone()),
            routes: vec![],
            strikes: crate::config::StrikeRulesConfig::default(),
        }
    }

    #[test]
    fn invalid_supplied_site_is_nonfatal_and_isolated_unless_strict() {
        let directory = tempfile::tempdir().unwrap();
        let bad = supplied_site(
            "bad.example.com",
            &write_pair(directory.path(), "bad", "invalid certificate"),
        );
        let good = supplied_site(
            "good.example.com",
            &write_pair(directory.path(), "good", TEST_CERTIFICATE),
        );
        let sites = [bad, good];

        let store = CertificateStore::load(&sites).unwrap();
        let certificates = store.certificates.read().unwrap();
        assert!(!certificates.contains_key("bad.example.com"));
        assert!(certificates.contains_key("good.example.com"));
        assert_eq!(certificates.len(), 1);
        drop(certificates);

        let error = CertificateStore::load_strict(&sites).unwrap_err();
        assert!(matches!(
            error,
            CertificateError::EmptyCertificateChain { .. }
        ));
    }

    #[test]
    fn derives_current_acme_paths_and_handles_invalid_bootstrap() {
        let directory = tempfile::tempdir().unwrap();
        let mut site = SiteConfig {
            acme: Some(crate::config::AcmeConfig {
                contact: String::new(),
                directory_url: String::new(),
                state_dir: directory.path().to_path_buf(),
                trusted_root: PathBuf::new(),
                renew_before_days: 30,
            }),
            hosts: vec!["example.com".to_owned()],
            tls_cert: None,
            tls_key: None,
            strikes: crate::config::StrikeRulesConfig::default(),
            routes: vec![],
        };
        let certificate_path = directory.path().join("example.com/current/cert.pem");
        let key_path = directory.path().join("example.com/current/key.pem");
        assert_eq!(
            acme_certificate_paths(&site),
            Some((certificate_path.clone(), key_path.clone()))
        );

        let store = CertificateStore::load(std::slice::from_ref(&site)).unwrap();
        assert!(store.certificates.read().unwrap().is_empty());
        assert_eq!(store.sources.len(), 1);
        assert_eq!(store.sources[0].hosts, ["example.com"]);
        assert!(store.sources[0].supplied.is_none());
        let acme = store.sources[0].acme.as_ref().unwrap();
        assert_eq!(acme.certificate, certificate_path);
        assert_eq!(acme.key, key_path);

        fs::create_dir_all(certificate_path.parent().unwrap()).unwrap();
        fs::write(&certificate_path, "invalid ACME certificate").unwrap();
        fs::write(&key_path, "invalid ACME key").unwrap();
        assert!(validate_certificate_pair(&certificate_path, &key_path).is_err());
        let store = CertificateStore::load(std::slice::from_ref(&site)).unwrap();
        assert!(store.certificates.read().unwrap().is_empty());

        site.tls_cert = Some(directory.path().join("supplied-cert.pem"));
        site.tls_key = Some(directory.path().join("supplied-key.pem"));
        let store = CertificateStore::load(std::slice::from_ref(&site)).unwrap();
        assert!(store.certificates.read().unwrap().is_empty());
        let error = CertificateStore::load_strict(&[site]).unwrap_err();
        assert!(
            matches!(error, CertificateError::ReadCertificate { ref source, .. } if source.kind() == io::ErrorKind::NotFound)
        );
    }

    #[test]
    fn rejects_weak_pkcs1_and_pkcs8_rsa_keys() {
        fn der(tag: u8, contents: &[u8]) -> Vec<u8> {
            let mut encoded = vec![tag, contents.len() as u8];
            encoded.extend_from_slice(contents);
            encoded
        }

        let pkcs1 = der(0x30, &[der(0x02, &[0]), der(0x02, &[0x80; 8])].concat());
        let pkcs8 = der(
            0x30,
            &[der(0x02, &[0]), der(0x30, &[]), der(0x04, &pkcs1)].concat(),
        );
        let path = Path::new("generated-test-key.pem");
        for encoded in [
            PrivateKeyDer::Pkcs1(pkcs1.into()),
            PrivateKeyDer::Pkcs8(pkcs8.into()),
        ] {
            let error = validate_private_key_strength(&encoded, path).unwrap_err();
            assert!(
                matches!(error, CertificateError::WeakRsaKey { bits, .. } if bits < 2048),
                "{error}"
            );
            assert!(error.to_string().contains("at least 2048 bits"));
        }
    }

    #[test]
    fn invalid_key_error_identifies_the_path() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("invalid-key.pem");
        fs::write(&path, "not a PEM private key").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let error = read_private_key(&path).unwrap_err();
        assert!(matches!(error, CertificateError::NoPrivateKey { .. }));
        assert!(error.to_string().contains(&path.display().to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_and_other_key_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("key.pem");
        fs::write(&path, "test key").unwrap();
        let file = File::open(&path).unwrap();

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(check_key_permissions(&file, &path).is_ok());

        for mode in [0o601, 0o610, 0o640, 0o644, 0o666] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            let error = check_key_permissions(&file, &path).unwrap_err();
            assert!(
                matches!(error, CertificateError::InsecureKeyPermissions { .. }),
                "mode {mode:o}: {error}"
            );
        }
    }

    #[test]
    fn logs_only_changed_acme_errors_until_success() {
        let state = CertificateErrorState::default();
        assert!(state.note("missing certificate".to_owned()));
        assert!(!state.note("missing certificate".to_owned()));
        assert!(state.note("expired certificate".to_owned()));
        assert!(!state.note("expired certificate".to_owned()));
        state.clear();
        assert!(state.note("expired certificate".to_owned()));
    }

    #[test]
    fn checks_certificate_validity_boundaries() {
        assert!(!certificate_valid_at(101, 200, 100));
        assert!(certificate_valid_at(101, 200, 101));
        assert!(certificate_valid_at(101, 200, 150));
        assert!(certificate_valid_at(101, 200, 200));
        assert!(!certificate_valid_at(101, 200, 201));
    }

    #[test]
    fn normalizes_ascii_case_and_exactly_one_trailing_dot() {
        assert_eq!(normalize_host("ExAmPlE.CoM."), "example.com");
        assert_eq!(normalize_host("EXAMPLE.COM"), "example.com");
        assert_eq!(normalize_host("example.com.."), "example.com.");
    }
}
