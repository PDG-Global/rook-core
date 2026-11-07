use std::{
    collections::HashSet,
    fs,
    io::BufReader,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use anyhow::{Context, anyhow, bail};
use bytes::Bytes;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{client::legacy::Client as HyperClient, rt::TokioExecutor};
use instant_acme::{Account, AccountBuilder, BodyWrapper};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error, RootCertStore, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::ring,
    pki_types::{CertificateDer, ServerName, UnixTime, pem::PemObject},
    version::{TLS12, TLS13},
};
use sha2::{Digest, Sha256};
use tracing::warn;
use x509_parser::parse_x509_certificate;

#[derive(Debug)]
pub struct TrustPolicy {
    blocklist_file: Option<PathBuf>,
    blocklist: Arc<RwLock<Blocklist>>,
}

#[derive(Debug, Default)]
struct Blocklist {
    certificates: HashSet<[u8; 32]>,
    public_keys: HashSet<[u8; 32]>,
}

impl TrustPolicy {
    pub fn load(blocklist_file: Option<&Path>) -> Result<Arc<Self>, anyhow::Error> {
        let blocklist = match blocklist_file {
            Some(path) => read_blocklist(path)?,
            None => Blocklist::default(),
        };
        Ok(Arc::new(Self {
            blocklist_file: blocklist_file.map(Path::to_path_buf),
            blocklist: Arc::new(RwLock::new(blocklist)),
        }))
    }

    pub fn reload(&self) {
        let Some(path) = &self.blocklist_file else {
            return;
        };
        match read_blocklist(path) {
            Ok(blocklist) => {
                *self
                    .blocklist
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = blocklist;
            }
            Err(error) => {
                warn!(
                    path = %path.display(),
                    %error,
                    "could not reload certificate blocklist; keeping the last valid blocklist"
                );
            }
        }
    }

    pub fn acme_account_builder(
        &self,
        trusted_root: &Path,
    ) -> Result<AccountBuilder, anyhow::Error> {
        let file = fs::File::open(trusted_root)
            .with_context(|| format!("could not open trusted roots {}", trusted_root.display()))?;
        let certificates = CertificateDer::pem_reader_iter(BufReader::new(file))
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("could not parse trusted roots {}", trusted_root.display()))?;
        let mut roots = RootCertStore::empty();
        for certificate in certificates {
            roots
                .add(certificate)
                .with_context(|| format!("invalid trusted root in {}", trusted_root.display()))?;
        }
        if roots.is_empty() {
            bail!("no PEM certificates found in {}", trusted_root.display());
        }

        let provider = Arc::new(ring::default_provider());
        let webpki =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
                .build()
                .context("could not build WebPki certificate verifier")?;
        let verifier = Arc::new(BlocklistVerifier {
            webpki,
            blocklist: Arc::clone(&self.blocklist),
        });
        let config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&TLS13, &TLS12])
            .context("could not configure TLS 1.2 and TLS 1.3")?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(config)
            .https_only()
            .enable_http1()
            .enable_http2()
            .build();
        let client =
            HyperClient::builder(TokioExecutor::new()).build::<_, BodyWrapper<Bytes>>(connector);
        Ok(Account::builder_with_http(Box::new(client)))
    }
}

#[derive(Debug)]
struct BlocklistVerifier {
    webpki: Arc<WebPkiServerVerifier>,
    blocklist: Arc<RwLock<Blocklist>>,
}

impl BlocklistVerifier {
    fn check_chain(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
    ) -> Result<(), Error> {
        let blocklist = self
            .blocklist
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for certificate in std::iter::once(end_entity).chain(intermediates) {
            let certificate_hash: [u8; 32] = Sha256::digest(certificate.as_ref()).into();
            if blocklist.certificates.contains(&certificate_hash) {
                return Err(Error::General(
                    "server certificate is blocked by trust policy".to_owned(),
                ));
            }
            let (_, parsed) = parse_x509_certificate(certificate.as_ref())
                .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
            let public_key_hash: [u8; 32] =
                Sha256::digest(parsed.tbs_certificate.subject_pki.raw).into();
            if blocklist.public_keys.contains(&public_key_hash) {
                return Err(Error::General(
                    "server certificate public key is blocked by trust policy".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

impl ServerCertVerifier for BlocklistVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.webpki.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        self.check_chain(end_entity, intermediates)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.webpki
            .verify_tls12_signature(message, certificate, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.webpki
            .verify_tls13_signature(message, certificate, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }
}

fn read_blocklist(path: &Path) -> Result<Blocklist, anyhow::Error> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("could not read blocklist {}", path.display()))?;
    parse_blocklist(&contents).with_context(|| format!("invalid blocklist {}", path.display()))
}

fn parse_blocklist(contents: &str) -> Result<Blocklist, anyhow::Error> {
    let mut blocklist = Blocklist::default();
    for (index, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (kind, value) = line
            .split_once(':')
            .ok_or_else(|| anyhow!("line {} has no hash type", index + 1))?;
        let hash = parse_hash(value)
            .ok_or_else(|| anyhow!("line {} does not contain 64 hexadecimal digits", index + 1))?;
        match kind {
            "cert-sha256" => {
                blocklist.certificates.insert(hash);
            }
            "key-sha256" => {
                blocklist.public_keys.insert(hash);
            }
            _ => bail!("line {} has unknown hash type {kind:?}", index + 1),
        }
    }
    Ok(blocklist)
}

fn parse_hash(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut hash = [0; 32];
    for (output, pair) in hash.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        let text = std::str::from_utf8(pair).ok()?;
        *output = u8::from_str_radix(text, 16).ok()?;
    }
    Some(hash)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    const ROOT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDDjCCAfagAwIBAgIULZtv4zMGLxZ2q2UiZe9btZbOvRQwDQYJKoZIhvcNAQEL\n\
BQAwHzEdMBsGA1UEAwwUUm9vayB0cnVzdCB0ZXN0IHJvb3QwHhcNMjYxMTAxMTkx\n\
MjUxWhcNMzYxMDI5MTkxMjUxWjAfMR0wGwYDVQQDDBRSb29rIHRydXN0IHRlc3Qg\n\
cm9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALAc/HOV60cDkD1E\n\
ENsUBfwdMdilOpZfQSnb4PTc3THfDJrTHv68uUjy3buBzWw+gW8NaFEMGamz6jAL\n\
ZsmD1Vp4//MuYR+ovT/JzSGfIanmL8+xCKvCxOmB/ByyXhJC66cbM5SQV8RkFXmk\n\
iCh8kZO0k2wGBuSzvfi8q+bZ+vdRUQdHVSCAwHhokLi82c6c2W9v3vhKwqwYBf6V\n\
0SioVpxv7dSlYhxPyY4oQHP9px3Jqe3JRlbS7lgIMdlsjT97qxETkyOEEXQVZDdh\n\
AYT+LXJw/gMEFThSYBuKk8CDdyIHtqJR9qN4dY/O8OLI4pc0t3+0QVeQP8SetZGq\n\
Uy5goAkCAwEAAaNCMEAwHQYDVR0OBBYEFPCX+Knp+TEFA5uJHiFFh1Oh4wF3MA8G\n\
A1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBCwUAA4IB\n\
AQBnzlocxvwuAF1ZLvnXAExit9qStehOMtXemdXa0uSa4xN3Lo5ek7gx1kOBqVP0\n\
wG12JiLex3wI6Dl6o2pt3gmLXW+7RnmujolAd6yNLZyGcdBbGxi4lbLdpcgJRPi4\n\
trts6bysSyJ3lUcAnI1FZ7AmahgSKW/2k6Zvss+AW30R9uDaMOduR/oYtv3d5WUj\n\
4GO0qLu47v+/osJxTgrxrhVwBdWGvwvlJYlL5uzK5pNUt3R2ikfGXsyt79SCJknE\n\
DC7Yt18gC3ylFnNifR6od2k3igEAr3vARySy9hCotDeif76vE4p9c2+dtdiwYVsv\n\
SSfLrtoGo/99jgI7YU7en40i\n\
-----END CERTIFICATE-----\n";

    const LEAF_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDDDCCAfSgAwIBAgIUFRb5IeR35fVXwvkDqTuac07JgV0wDQYJKoZIhvcNAQEL\n\
BQAwHzEdMBsGA1UEAwwUUm9vayB0cnVzdCB0ZXN0IHJvb3QwHhcNMjYxMTAxMTkx\n\
MjUxWhcNMzYxMDI5MTkxMjUxWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0G\n\
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCcARMPSRQ8E1MIJrqyEkYUx7Vg4xe0\n\
es0r7ultiTgKj+T2nidgxrTPmCr7sMIKr0tf2SpRnuvz1U8OLAyXYKVQAkeVeKbi\n\
TbBXSOqc1HjBUqeeBrQGuwmdmDYIXaIwTwZCsp3XSUN1CnjpcyQI9riRIunt3hf5\n\
0GqQ9QdiImfwx34TUFDQ+ikZ6aBpQLoLKrGKs+lyXM/z1KfZeRJoW4plsg87ud6j\n\
AzUHCRsEBbdul/Imdkvbv/Uivsdxs+wNoPE/2EcuolZY3Q+9KrcSusBv/uucgTYn\n\
EykR5MgH3gXXSEpghZeICMZXkJu2OUGsY8OBiMO7wbCiaCKdfNz5mbBVAgMBAAGj\n\
SzBJMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsG\n\
AQUFBwMBMBQGA1UdEQQNMAuCCWxvY2FsaG9zdDANBgkqhkiG9w0BAQsFAAOCAQEA\n\
bjLNZD5ZxBHUDt7aJdibstgAQTAuYmAyH+VO5l3jcaYa2H4uDFPaCQVw2YcGnGNK\n\
du2xRdlLKWqCirbWZ+cVOAmVmrQj7484NhQnqm3kHGcixkz0T+Jin4N05/Usjx4i\n\
MyUFfnyV8aapFuB6s4YJYXRilWzRRaDeAQ+XkliBdPXdC4qIrCuNG0VHjn+c7D26\n\
jgpUJKAoXxxCEX4LMbPsLSVKzZXoC/jB9DrKTCelwxHCbGUNR8PY1xPeo20NmWJF\n\
tJfZUG3yefBxiQrBk38g/j5MXWOjoDBPN0qUdW3aaw6/s3+NM2wsHIBZxKw7Oc6M\n\
lUBjgZ5Ki4ZTHpJCLOyMag==\n\
-----END CERTIFICATE-----\n";

    fn hash_lines(certificate: u8, public_key: u8) -> String {
        format!(
            "cert-sha256:{}\nkey-sha256:{}\n",
            format!("{certificate:02x}").repeat(32),
            format!("{public_key:02X}").repeat(32)
        )
    }

    fn certificate(pem: &str) -> CertificateDer<'static> {
        CertificateDer::from_pem_slice(pem.as_bytes()).expect("test certificate is valid PEM")
    }

    fn verifier(blocklist: Blocklist) -> BlocklistVerifier {
        let mut roots = RootCertStore::empty();
        roots.add(certificate(ROOT_PEM)).unwrap();
        let provider = Arc::new(ring::default_provider());
        let webpki = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
            .build()
            .unwrap();
        BlocklistVerifier {
            webpki,
            blocklist: Arc::new(RwLock::new(blocklist)),
        }
    }

    fn verify(verifier: &BlocklistVerifier) -> Result<ServerCertVerified, Error> {
        verifier.verify_server_cert(
            &certificate(LEAF_PEM),
            &[],
            &ServerName::try_from("localhost").unwrap(),
            &[],
            UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000)),
        )
    }

    #[test]
    fn parser_accepts_comments_case_and_duplicates() {
        let input = format!(
            "\n  # comment\n{}\ncert-sha256:{}\n",
            hash_lines(0, 0xab),
            "00".repeat(32)
        );
        let blocklist = parse_blocklist(&input).unwrap();
        assert_eq!(blocklist.certificates.len(), 1);
        assert!(blocklist.certificates.contains(&[0; 32]));
        assert_eq!(blocklist.public_keys.len(), 1);
        assert!(blocklist.public_keys.contains(&[0xab; 32]));
    }

    #[test]
    fn parser_rejects_malformed_lines() {
        let valid = "00".repeat(32);
        let malformed = [
            "cert-sha256".to_owned(),
            "cert-sha256:".to_owned(),
            format!("cert-sha256:{}", "0".repeat(63)),
            format!("cert-sha256:{}g", "0".repeat(63)),
            format!("unknown:{valid}"),
            format!("CERT-SHA256:{valid}"),
            format!("cert-sha256:{valid} # inline comments are not supported"),
        ];
        for line in malformed {
            assert!(parse_blocklist(&line).is_err(), "accepted {line:?}");
        }
    }

    #[test]
    fn reload_keeps_last_good_blocklist() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("blocklist.txt");
        fs::write(&path, hash_lines(1, 2)).unwrap();
        let policy = TrustPolicy::load(Some(&path)).unwrap();

        fs::write(&path, "not-a-blocklist-entry").unwrap();
        policy.reload();
        let blocklist = policy.blocklist.read().unwrap();
        assert!(blocklist.certificates.contains(&[1; 32]));
        assert!(blocklist.public_keys.contains(&[2; 32]));
        drop(blocklist);

        fs::remove_file(&path).unwrap();
        policy.reload();
        let blocklist = policy.blocklist.read().unwrap();
        assert!(blocklist.certificates.contains(&[1; 32]));
        assert!(blocklist.public_keys.contains(&[2; 32]));
        drop(blocklist);

        fs::write(&path, hash_lines(3, 4)).unwrap();
        policy.reload();
        let blocklist = policy.blocklist.read().unwrap();
        assert!(blocklist.certificates.contains(&[3; 32]));
        assert!(!blocklist.certificates.contains(&[1; 32]));
        assert!(blocklist.public_keys.contains(&[4; 32]));
    }

    #[test]
    fn initial_bad_line_is_fatal() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("blocklist.txt");
        fs::write(&path, "cert-sha256:invalid").unwrap();
        assert!(TrustPolicy::load(Some(&path)).is_err());
    }

    #[test]
    fn blocked_certificate_is_rejected_after_webpki_verification() {
        assert!(verify(&verifier(Blocklist::default())).is_ok());

        let leaf = certificate(LEAF_PEM);
        let certificate_hash: [u8; 32] = Sha256::digest(leaf.as_ref()).into();
        let blocklist = Blocklist {
            certificates: HashSet::from([certificate_hash]),
            public_keys: HashSet::new(),
        };
        let error = verify(&verifier(blocklist)).unwrap_err();
        assert!(error.to_string().contains("certificate is blocked"));
    }

    #[test]
    fn blocked_public_key_is_rejected() {
        let leaf = certificate(LEAF_PEM);
        let (_, parsed) = parse_x509_certificate(leaf.as_ref()).unwrap();
        let public_key_hash: [u8; 32] =
            Sha256::digest(parsed.tbs_certificate.subject_pki.raw).into();
        let blocklist = Blocklist {
            certificates: HashSet::new(),
            public_keys: HashSet::from([public_key_hash]),
        };
        let error = verify(&verifier(blocklist)).unwrap_err();
        assert!(error.to_string().contains("public key is blocked"));
    }

    #[test]
    fn account_builder_requires_a_pem_root() {
        let directory = tempfile::tempdir().unwrap();
        let empty = directory.path().join("empty.pem");
        fs::write(&empty, "").unwrap();
        let policy = TrustPolicy::load(None).unwrap();
        assert!(policy.acme_account_builder(&empty).is_err());

        let root = directory.path().join("root.pem");
        fs::write(&root, ROOT_PEM).unwrap();
        assert!(policy.acme_account_builder(&root).is_ok());
    }
}
