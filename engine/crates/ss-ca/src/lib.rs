//! `ss-ca` — SecureSuite's internal certificate authority.
//!
//! SecureSuite intercepts TLS by terminating the client's connection with a
//! certificate it generates on the fly for the requested host, signed by a
//! locally-trusted root CA. This crate owns that root CA and mints (and caches)
//! the per-host leaf certificates used for interception.
//!
//! Pure Rust via [`rcgen`] — no OpenSSL / system crypto dependency.
//!
//! ```
//! use ss_ca::CertAuthority;
//!
//! let ca = CertAuthority::generate().unwrap();
//! let leaf = ca.leaf_for("example.com").unwrap();
//! assert!(leaf.cert_pem.contains("BEGIN CERTIFICATE"));
//! ```

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Mutex;

use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use thiserror::Error;

/// Errors produced by the certificate authority.
#[derive(Debug, Error)]
pub enum CaError {
    /// Certificate generation / signing failed.
    #[error("certificate generation failed: {0}")]
    Rcgen(#[from] rcgen::Error),
    /// Reading or writing persisted CA material failed.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

/// A PEM-encoded certificate together with its private key.
#[derive(Clone, Debug)]
pub struct PemPair {
    /// PEM-encoded X.509 certificate.
    pub cert_pem: String,
    /// PEM-encoded private key.
    pub key_pem: String,
}

/// SecureSuite's root certificate authority.
///
/// Holds the root certificate (for export/trust) and an [`Issuer`] that signs
/// leaf certificates, plus an in-memory cache of already-minted leaves keyed by
/// host.
pub struct CertAuthority {
    ca_cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
    cache: Mutex<HashMap<String, PemPair>>,
}

impl CertAuthority {
    /// Generate a brand-new in-memory root CA (not persisted).
    pub fn generate() -> Result<Self, CaError> {
        let (ca_cert_pem, _ca_key_pem, issuer) = Self::generate_parts()?;
        Ok(Self {
            ca_cert_pem,
            issuer,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// Load a persisted root CA from `dir`, or generate and persist one if none
    /// exists. Writes `ca-cert.pem` (public, safe to distribute) and
    /// `ca-key.pem` (private; `0600` on Unix).
    pub fn load_or_generate(dir: &Path) -> Result<Self, CaError> {
        let cert_path = dir.join("ca-cert.pem");
        let key_path = dir.join("ca-key.pem");

        if cert_path.exists() && key_path.exists() {
            let ca_cert_pem = fs::read_to_string(&cert_path)?;
            let key_pem = fs::read_to_string(&key_path)?;
            let key = KeyPair::from_pem(&key_pem)?;
            let issuer = Issuer::from_ca_cert_pem(&ca_cert_pem, key)?;
            return Ok(Self {
                ca_cert_pem,
                issuer,
                cache: Mutex::new(HashMap::new()),
            });
        }

        let (ca_cert_pem, ca_key_pem, issuer) = Self::generate_parts()?;
        fs::create_dir_all(dir)?;
        fs::write(&cert_path, ca_cert_pem.as_bytes())?;
        write_private(&key_path, ca_key_pem.as_bytes())?;
        Ok(Self {
            ca_cert_pem,
            issuer,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// The root CA certificate in PEM form. Import this into a browser/OS trust
    /// store to let SecureSuite intercept HTTPS.
    pub fn root_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Number of leaf certificates currently cached.
    pub fn cached_count(&self) -> usize {
        self.cache.lock().expect("ca cache poisoned").len()
    }

    /// Mint (or return a cached) leaf certificate valid for `host`, signed by
    /// this CA.
    pub fn leaf_for(&self, host: &str) -> Result<PemPair, CaError> {
        if let Some(existing) = self.cache.lock().expect("ca cache poisoned").get(host) {
            return Ok(existing.clone());
        }

        let mut params = CertificateParams::new(vec![host.to_string()])?;
        params.is_ca = IsCa::NoCa;
        params.use_authority_key_identifier_extension = true;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.distinguished_name.push(DnType::CommonName, host);
        params.not_before = date_time_ymd(2024, 1, 1);
        params.not_after = date_time_ymd(2034, 1, 1);

        let leaf_key = KeyPair::generate()?;
        let leaf_cert = params.signed_by(&leaf_key, &self.issuer)?;
        let pair = PemPair {
            cert_pem: leaf_cert.pem(),
            key_pem: leaf_key.serialize_pem(),
        };

        self.cache
            .lock()
            .expect("ca cache poisoned")
            .insert(host.to_string(), pair.clone());
        Ok(pair)
    }

    fn generate_parts() -> Result<(String, String, Issuer<'static, KeyPair>), CaError> {
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params
            .distinguished_name
            .push(DnType::CommonName, "SecureSuite CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "SecureSuite");
        params.not_before = date_time_ymd(2024, 1, 1);
        params.not_after = date_time_ymd(2034, 1, 1);

        let key = KeyPair::generate()?;
        let cert = params.self_signed(&key)?;
        let ca_cert_pem = cert.pem();
        let ca_key_pem = key.serialize_pem();
        let issuer = Issuer::new(params, key);
        Ok((ca_cert_pem, ca_key_pem, issuer))
    }
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    fs::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::prelude::*;

    #[test]
    fn generates_root_cert() {
        let ca = CertAuthority::generate().unwrap();
        assert!(ca.root_cert_pem().contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn leaves_are_cached() {
        let ca = CertAuthority::generate().unwrap();
        assert_eq!(ca.cached_count(), 0);
        let a = ca.leaf_for("example.com").unwrap();
        let b = ca.leaf_for("example.com").unwrap();
        assert_eq!(a.cert_pem, b.cert_pem, "second call should hit the cache");
        assert_eq!(ca.cached_count(), 1);
    }

    #[test]
    fn distinct_hosts_get_distinct_leaves() {
        let ca = CertAuthority::generate().unwrap();
        let a = ca.leaf_for("a.example").unwrap();
        let b = ca.leaf_for("b.example").unwrap();
        assert_ne!(a.cert_pem, b.cert_pem);
        assert!(a.key_pem.contains("PRIVATE KEY"));
        assert_eq!(ca.cached_count(), 2);
    }

    #[test]
    fn leaf_is_issued_by_ca_for_host() {
        let ca = CertAuthority::generate().unwrap();
        let leaf = ca.leaf_for("shop.example").unwrap();

        let (_, pem) = parse_x509_pem(leaf.cert_pem.as_bytes()).expect("valid pem");
        let cert = pem.parse_x509().expect("valid x509");

        let issuer = cert.issuer().to_string();
        assert!(issuer.contains("SecureSuite CA"), "issuer was: {issuer}");

        let subject = cert.subject().to_string();
        assert!(subject.contains("shop.example"), "subject was: {subject}");

        let san = cert
            .subject_alternative_name()
            .expect("SAN extension parses")
            .expect("SAN extension present");
        let has_host = san
            .value
            .general_names
            .iter()
            .any(|gn| matches!(gn, GeneralName::DNSName(name) if *name == "shop.example"));
        assert!(has_host, "SAN did not contain the host");
    }

    #[test]
    fn persistence_roundtrip_keeps_same_ca() {
        let dir = tempfile::tempdir().unwrap();
        let first = CertAuthority::load_or_generate(dir.path()).unwrap();
        let second = CertAuthority::load_or_generate(dir.path()).unwrap();
        assert_eq!(
            first.root_cert_pem(),
            second.root_cert_pem(),
            "reloading must yield the same root CA"
        );
        assert!(dir.path().join("ca-cert.pem").exists());
        assert!(dir.path().join("ca-key.pem").exists());

        // A leaf minted after reload is still valid/issued by the same CA.
        let leaf = second.leaf_for("late.example").unwrap();
        assert!(leaf.cert_pem.contains("BEGIN CERTIFICATE"));
    }

    #[cfg(unix)]
    #[test]
    fn ca_key_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let _ca = CertAuthority::load_or_generate(dir.path()).unwrap();
        let mode = fs::metadata(dir.path().join("ca-key.pem"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o077,
            0,
            "CA private key must not be group/world accessible"
        );
    }
}
