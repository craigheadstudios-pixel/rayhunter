//! Self-signed TLS certificate generation for the HTTPS listener.
//!
//! Phones need HTTPS (or literal `localhost`) before their browser will grant
//! Geolocation access, so the daemon needs to terminate TLS itself rather
//! than relying on a user-provided cert. We build this on the pure-Rust
//! `p256` crate rather than rcgen's own `ring`/`aws-lc-rs` backends, so that
//! firmware-devel builds still don't require a C cross-compiler (see the
//! comment on the rcgen dependency in Cargo.toml).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use axum_server::tls_rustls::RustlsConfig;
use log::info;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rand_core::{OsRng, RngCore};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
    RemoteKeyPair, SanType, SerialNumber, SignatureAlgorithm,
};
use time::{Duration, OffsetDateTime};

use crate::error::RayhunterError;

const CERT_FILENAME: &str = "cert.pem";
const KEY_FILENAME: &str = "key.pem";

/// Wraps a `p256` signing key so rcgen can sign certificates with it, without
/// pulling in rcgen's own `ring`/`aws-lc-rs` crypto backend.
struct P256RemoteKeyPair {
    signing_key: SigningKey,
    public_key_bytes: Vec<u8>,
}

impl RemoteKeyPair for P256RemoteKeyPair {
    fn public_key(&self) -> &[u8] {
        &self.public_key_bytes
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let signature: Signature = self.signing_key.sign(msg);
        Ok(signature.to_der().as_bytes().to_vec())
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

/// SANs covering every LAN IP the supported devices hand out by default, plus
/// loopback for local debugging. IP SANs can't be wildcarded, so this is an
/// explicit list rather than a pattern.
fn subject_alt_names() -> Vec<SanType> {
    vec![
        SanType::IpAddress(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))),
        SanType::IpAddress(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        SanType::IpAddress(IpAddr::V6(Ipv6Addr::LOCALHOST)),
    ]
}

fn generate_and_persist(tls_dir: &Path) -> Result<(), RayhunterError> {
    let signing_key = SigningKey::random(&mut OsRng);
    let public_key_bytes = signing_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let remote = P256RemoteKeyPair {
        signing_key: signing_key.clone(),
        public_key_bytes,
    };
    let key_pair = KeyPair::from_remote(Box::new(remote))?;

    let mut params = CertificateParams::new(Vec::<String>::new())?;
    // rcgen can't generate a random serial number itself without its own
    // ring/aws-lc-rs backend (which we're deliberately not using, see the
    // module doc comment), so supply one directly.
    params.serial_number = Some(SerialNumber::from(OsRng.next_u64()));
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Rayhunter");
    params.distinguished_name = dn;
    params.subject_alt_names = subject_alt_names();
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    let now = OffsetDateTime::now_utc();
    // Backdate slightly to tolerate the device's clock being a bit behind
    // before it's synced (see ClockSyncMode).
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(365 * 10);

    let cert = params.self_signed(&key_pair)?;
    let cert_pem = cert.pem();
    let key_pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| RayhunterError::TlsKeyError(e.to_string()))?;

    std::fs::create_dir_all(tls_dir)?;
    std::fs::write(tls_dir.join(CERT_FILENAME), &cert_pem)?;
    std::fs::write(tls_dir.join(KEY_FILENAME), key_pem.as_bytes())?;
    info!(
        "generated new self-signed TLS certificate at {}",
        tls_dir.display()
    );

    Ok(())
}

/// Loads the TLS cert/key from `tls_dir`, generating and persisting a new
/// self-signed pair on first run so it stays stable across restarts (the
/// user only has to click through the browser's "untrusted cert" warning
/// once).
pub async fn load_or_generate_tls_config(tls_dir: &Path) -> Result<RustlsConfig, RayhunterError> {
    let cert_path = tls_dir.join(CERT_FILENAME);
    let key_path = tls_dir.join(KEY_FILENAME);

    if !cert_path.exists() || !key_path.exists() {
        generate_and_persist(tls_dir)?;
    } else {
        // Sanity-check the persisted key parses before handing it to
        // axum-server, so a corrupt file regenerates instead of failing to
        // start the HTTPS listener entirely.
        let key_pem = std::fs::read_to_string(&key_path)?;
        if SigningKey::from_pkcs8_pem(&key_pem).is_err() {
            info!("existing TLS key at {} is invalid, regenerating", key_path.display());
            generate_and_persist(tls_dir)?;
        }
    }

    RustlsConfig::from_pem_file(&cert_path, &key_path)
        .await
        .map_err(RayhunterError::TokioError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn generates_and_loads_a_valid_cert() {
        // RustlsConfig::from_pem_file needs a process-level CryptoProvider
        // installed (normally done once in main()); we use
        // tls-rustls-no-provider specifically so this isn't implicit.
        crate::crypto_provider::install_default();
        let dir = tempfile::tempdir().unwrap();
        // RustlsConfig::from_pem_file internally validates that the cert and
        // key match and parse as valid DER, so a successful load here is a
        // real correctness check of the RemoteKeyPair signing path above,
        // not just that files got written.
        load_or_generate_tls_config(dir.path()).await.unwrap();

        assert!(dir.path().join(CERT_FILENAME).exists());
        assert!(dir.path().join(KEY_FILENAME).exists());

        // Loading again should reuse the persisted cert/key rather than
        // regenerating (so the browser doesn't need to re-trust it).
        let cert_pem_before = std::fs::read_to_string(dir.path().join(CERT_FILENAME)).unwrap();
        load_or_generate_tls_config(dir.path()).await.unwrap();
        let cert_pem_after = std::fs::read_to_string(dir.path().join(CERT_FILENAME)).unwrap();
        assert_eq!(cert_pem_before, cert_pem_after);
    }

    #[tokio::test]
    async fn regenerates_a_corrupt_key() {
        crate::crypto_provider::install_default();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(CERT_FILENAME), "not a cert").unwrap();
        std::fs::write(dir.path().join(KEY_FILENAME), "not a key").unwrap();

        load_or_generate_tls_config(dir.path()).await.unwrap();
    }
}
