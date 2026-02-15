/*
 * This file is part of rusty-pcap.
 *
 * rusty-pcap is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * rusty-pcap is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * rusty-pcap. If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * This module handles TLS certificate generation for mTLS support.
 * It can generate a self-signed CA certificate, server certificates,
 * and client certificates signed by the CA.
 */

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use std::fs;
use std::io;
use std::path::Path;
use time::{Duration, OffsetDateTime};

/// Paths to the generated certificate files within a certs directory.
pub struct CertPaths {
    pub ca_cert: String,
    pub ca_key: String,
    pub server_cert: String,
    pub server_key: String,
    pub client_cert: String,
    pub client_key: String,
}

impl CertPaths {
    pub fn new(certs_dir: &str) -> Self {
        CertPaths {
            ca_cert: format!("{}/ca.pem", certs_dir),
            ca_key: format!("{}/ca.key", certs_dir),
            server_cert: format!("{}/server.pem", certs_dir),
            server_key: format!("{}/server.key", certs_dir),
            client_cert: format!("{}/client.pem", certs_dir),
            client_key: format!("{}/client.key", certs_dir),
        }
    }
}

/// Check if all required certificates exist and generate any that are missing.
/// Returns the paths to the certificate files.
pub fn ensure_certificates(
    certs_dir: &str,
    server_sans: &[String],
) -> Result<CertPaths, Box<dyn std::error::Error>> {
    let paths = CertPaths::new(certs_dir);

    // Ensure the certs directory exists
    let dir_path = Path::new(certs_dir);
    if !dir_path.exists() {
        log::info!(
            "Certificate directory '{}' does not exist, creating it",
            certs_dir
        );
        fs::create_dir_all(dir_path)?;
        log::info!("Created certificate directory: {}", certs_dir);
    }

    let ca_exists = Path::new(&paths.ca_cert).exists() && Path::new(&paths.ca_key).exists();
    let server_exists =
        Path::new(&paths.server_cert).exists() && Path::new(&paths.server_key).exists();
    let client_exists =
        Path::new(&paths.client_cert).exists() && Path::new(&paths.client_key).exists();

    if ca_exists && server_exists && client_exists {
        log::info!("All certificates found in '{}'", certs_dir);
        log::info!("  CA cert:     {}", paths.ca_cert);
        log::info!("  Server cert: {}", paths.server_cert);
        log::info!("  Client cert: {}", paths.client_cert);
        return Ok(paths);
    }

    // If the CA doesn't exist, we need to regenerate everything since
    // server/client certs are signed by the CA.
    if !ca_exists {
        log::info!("CA certificate not found, generating full certificate chain");
        generate_full_chain(certs_dir, server_sans, &paths)?;
    } else {
        // CA exists, generate only missing certs
        log::info!("CA certificate found, loading it to sign any missing certificates");

        let ca_cert_pem = fs::read_to_string(&paths.ca_cert).map_err(|e| {
            log::error!("Failed to read CA certificate at '{}': {}", paths.ca_cert, e);
            e
        })?;
        let ca_key_pem = fs::read_to_string(&paths.ca_key).map_err(|e| {
            log::error!("Failed to read CA key at '{}': {}", paths.ca_key, e);
            e
        })?;

        let ca_key = KeyPair::from_pem(&ca_key_pem).map_err(|e| {
            log::error!("Failed to parse CA private key: {}", e);
            io::Error::new(io::ErrorKind::InvalidData, format!("Invalid CA key: {}", e))
        })?;

        let ca_params = CertificateParams::from_ca_cert_pem(&ca_cert_pem).map_err(|e| {
            log::error!("Failed to parse CA certificate: {}", e);
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid CA cert: {}", e),
            )
        })?;
        let ca_cert = ca_params.self_signed(&ca_key).map_err(|e| {
            log::error!("Failed to reconstruct CA certificate: {}", e);
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to reconstruct CA: {}", e),
            )
        })?;

        if !server_exists {
            log::info!("Server certificate not found, generating it");
            generate_server_cert(server_sans, &ca_cert, &ca_key, &paths)?;
        } else {
            log::info!("Server certificate found: {}", paths.server_cert);
        }

        if !client_exists {
            log::info!("Client certificate not found, generating it");
            generate_client_cert(&ca_cert, &ca_key, &paths)?;
        } else {
            log::info!("Client certificate found: {}", paths.client_cert);
        }
    }

    Ok(paths)
}

/// Generate a complete certificate chain: CA, server cert, and client cert.
fn generate_full_chain(
    certs_dir: &str,
    server_sans: &[String],
    paths: &CertPaths,
) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Generating new CA certificate...");
    let (ca_cert, ca_key) = generate_ca()?;

    // Write CA cert and key
    let ca_cert_pem = ca_cert.pem();
    let ca_key_pem = ca_key.serialize_pem();
    fs::write(&paths.ca_cert, &ca_cert_pem)?;
    fs::write(&paths.ca_key, &ca_key_pem)?;
    log::info!("CA certificate written to: {}", paths.ca_cert);
    log::info!("CA private key written to: {}", paths.ca_key);

    // Set restrictive permissions on the CA key
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&paths.ca_key, fs::Permissions::from_mode(0o600))?;
        log::info!("Set CA key file permissions to 600 (owner read/write only)");
    }

    log::info!(
        "Generated new CA certificate for directory: {}",
        certs_dir
    );

    // Generate server and client certs signed by the new CA
    generate_server_cert(server_sans, &ca_cert, &ca_key, paths)?;
    generate_client_cert(&ca_cert, &ca_key, paths)?;

    Ok(())
}

/// Generate a self-signed CA certificate and key pair.
fn generate_ca() -> Result<(rcgen::Certificate, KeyPair), Box<dyn std::error::Error>> {
    let mut params =
        CertificateParams::new(Vec::<String>::new()).expect("empty SAN list cannot produce error");

    let now = OffsetDateTime::now_utc();
    let ten_years = Duration::days(3650);
    params.not_before = now.checked_sub(Duration::days(1)).unwrap_or(now);
    params.not_after = now
        .checked_add(ten_years)
        .unwrap_or(now.checked_add(Duration::days(365)).unwrap());

    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "Rusty Pcap CA");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Rusty Pcap");
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    log::info!("Generated self-signed CA certificate (valid for 10 years)");
    log::info!("  Subject: CN=Rusty Pcap CA, O=Rusty Pcap");

    Ok((cert, key_pair))
}

/// Generate a server certificate signed by the CA.
fn generate_server_cert(
    sans: &[String],
    ca_cert: &rcgen::Certificate,
    ca_key: &KeyPair,
    paths: &CertPaths,
) -> Result<(), Box<dyn std::error::Error>> {
    let san_list: Vec<String> = if sans.is_empty() {
        log::info!("No server SANs specified, using defaults: localhost, 127.0.0.1, 0.0.0.0");
        vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "0.0.0.0".to_string(),
        ]
    } else {
        let mut list = sans.to_vec();
        // Always include localhost for local development
        if !list.contains(&"localhost".to_string()) {
            list.push("localhost".to_string());
        }
        list
    };

    log::info!("Generating server certificate with SANs: {:?}", san_list);

    let mut params = CertificateParams::new(san_list.clone())?;

    let now = OffsetDateTime::now_utc();
    let one_year = Duration::days(365);
    params.not_before = now.checked_sub(Duration::days(1)).unwrap_or(now);
    params.not_after = now
        .checked_add(one_year)
        .unwrap_or(now.checked_add(Duration::days(30)).unwrap());

    params
        .distinguished_name
        .push(DnType::CommonName, "Rusty Pcap Server");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Rusty Pcap");
    params.use_authority_key_identifier_extension = true;
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);

    let server_key = KeyPair::generate()?;
    let server_cert = params.signed_by(&server_key, ca_cert, ca_key)?;

    let server_cert_pem = server_cert.pem();
    let server_key_pem = server_key.serialize_pem();
    fs::write(&paths.server_cert, &server_cert_pem)?;
    fs::write(&paths.server_key, &server_key_pem)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&paths.server_key, fs::Permissions::from_mode(0o600))?;
    }

    log::info!("Server certificate written to: {}", paths.server_cert);
    log::info!("Server private key written to: {}", paths.server_key);
    log::info!("  Subject: CN=Rusty Pcap Server, O=Rusty Pcap");
    log::info!("  Valid for: 1 year");
    log::info!("  SANs: {:?}", san_list);

    Ok(())
}

/// Generate a client certificate signed by the CA.
fn generate_client_cert(
    ca_cert: &rcgen::Certificate,
    ca_key: &KeyPair,
    paths: &CertPaths,
) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Generating client certificate...");

    let mut params =
        CertificateParams::new(Vec::<String>::new()).expect("empty SAN list cannot produce error");

    let now = OffsetDateTime::now_utc();
    let one_year = Duration::days(365);
    params.not_before = now.checked_sub(Duration::days(1)).unwrap_or(now);
    params.not_after = now
        .checked_add(one_year)
        .unwrap_or(now.checked_add(Duration::days(30)).unwrap());

    params
        .distinguished_name
        .push(DnType::CommonName, "Rusty Pcap Client");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Rusty Pcap");
    params.use_authority_key_identifier_extension = true;
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);

    let client_key = KeyPair::generate()?;
    let client_cert = params.signed_by(&client_key, ca_cert, ca_key)?;

    let client_cert_pem = client_cert.pem();
    let client_key_pem = client_key.serialize_pem();
    fs::write(&paths.client_cert, &client_cert_pem)?;
    fs::write(&paths.client_key, &client_key_pem)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&paths.client_key, fs::Permissions::from_mode(0o600))?;
    }

    log::info!("Client certificate written to: {}", paths.client_cert);
    log::info!("Client private key written to: {}", paths.client_key);
    log::info!("  Subject: CN=Rusty Pcap Client, O=Rusty Pcap");
    log::info!("  Valid for: 1 year");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_generate_full_chain() {
        let tmp_dir = TempDir::new().unwrap();
        let certs_dir = tmp_dir.path().to_str().unwrap();
        let sans = vec!["localhost".to_string(), "127.0.0.1".to_string()];

        let paths = ensure_certificates(certs_dir, &sans).unwrap();

        // Verify all files exist
        assert!(Path::new(&paths.ca_cert).exists());
        assert!(Path::new(&paths.ca_key).exists());
        assert!(Path::new(&paths.server_cert).exists());
        assert!(Path::new(&paths.server_key).exists());
        assert!(Path::new(&paths.client_cert).exists());
        assert!(Path::new(&paths.client_key).exists());

        // Verify PEM format
        let ca_pem = fs::read_to_string(&paths.ca_cert).unwrap();
        assert!(ca_pem.contains("BEGIN CERTIFICATE"));
        let server_pem = fs::read_to_string(&paths.server_cert).unwrap();
        assert!(server_pem.contains("BEGIN CERTIFICATE"));
        let client_pem = fs::read_to_string(&paths.client_cert).unwrap();
        assert!(client_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn test_regenerate_missing_server_cert() {
        let tmp_dir = TempDir::new().unwrap();
        let certs_dir = tmp_dir.path().to_str().unwrap();
        let sans = vec!["localhost".to_string()];

        // Generate full chain first
        ensure_certificates(certs_dir, &sans).unwrap();

        // Remove server cert
        let paths = CertPaths::new(certs_dir);
        fs::remove_file(&paths.server_cert).unwrap();
        fs::remove_file(&paths.server_key).unwrap();

        // Re-run should regenerate only server cert
        let paths = ensure_certificates(certs_dir, &sans).unwrap();
        assert!(Path::new(&paths.server_cert).exists());
        assert!(Path::new(&paths.server_key).exists());
    }

    #[test]
    fn test_regenerate_missing_client_cert() {
        let tmp_dir = TempDir::new().unwrap();
        let certs_dir = tmp_dir.path().to_str().unwrap();
        let sans = vec!["localhost".to_string()];

        // Generate full chain first
        ensure_certificates(certs_dir, &sans).unwrap();

        // Remove client cert
        let paths = CertPaths::new(certs_dir);
        fs::remove_file(&paths.client_cert).unwrap();
        fs::remove_file(&paths.client_key).unwrap();

        // Re-run should regenerate only client cert
        let paths = ensure_certificates(certs_dir, &sans).unwrap();
        assert!(Path::new(&paths.client_cert).exists());
        assert!(Path::new(&paths.client_key).exists());
    }

    #[test]
    fn test_existing_certs_not_overwritten() {
        let tmp_dir = TempDir::new().unwrap();
        let certs_dir = tmp_dir.path().to_str().unwrap();
        let sans = vec!["localhost".to_string()];

        // Generate full chain
        ensure_certificates(certs_dir, &sans).unwrap();

        // Read the CA cert content
        let paths = CertPaths::new(certs_dir);
        let original_ca = fs::read_to_string(&paths.ca_cert).unwrap();

        // Re-run should not regenerate anything
        ensure_certificates(certs_dir, &sans).unwrap();
        let after_ca = fs::read_to_string(&paths.ca_cert).unwrap();

        assert_eq!(original_ca, after_ca, "CA cert should not be regenerated");
    }
}
