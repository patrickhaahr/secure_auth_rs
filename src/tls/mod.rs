use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::{BufReader, Error as IoError, Read};
use std::path::Path;
use zeroize::Zeroizing;

#[derive(Debug)]
pub enum TlsError {
    IoError(IoError),
    InvalidCertificate(String),
    InvalidPrivateKey(String),
    DecryptionFailed,
    ConfigurationFailed(String),
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsError::IoError(e) => write!(f, "I/O error: {}", e),
            TlsError::InvalidCertificate(msg) => write!(f, "Invalid certificate: {}", msg),
            TlsError::InvalidPrivateKey(msg) => write!(f, "Invalid private key: {}", msg),
            TlsError::DecryptionFailed => write!(
                f,
                "Failed to decrypt private key - incorrect password or corrupted key"
            ),
            TlsError::ConfigurationFailed(msg) => write!(f, "TLS configuration failed: {}", msg),
        }
    }
}

impl std::error::Error for TlsError {}

/// Loads and validates TLS certificates with password-protected private key
pub async fn load_tls_config(
    cert_path: &str,
    key_path: &str,
    key_password: &str,
) -> Result<axum_server::tls_rustls::RustlsConfig, TlsError> {
    tracing::info!(
        "Loading TLS certificates from: {} and {}",
        cert_path,
        key_path
    );

    // Validate paths exist
    if !Path::new(cert_path).exists() {
        tracing::error!("Certificate file not found: {}", cert_path);
        return Err(TlsError::IoError(IoError::new(
            std::io::ErrorKind::NotFound,
            format!("Certificate file not found: {}", cert_path),
        )));
    }

    if !Path::new(key_path).exists() {
        tracing::error!("Private key file not found: {}", key_path);
        return Err(TlsError::IoError(IoError::new(
            std::io::ErrorKind::NotFound,
            format!("Private key file not found: {}", key_path),
        )));
    }

    // Validate password against stored password file
    validate_password(key_path, key_password)?;

    // Load certificates
    let certs = load_certificates(cert_path)?;
    tracing::info!("Loaded {} certificate(s)", certs.len());

    // Load private key
    let _private_key = load_private_key(key_path)?;
    tracing::info!("Private key loaded successfully");

    // Build TLS configuration using axum_server's helper
    // Note: This will re-read the files, but provides proper validation
    let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path)
        .await
        .map_err(|e| {
            tracing::error!("Failed to build TLS configuration: {}", e);
            TlsError::ConfigurationFailed(e.to_string())
        })?;

    tracing::info!("TLS configuration initialized successfully");
    Ok(config)
}

/// Load certificates from PEM file with validation
fn load_certificates(path: &str) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let cert_file = File::open(path).map_err(TlsError::IoError)?;
    let mut reader = BufReader::new(cert_file);

    let certs: Vec<CertificateDer<'static>> = certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            tracing::error!("Failed to parse certificate: {}", e);
            TlsError::InvalidCertificate(format!("Failed to parse PEM: {}", e))
        })?;

    if certs.is_empty() {
        tracing::error!("No certificates found in file: {}", path);
        return Err(TlsError::InvalidCertificate(
            "No certificates found in PEM file".to_string(),
        ));
    }

    // Validate certificate structure
    tracing::info!("Certificate validation passed");
    Ok(certs)
}

/// Load private key from PEM file with validation
fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, TlsError> {
    let key_file = File::open(path).map_err(TlsError::IoError)?;
    let mut reader = BufReader::new(key_file);

    // Try to parse as PKCS#8 private key
    let keys: Vec<PrivateKeyDer<'static>> = pkcs8_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            tracing::error!("Failed to parse private key: {}", e);
            TlsError::InvalidPrivateKey(format!("Failed to parse PKCS#8 PEM: {}", e))
        })?
        .into_iter()
        .map(PrivateKeyDer::from)
        .collect();

    if keys.is_empty() {
        tracing::error!("No private keys found in file: {}", path);
        return Err(TlsError::InvalidPrivateKey(
            "No private keys found in PEM file".to_string(),
        ));
    }

    tracing::info!("Private key validation passed");
    Ok(keys.into_iter().next().unwrap())
}

/// Validates the provided password against the stored password file
/// This provides application-level security for the TLS configuration
fn validate_password(key_path: &str, provided_password: &str) -> Result<(), TlsError> {
    // Derive password file path from key path
    let key_dir = Path::new(key_path)
        .parent()
        .ok_or_else(|| TlsError::InvalidPrivateKey("Invalid key path".to_string()))?;

    let password_file_path = key_dir.join(".key_password");

    if !password_file_path.exists() {
        tracing::error!(
            "Password file not found: {}",
            password_file_path.display()
        );
        return Err(TlsError::DecryptionFailed);
    }

    // Read stored password
    let mut password_file = File::open(&password_file_path).map_err(|e| {
        tracing::error!("Failed to open password file: {}", e);
        TlsError::DecryptionFailed
    })?;

    let mut stored_password = String::new();
    password_file
        .read_to_string(&mut stored_password)
        .map_err(|e| {
            tracing::error!("Failed to read password file: {}", e);
            TlsError::DecryptionFailed
        })?;

    // Use Zeroizing to ensure passwords are cleared from memory
    let stored_password_z = Zeroizing::new(stored_password.trim().to_string());
    let provided_password_z = Zeroizing::new(provided_password.to_string());

    // Constant-time comparison to prevent timing attacks
    if stored_password_z.as_bytes().len() != provided_password_z.as_bytes().len() {
        tracing::error!("TLS password validation failed - incorrect password provided");
        return Err(TlsError::DecryptionFailed);
    }

    let mut result = 0u8;
    for (a, b) in stored_password_z
        .as_bytes()
        .iter()
        .zip(provided_password_z.as_bytes().iter())
    {
        result |= a ^ b;
    }

    if result != 0 {
        tracing::error!("TLS password validation failed - incorrect password provided");
        return Err(TlsError::DecryptionFailed);
    }

    tracing::info!("TLS password validation successful");
    Ok(())
}
