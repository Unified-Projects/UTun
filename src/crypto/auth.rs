use chrono::Utc;
use pem_rfc7468;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::fmt;
use std::fs;
use std::ops::Deref;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration as StdDuration, SystemTime};
use thiserror::Error;
use x509_parser::prelude::*;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Certificate parsing failed: {0}")]
    CertParseError(String),

    #[error("Private key loading failed: {0}")]
    KeyLoadError(String),

    #[error("Certificate verification failed: {0}")]
    VerificationFailed(String),

    #[error("Invalid certificate chain")]
    InvalidChain,

    #[error("Certificate expired")]
    Expired,

    #[error("Certificate not yet valid")]
    NotYetValid,

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Certificate generation failed: {0}")]
    GenerationFailed(String),

    #[error(transparent)]
    FileAccess(#[from] crate::crypto::file_access::FileAccessError),
}

#[cfg(windows)]
fn check_windows_file_permissions(path: &Path) -> Result<(), AuthError> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{BOOL, PSID};
    use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows::Win32::Security::{
        AclSizeInformation, GetAce, GetAclInformation, IsWellKnownSid, WinBuiltinUsersSid,
        WinWorldSid, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION,
        SECURITY_DESCRIPTOR,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING,
    };
    use windows::Win32::System::Memory::LocalFree;

    let wide_path: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let handle = CreateFileW(
            PCWSTR(wide_path.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            Default::default(),
            None,
        )
        .map_err(|e| AuthError::KeyLoadError(format!("Failed to open file: {}", e)))?;

        let mut sd: *mut SECURITY_DESCRIPTOR = std::ptr::null_mut();
        let mut dacl: *mut ACL = std::ptr::null_mut();

        let result = GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            windows::Win32::Security::DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            &mut sd as *mut _ as *mut _,
        );

        let _ = windows::Win32::Foundation::CloseHandle(handle);

        if result.is_err() {
            return Err(AuthError::KeyLoadError(
                "Failed to get file security info".to_string(),
            ));
        }

        if dacl.is_null() {
            if !sd.is_null() {
                let _ = LocalFree(Some(sd as *mut _));
            }
            return Err(AuthError::KeyLoadError(
                "File has no DACL (NULL DACL means full access to everyone)".to_string(),
            ));
        }

        let mut acl_info: ACL_SIZE_INFORMATION = std::mem::zeroed();
        let info_result = GetAclInformation(
            dacl,
            &mut acl_info as *mut _ as *mut _,
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        );

        if info_result == BOOL(0) {
            if !sd.is_null() {
                let _ = LocalFree(Some(sd as *mut _));
            }
            return Err(AuthError::KeyLoadError(
                "Failed to get ACL information".to_string(),
            ));
        }

        for i in 0..acl_info.AceCount {
            let mut ace: *mut std::ffi::c_void = std::ptr::null_mut();
            if GetAce(dacl, i, &mut ace) == BOOL(0) {
                continue;
            }

            let ace_header = &*(ace as *const ACE_HEADER);
            if ace_header.AceType == 0 {
                let allowed_ace = &*(ace as *const ACCESS_ALLOWED_ACE);
                let sid = &allowed_ace.SidStart as *const u32 as PSID;

                if IsWellKnownSid(sid, WinWorldSid).as_bool()
                    || IsWellKnownSid(sid, WinBuiltinUsersSid).as_bool()
                {
                    if !sd.is_null() {
                        let _ = LocalFree(Some(sd as *mut _));
                    }
                    return Err(AuthError::KeyLoadError(format!(
                        "Private key file {:?} is accessible by Everyone or Users group. \
                         Remove broad permissions to protect the key.",
                        path
                    )));
                }
            }
        }

        if !sd.is_null() {
            let _ = LocalFree(Some(sd as *mut _));
        }
    }

    Ok(())
}

/// Wrapper type for secret byte arrays that automatically zeroizes memory on drop.
/// Use `expose_secret()` to access the underlying bytes.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes {
    data: Vec<u8>,
}

impl SecretBytes {
    /// Create a new SecretBytes from raw bytes
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Expose the secret data. Use with caution.
    pub fn expose_secret(&self) -> &[u8] {
        &self.data
    }

    /// Convert to owned Vec, consuming the wrapper.
    /// The returned Vec will NOT be zeroized on drop.
    pub fn into_inner(mut self) -> Vec<u8> {
        std::mem::take(&mut self.data)
    }
}

impl Deref for SecretBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretBytes")
            .field("len", &self.data.len())
            .field("data", &"[REDACTED]")
            .finish()
    }
}

/// Wrapper type for secret strings that automatically zeroizes memory on drop.
/// Use `expose_secret()` to access the underlying string.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretString {
    data: String,
}

impl SecretString {
    /// Create a new SecretString from a String
    pub fn new(data: String) -> Self {
        Self { data }
    }

    /// Expose the secret data. Use with caution.
    pub fn expose_secret(&self) -> &str {
        &self.data
    }

    /// Convert to owned String, consuming the wrapper.
    /// The returned String will NOT be zeroized on drop.
    pub fn into_inner(mut self) -> String {
        std::mem::take(&mut self.data)
    }
}

impl Deref for SecretString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretString")
            .field("len", &self.data.len())
            .field("data", &"[REDACTED]")
            .finish()
    }
}

/// Certificate and key pair bundle with zeroizing private key storage.
///
/// The private key fields use SecretBytes and SecretString wrappers that
/// automatically zeroize memory when the bundle is dropped. Use `expose_secret()`
/// methods to access the private key data.
#[derive(Debug, Clone)]
pub struct CertBundle {
    /// DER-encoded certificate
    pub certificate_der: Vec<u8>,

    /// DER-encoded private key (zeroized on drop)
    pub private_key_der: SecretBytes,

    /// PEM-formatted certificate
    pub certificate_pem: String,

    /// PEM-formatted private key (zeroized on drop)
    pub private_key_pem: SecretString,
}

/// Helper function to convert PEM to DER
fn pem_to_der(pem_str: &str) -> Result<Vec<u8>, String> {
    // Parse PEM and extract the base64 data
    let (_label, der_bytes) = pem_rfc7468::decode_vec(pem_str.as_bytes())
        .map_err(|e| format!("PEM parse failed: {:?}", e))?;
    Ok(der_bytes)
}

/// Generate a CA certificate
pub fn generate_ca_certificate(
    common_name: &str,
    validity_days: u32,
) -> Result<CertBundle, AuthError> {
    // Create key pair for CA
    let key_pair = KeyPair::generate()
        .map_err(|e| AuthError::GenerationFailed(format!("Key generation failed: {}", e)))?;

    // Build distinguished name
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CountryName, "US");
    distinguished_name.push(DnType::StateOrProvinceName, "California");
    distinguished_name.push(DnType::LocalityName, "San Francisco");
    distinguished_name.push(DnType::OrganizationName, "UTun PQC Tunnel");
    distinguished_name.push(DnType::CommonName, common_name);

    // Build certificate parameters
    let mut params = CertificateParams::new(vec![])
        .map_err(|e| AuthError::GenerationFailed(format!("Params creation failed: {}", e)))?;

    params.distinguished_name = distinguished_name;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    // Set validity period
    let not_before = SystemTime::now();
    let not_after = not_before + StdDuration::from_secs(validity_days as u64 * 86400);
    params.not_before = not_before.into();
    params.not_after = not_after.into();

    // Generate self-signed certificate
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| AuthError::GenerationFailed(format!("Self-signing failed: {}", e)))?;

    // Serialize to PEM and DER
    let certificate_pem = cert.pem();
    let certificate_der = cert.der().to_vec();
    let private_key_pem = SecretString::new(key_pair.serialize_pem());
    let private_key_der = SecretBytes::new(key_pair.serialize_der());

    Ok(CertBundle {
        certificate_der,
        private_key_der,
        certificate_pem,
        private_key_pem,
    })
}

/// Generate a server certificate signed by a CA
pub fn generate_server_certificate(
    ca_cert_pem: &str,
    ca_key_pem: &str,
    common_name: &str,
    dns_names: Vec<String>,
    ip_addresses: Vec<String>,
    validity_days: u32,
) -> Result<CertBundle, AuthError> {
    // Parse CA private key from PEM
    let ca_key_pair = KeyPair::from_pem(ca_key_pem)
        .map_err(|e| AuthError::KeyLoadError(format!("Failed to parse CA key: {}", e)))?;

    // Parse CA certificate from PEM to extract parameters
    let ca_cert_der = pem_to_der(ca_cert_pem)
        .map_err(|e| AuthError::CertParseError(format!("Failed to parse CA cert PEM: {}", e)))?;

    // Validate CA certificate structure
    let (_, _ca_x509) = X509Certificate::from_der(&ca_cert_der)
        .map_err(|e| AuthError::CertParseError(format!("Failed to parse CA cert DER: {}", e)))?;

    let issuer = Issuer::from_ca_cert_pem(ca_cert_pem, ca_key_pair)
        .map_err(|e| AuthError::CertParseError(format!("Failed to parse CA cert PEM: {}", e)))?;

    // Create server key pair
    let server_key_pair = KeyPair::generate()
        .map_err(|e| AuthError::GenerationFailed(format!("Server key generation failed: {}", e)))?;

    // Build distinguished name
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CountryName, "US");
    distinguished_name.push(DnType::StateOrProvinceName, "California");
    distinguished_name.push(DnType::LocalityName, "San Francisco");
    distinguished_name.push(DnType::OrganizationName, "UTun PQC Tunnel");
    distinguished_name.push(DnType::CommonName, common_name);

    // Build subject alternative names as Strings for rcgen
    let mut subject_alt_names = Vec::new();
    for dns_name in &dns_names {
        subject_alt_names.push(dns_name.clone());
    }
    for ip_address in &ip_addresses {
        subject_alt_names.push(ip_address.clone());
    }

    // Build certificate parameters
    let mut params = CertificateParams::new(subject_alt_names)
        .map_err(|e| AuthError::GenerationFailed(format!("Params creation failed: {}", e)))?;

    params.distinguished_name = distinguished_name;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    // Set validity period
    let not_before = SystemTime::now();
    let not_after = not_before + StdDuration::from_secs(validity_days as u64 * 86400);
    params.not_before = not_before.into();
    params.not_after = not_after.into();

    // Sign certificate with CA (proper CA signing implemented)
    let cert = params
        .signed_by(&server_key_pair, &issuer)
        .map_err(|e| AuthError::GenerationFailed(format!("CA signing failed: {}", e)))?;

    // Serialize to PEM and DER
    let certificate_pem = cert.pem();
    let certificate_der = cert.der().to_vec();
    let private_key_pem = SecretString::new(server_key_pair.serialize_pem());
    let private_key_der = SecretBytes::new(server_key_pair.serialize_der());

    Ok(CertBundle {
        certificate_der,
        private_key_der,
        certificate_pem,
        private_key_pem,
    })
}

/// Generate a client certificate signed by a CA
pub fn generate_client_certificate(
    ca_cert_pem: &str,
    ca_key_pem: &str,
    common_name: &str,
    validity_days: u32,
) -> Result<CertBundle, AuthError> {
    // Parse CA private key from PEM
    let ca_key_pair = KeyPair::from_pem(ca_key_pem)
        .map_err(|e| AuthError::KeyLoadError(format!("Failed to parse CA key: {}", e)))?;

    // Parse CA certificate from PEM to extract parameters
    let ca_cert_der = pem_to_der(ca_cert_pem)
        .map_err(|e| AuthError::CertParseError(format!("Failed to parse CA cert PEM: {}", e)))?;

    // Validate CA certificate structure
    let (_, _ca_x509) = X509Certificate::from_der(&ca_cert_der)
        .map_err(|e| AuthError::CertParseError(format!("Failed to parse CA cert DER: {}", e)))?;

    let issuer = Issuer::from_ca_cert_pem(ca_cert_pem, ca_key_pair)
        .map_err(|e| AuthError::CertParseError(format!("Failed to parse CA cert PEM: {}", e)))?;

    // Create client key pair
    let client_key_pair = KeyPair::generate()
        .map_err(|e| AuthError::GenerationFailed(format!("Client key generation failed: {}", e)))?;

    // Build distinguished name
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CountryName, "US");
    distinguished_name.push(DnType::StateOrProvinceName, "California");
    distinguished_name.push(DnType::LocalityName, "San Francisco");
    distinguished_name.push(DnType::OrganizationName, "UTun PQC Tunnel");
    distinguished_name.push(DnType::CommonName, common_name);

    // Build certificate parameters
    let mut params = CertificateParams::new(vec![])
        .map_err(|e| AuthError::GenerationFailed(format!("Params creation failed: {}", e)))?;

    params.distinguished_name = distinguished_name;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];

    // Set validity period
    let not_before = SystemTime::now();
    let not_after = not_before + StdDuration::from_secs(validity_days as u64 * 86400);
    params.not_before = not_before.into();
    params.not_after = not_after.into();

    // Sign certificate with CA (proper CA signing implemented)
    let cert = params
        .signed_by(&client_key_pair, &issuer)
        .map_err(|e| AuthError::GenerationFailed(format!("CA signing failed: {}", e)))?;

    // Serialize to PEM and DER
    let certificate_pem = cert.pem();
    let certificate_der = cert.der().to_vec();
    let private_key_pem = SecretString::new(client_key_pair.serialize_pem());
    let private_key_der = SecretBytes::new(client_key_pair.serialize_der());

    Ok(CertBundle {
        certificate_der,
        private_key_der,
        certificate_pem,
        private_key_pem,
    })
}

/// Load a certificate bundle from files
///
/// # Security
///
/// On Unix systems, validates that the private key file has restrictive permissions (0600).
/// On Windows, logs a warning about ACL checks not being implemented.
///
/// # Clock Dependency
///
/// Certificate validity is checked against the system clock. Ensure the system time
/// is synchronized (e.g., via NTP) to avoid false positive/negative validity errors.
/// If the system clock is more than a few minutes off, certificate validation may fail.
pub fn load_cert_bundle(cert_path: &Path, key_path: &Path) -> Result<CertBundle, AuthError> {
    // Validate key file permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let key_perms = fs::metadata(key_path)?.permissions();
        let mode = key_perms.mode() & 0o777;

        if mode & 0o077 != 0 {
            return Err(AuthError::KeyLoadError(format!(
                "Private key file {:?} has insecure permissions {:o}. Must be 0600",
                key_path, mode
            )));
        }
    }

    #[cfg(windows)]
    {
        check_windows_file_permissions(key_path)?;
    }

    // Read certificate and key files
    let certificate_pem = fs::read_to_string(cert_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            let msg = format!(
                "Failed to read certificate: {}\n\nNote: Run with RUST_LOG=debug for detailed diagnostics",
                e
            );
            AuthError::IoError(std::io::Error::new(e.kind(), msg))
        } else {
            AuthError::IoError(e)
        }
    })?;

    let private_key_pem = fs::read_to_string(key_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            let msg = format!(
                "Failed to read private key: {}\n\nNote: Run with RUST_LOG=debug for detailed diagnostics",
                e
            );
            AuthError::IoError(std::io::Error::new(e.kind(), msg))
        } else {
            AuthError::IoError(e)
        }
    })?;

    // Parse PEM to DER
    let certificate_der = pem_rfc7468::decode_vec(certificate_pem.as_bytes())
        .map_err(|e| AuthError::CertParseError(format!("PEM decode failed: {}", e)))?
        .1;

    let private_key_der = pem_rfc7468::decode_vec(private_key_pem.as_bytes())
        .map_err(|e| AuthError::KeyLoadError(format!("PEM decode failed: {}", e)))?
        .1;

    // Validate certificate structure and check validity
    let (_, cert) = X509Certificate::from_der(&certificate_der)
        .map_err(|e| AuthError::CertParseError(format!("X509 parse failed: {}", e)))?;

    let validity = cert.validity();
    let now = Utc::now().timestamp();

    // Sanity check: warn if system time seems unreasonable
    // (before year 2020 or after year 2100)
    if !(1577836800..=4102444800).contains(&now) {
        tracing::warn!(
            "System clock may be incorrect (timestamp: {}). Certificate validation may be unreliable.",
            now
        );
    }

    if validity.not_before.timestamp() > now {
        return Err(AuthError::NotYetValid);
    }
    if validity.not_after.timestamp() < now {
        return Err(AuthError::Expired);
    }

    Ok(CertBundle {
        certificate_der,
        private_key_der: SecretBytes::new(private_key_der),
        certificate_pem,
        private_key_pem: SecretString::new(private_key_pem),
    })
}

/// Load a CA certificate from file
pub fn load_ca_certificate(ca_cert_path: &Path) -> Result<Vec<u8>, AuthError> {
    // Read CA certificate file
    let ca_cert_pem = fs::read_to_string(ca_cert_path)?;

    // Parse PEM to DER
    let ca_cert_der = pem_rfc7468::decode_vec(ca_cert_pem.as_bytes())
        .map_err(|e| AuthError::CertParseError(format!("PEM decode failed: {}", e)))?
        .1;

    // Validate CA certificate has CA:TRUE basic constraint
    let (_, cert) = X509Certificate::from_der(&ca_cert_der)
        .map_err(|e| AuthError::CertParseError(format!("X509 parse failed: {}", e)))?;

    if !cert.is_ca() {
        return Err(AuthError::CertParseError(
            "Certificate is not a CA".to_string(),
        ));
    }

    Ok(ca_cert_der)
}

/// Verify certificate chain
pub fn verify_certificate_chain(cert_der: &[u8], ca_cert_der: &[u8]) -> Result<(), AuthError> {
    // Parse leaf certificate using x509-parser for issuer/subject checks
    let (_, leaf_cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| AuthError::CertParseError(format!("Leaf cert parse failed: {}", e)))?;

    // Parse CA certificate
    let (_, ca_cert) = X509Certificate::from_der(ca_cert_der)
        .map_err(|e| AuthError::CertParseError(format!("CA cert parse failed: {}", e)))?;

    // Verify CA is the issuer
    if leaf_cert.issuer() != ca_cert.subject() {
        return Err(AuthError::InvalidChain);
    }

    // Verify validity periods
    let now = Utc::now().timestamp();
    let leaf_validity = leaf_cert.validity();

    if leaf_validity.not_before.timestamp() > now {
        return Err(AuthError::NotYetValid);
    }
    if leaf_validity.not_after.timestamp() < now {
        return Err(AuthError::Expired);
    }

    // Cryptographic signature verification
    let ca_public_key = ca_cert.public_key();
    leaf_cert
        .verify_signature(Some(ca_public_key))
        .map_err(|e| {
            AuthError::VerificationFailed(format!(
                "Certificate signature verification failed: {:?}",
                e
            ))
        })?;

    Ok(())
}

/// Verify certificate hostname matches
pub fn verify_certificate_hostname(cert_der: &[u8], hostname: &str) -> Result<(), AuthError> {
    // Parse certificate
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| AuthError::CertParseError(format!("Cert parse failed: {}", e)))?;

    // Extract Subject Alternative Names
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        let san = &san_ext.value;
        for name in &san.general_names {
            match name {
                GeneralName::DNSName(dns_name) => {
                    if dns_name == &hostname {
                        return Ok(());
                    }
                }
                GeneralName::IPAddress(ip_bytes) => {
                    // Try to parse hostname as IP and compare
                    if let Ok(ip) = hostname.parse::<std::net::IpAddr>() {
                        let ip_str = ip.to_string();
                        let bytes_str = match ip_bytes.len() {
                            4 => {
                                format!(
                                    "{}.{}.{}.{}",
                                    ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]
                                )
                            }
                            16 => {
                                // IPv6
                                std::net::Ipv6Addr::from([
                                    ip_bytes[0],
                                    ip_bytes[1],
                                    ip_bytes[2],
                                    ip_bytes[3],
                                    ip_bytes[4],
                                    ip_bytes[5],
                                    ip_bytes[6],
                                    ip_bytes[7],
                                    ip_bytes[8],
                                    ip_bytes[9],
                                    ip_bytes[10],
                                    ip_bytes[11],
                                    ip_bytes[12],
                                    ip_bytes[13],
                                    ip_bytes[14],
                                    ip_bytes[15],
                                ])
                                .to_string()
                            }
                            _ => continue,
                        };
                        if ip_str == bytes_str {
                            return Ok(());
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // Check CommonName as fallback
    for rdn in cert.subject().iter() {
        for attr in rdn.iter() {
            if let Ok(cn) = attr.as_str() {
                if cn == hostname {
                    return Ok(());
                }
            }
        }
    }

    Err(AuthError::VerificationFailed(format!(
        "Hostname '{}' does not match certificate",
        hostname
    )))
}

/// Create server TLS configuration with optional client certificate verification
pub fn create_server_tls_config(
    server_cert_path: &Path,
    server_key_path: &Path,
    ca_cert_path: Option<&Path>,
    require_client_cert: bool,
) -> Result<Arc<ServerConfig>, AuthError> {
    // Load server certificate bundle
    let server_bundle = load_cert_bundle(server_cert_path, server_key_path)?;

    // Parse private key (use expose_secret() to access zeroizing wrapper)
    let private_key =
        PrivateKeyDer::try_from(server_bundle.private_key_der.expose_secret().to_vec())
            .map_err(|_| AuthError::KeyLoadError("Invalid private key format".to_string()))?;

    // Build certificate chain
    let cert_chain = vec![CertificateDer::from(server_bundle.certificate_der.clone())];

    // Build server config
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(|e| {
            AuthError::GenerationFailed(format!("Server config creation failed: {}", e))
        })?;

    // If client certificate verification is required, configure it
    if require_client_cert {
        if let Some(ca_path) = ca_cert_path {
            let ca_cert_der = load_ca_certificate(ca_path)?;

            let mut root_store = RootCertStore::empty();
            root_store
                .add(CertificateDer::from(ca_cert_der))
                .map_err(|e| {
                    AuthError::CertParseError(format!("Failed to add CA to root store: {}", e))
                })?;

            let verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
                .build()
                .map_err(|e| {
                    AuthError::GenerationFailed(format!("Client verifier creation failed: {}", e))
                })?;

            config = ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(
                    vec![CertificateDer::from(server_bundle.certificate_der)],
                    PrivateKeyDer::try_from(server_bundle.private_key_der.expose_secret().to_vec())
                        .map_err(|_| {
                            AuthError::KeyLoadError("Invalid private key format".to_string())
                        })?,
                )
                .map_err(|e| {
                    AuthError::GenerationFailed(format!("Server config creation failed: {}", e))
                })?;
        }
    }

    Ok(Arc::new(config))
}

/// Create client TLS configuration with client certificate
pub fn create_client_tls_config(
    client_cert_path: &Path,
    client_key_path: &Path,
    ca_cert_path: &Path,
) -> Result<Arc<ClientConfig>, AuthError> {
    // Load client certificate bundle
    let client_bundle = load_cert_bundle(client_cert_path, client_key_path)?;

    // Load CA certificate
    let ca_cert_der = load_ca_certificate(ca_cert_path)?;

    // Build root cert store
    let mut root_store = RootCertStore::empty();
    root_store
        .add(CertificateDer::from(ca_cert_der))
        .map_err(|e| AuthError::CertParseError(format!("Failed to add CA to root store: {}", e)))?;

    // Parse private key (use expose_secret() to access zeroizing wrapper)
    let private_key =
        PrivateKeyDer::try_from(client_bundle.private_key_der.expose_secret().to_vec())
            .map_err(|_| AuthError::KeyLoadError("Invalid private key format".to_string()))?;

    // Build certificate chain
    let cert_chain = vec![CertificateDer::from(client_bundle.certificate_der.clone())];

    // Create client config
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(cert_chain, private_key)
        .map_err(|e| {
            AuthError::GenerationFailed(format!("Client config creation failed: {}", e))
        })?;

    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ca_certificate() {
        let bundle = generate_ca_certificate("Test CA", 365).unwrap();
        assert!(!bundle.certificate_pem.is_empty());
        assert!(!bundle.private_key_pem.is_empty());

        // Parse and verify CA extensions
        let (_, cert) = X509Certificate::from_der(&bundle.certificate_der).unwrap();
        assert!(cert.is_ca());
    }

    #[test]
    fn test_generate_server_certificate() {
        let ca = generate_ca_certificate("Test CA", 365).unwrap();
        let server = generate_server_certificate(
            &ca.certificate_pem,
            &ca.private_key_pem,
            "server.example.com",
            vec!["server.example.com".to_string(), "localhost".to_string()],
            vec!["127.0.0.1".to_string(), "10.0.0.1".to_string()],
            365,
        )
        .unwrap();

        // Verify signed by CA
        verify_certificate_chain(&server.certificate_der, &ca.certificate_der).unwrap();

        // Verify hostname
        verify_certificate_hostname(&server.certificate_der, "server.example.com").unwrap();
    }

    #[test]
    fn test_generate_client_certificate() {
        let ca = generate_ca_certificate("Test CA", 365).unwrap();
        let client = generate_client_certificate(
            &ca.certificate_pem,
            &ca.private_key_pem,
            "tunnel-client-001",
            365,
        )
        .unwrap();

        // Verify signed by CA
        verify_certificate_chain(&client.certificate_der, &ca.certificate_der).unwrap();
    }

    #[test]
    fn test_hostname_mismatch() {
        let ca = generate_ca_certificate("Test CA", 365).unwrap();
        let server = generate_server_certificate(
            &ca.certificate_pem,
            &ca.private_key_pem,
            "server.example.com",
            vec!["server.example.com".to_string()],
            vec![],
            365,
        )
        .unwrap();

        let result = verify_certificate_hostname(&server.certificate_der, "other.example.com");
        assert!(result.is_err());
    }
}
