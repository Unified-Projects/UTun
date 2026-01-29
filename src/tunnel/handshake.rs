use crate::crypto::{
    verify_certificate_chain, verify_certificate_hostname, HybridCiphertext, HybridPublicKey,
    KeyManager,
};
use chrono::Utc;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use x509_parser::prelude::*;

/// Convert PEM-encoded certificate to DER format
/// If already DER, returns as-is
fn pem_to_der(data: &[u8]) -> Result<Vec<u8>, HandshakeError> {
    // Check if this looks like PEM (starts with -----BEGIN)
    if data.starts_with(b"-----BEGIN") {
        pem_rfc7468::decode_vec(data)
            .map(|(_, der)| der)
            .map_err(|e| HandshakeError::CertParseError(format!("PEM decode failed: {}", e)))
    } else {
        // Already DER
        Ok(data.to_vec())
    }
}

// KEM Algorithm Enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum KemAlgorithm {
    Hybrid = 0x01,
    Mlkem768 = 0x02,
    Mceliece460896 = 0x03,
}

impl KemAlgorithm {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(KemAlgorithm::Hybrid),
            0x02 => Some(KemAlgorithm::Mlkem768),
            0x03 => Some(KemAlgorithm::Mceliece460896),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

// Handshake Messages - all PQC keys/ciphertexts are stored as raw bytes for serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHello {
    pub version: u8,
    pub random: [u8; 32],
    pub supported_kems: Vec<KemAlgorithm>,
    pub client_public_key: Vec<u8>, // Serialized HybridPublicKey
    /// Unix timestamp in milliseconds for replay protection
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHello {
    pub version: u8,
    pub random: [u8; 32],
    pub selected_kem: KemAlgorithm,
    pub certificate: Vec<u8>,
    pub server_public_key: Vec<u8>, // Serialized HybridPublicKey
    pub server_kex_ct: Vec<u8>,     // Serialized HybridCiphertext
    /// Unix timestamp in milliseconds for replay protection
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientFinished {
    pub certificate: Vec<u8>,
    pub client_kex_ct: Vec<u8>, // Serialized HybridCiphertext
    pub verify_data: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerFinished {
    pub verify_data: [u8; 32],
}

// Handshake State Machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    Idle,
    ClientHelloSent,
    ServerHelloReceived,
    ClientFinishedSent,
    Established,
    Failed,
}

/// Maximum allowed clock skew for handshake timestamps (5 minutes)
const MAX_CLOCK_SKEW_SECONDS: i64 = 300;

/// Maximum age of a handshake message before it's considered stale (30 seconds)
const MAX_HANDSHAKE_AGE_SECONDS: i64 = 30;

// HandshakeError
#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("Invalid protocol version: {0}")]
    InvalidVersion(u8),

    #[error("No compatible KEM algorithm")]
    NoCompatibleKem,

    #[error("Certificate verification failed")]
    CertVerificationFailed,

    #[error("Hostname verification failed: expected '{expected}', certificate does not match")]
    HostnameVerificationFailed { expected: String },

    #[error("Certificate expired")]
    CertificateExpired,

    #[error("Certificate not yet valid")]
    CertificateNotYetValid,

    #[error("Certificate not available")]
    CertNotAvailable,

    #[error("Handshake verification failed")]
    VerificationFailed,

    #[error("Handshake replay detected - timestamp too old or reused")]
    ReplayDetected,

    #[error("Invalid state transition: {from:?} -> {to:?}")]
    InvalidStateTransition {
        from: HandshakeState,
        to: HandshakeState,
    },

    #[error("Timeout during handshake")]
    Timeout,

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Key exchange error: {0}")]
    KeyExchangeError(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Certificate parsing error: {0}")]
    CertParseError(String),
}

// HandshakeContext
pub struct HandshakeContext {
    state: HandshakeState,
    key_manager: Arc<KeyManager>,
    ca_cert: Vec<u8>,
    our_cert: Option<Vec<u8>>,
    transcript: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    client_keypair: Option<crate::crypto::HybridKeyPair>,
    server_keypair: Option<crate::crypto::HybridKeyPair>,
    client_public_key: Option<HybridPublicKey>,
    server_public_key: Option<HybridPublicKey>,
    shared_secret_client: Option<Vec<u8>>,
    shared_secret_server: Option<Vec<u8>>,
    /// Expected hostname for peer certificate verification (optional)
    expected_peer_hostname: Option<String>,
    /// Timestamp of handshake initiation for replay protection
    handshake_timestamp_ms: u64,
    /// Peer's timestamp for replay protection validation
    peer_timestamp_ms: Option<u64>,
    /// Whether this context is for the client role (true) or server role (false)
    is_client_role: bool,
}

/// Helper function to get current timestamp in milliseconds
fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Verify that a certificate is within its validity period
fn verify_certificate_validity(cert_der: &[u8]) -> Result<(), HandshakeError> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| HandshakeError::CertParseError(format!("X509 parse failed: {}", e)))?;

    let validity = cert.validity();
    let now = Utc::now().timestamp();

    if validity.not_before.timestamp() > now {
        return Err(HandshakeError::CertificateNotYetValid);
    }
    if validity.not_after.timestamp() < now {
        return Err(HandshakeError::CertificateExpired);
    }

    Ok(())
}

/// Validate handshake timestamp for replay protection
fn validate_timestamp(peer_timestamp_ms: u64) -> Result<(), HandshakeError> {
    let now_ms = current_timestamp_ms() as i64;
    let peer_ms = peer_timestamp_ms as i64;

    // Check if timestamp is too far in the future (clock skew)
    if peer_ms > now_ms + (MAX_CLOCK_SKEW_SECONDS * 1000) {
        tracing::warn!(
            "Handshake timestamp too far in future: {} vs now {}",
            peer_ms,
            now_ms
        );
        return Err(HandshakeError::ReplayDetected);
    }

    // Check if timestamp is too old
    if peer_ms < now_ms - (MAX_HANDSHAKE_AGE_SECONDS * 1000) {
        tracing::warn!("Handshake timestamp too old: {} vs now {}", peer_ms, now_ms);
        return Err(HandshakeError::ReplayDetected);
    }

    Ok(())
}

impl HandshakeContext {
    // Client-side constructor
    pub fn new_client(
        key_manager: Arc<KeyManager>,
        client_cert: Vec<u8>,
        _client_key: Vec<u8>, // Key not needed for PQC handshake, kept for API compat
        ca_cert: Vec<u8>,
    ) -> Self {
        // Convert PEM to DER if needed
        let ca_cert_der = pem_to_der(&ca_cert).unwrap_or_else(|_| ca_cert.clone());
        let client_cert_der = pem_to_der(&client_cert).unwrap_or_else(|_| client_cert.clone());

        Self {
            state: HandshakeState::Idle,
            key_manager,
            ca_cert: ca_cert_der,
            our_cert: Some(client_cert_der),
            transcript: Vec::new(),
            client_random: [0u8; 32],
            server_random: [0u8; 32],
            client_keypair: None,
            server_keypair: None,
            client_public_key: None,
            server_public_key: None,
            shared_secret_client: None,
            shared_secret_server: None,
            expected_peer_hostname: None,
            handshake_timestamp_ms: 0,
            peer_timestamp_ms: None,
            is_client_role: true,
        }
    }

    /// Create a client handshake context with hostname verification enabled
    pub fn new_client_with_hostname(
        key_manager: Arc<KeyManager>,
        client_cert: Vec<u8>,
        client_key: Vec<u8>,
        ca_cert: Vec<u8>,
        expected_server_hostname: String,
    ) -> Self {
        let mut ctx = Self::new_client(key_manager, client_cert, client_key, ca_cert);
        ctx.expected_peer_hostname = Some(expected_server_hostname);
        ctx
    }

    // Server-side constructor
    pub fn new_server(
        key_manager: Arc<KeyManager>,
        server_cert: Vec<u8>,
        _server_key: Vec<u8>, // Key not needed for PQC handshake, kept for API compat
        ca_cert: Vec<u8>,
    ) -> Self {
        // Convert PEM to DER if needed
        let ca_cert_der = pem_to_der(&ca_cert).unwrap_or_else(|_| ca_cert.clone());
        let server_cert_der = pem_to_der(&server_cert).unwrap_or_else(|_| server_cert.clone());

        Self {
            state: HandshakeState::Idle,
            key_manager,
            ca_cert: ca_cert_der,
            our_cert: Some(server_cert_der),
            transcript: Vec::new(),
            client_random: [0u8; 32],
            server_random: [0u8; 32],
            client_keypair: None,
            server_keypair: None,
            client_public_key: None,
            server_public_key: None,
            shared_secret_client: None,
            shared_secret_server: None,
            expected_peer_hostname: None,
            handshake_timestamp_ms: 0,
            peer_timestamp_ms: None,
            is_client_role: false,
        }
    }

    /// Create a server handshake context with optional client hostname verification
    pub fn new_server_with_hostname(
        key_manager: Arc<KeyManager>,
        server_cert: Vec<u8>,
        server_key: Vec<u8>,
        ca_cert: Vec<u8>,
        expected_client_hostname: Option<String>,
    ) -> Self {
        let mut ctx = Self::new_server(key_manager, server_cert, server_key, ca_cert);
        ctx.expected_peer_hostname = expected_client_hostname;
        ctx
    }

    // Client-side: Create ClientHello
    pub fn create_client_hello(&mut self) -> Result<ClientHello, HandshakeError> {
        // Generate random
        let mut rng = rand::rng();
        rng.fill_bytes(&mut self.client_random);

        // Record handshake timestamp for replay protection
        self.handshake_timestamp_ms = current_timestamp_ms();

        // Generate ephemeral key pair and store it for later decapsulation
        let keypair = self.key_manager.generate_ephemeral_keypair();
        let public_key_bytes = keypair.public_key().as_bytes().to_vec();

        self.client_public_key = Some(keypair.public_key().clone());
        self.client_keypair = Some(keypair);

        let hello = ClientHello {
            version: crate::tunnel::PROTOCOL_VERSION,
            random: self.client_random,
            supported_kems: vec![KemAlgorithm::Hybrid],
            client_public_key: public_key_bytes,
            timestamp_ms: self.handshake_timestamp_ms,
        };

        // Add to transcript
        let hello_bytes = bincode::serialize(&hello)
            .map_err(|e| HandshakeError::SerializationError(e.to_string()))?;
        self.transcript.extend_from_slice(&hello_bytes);

        self.state = HandshakeState::ClientHelloSent;

        Ok(hello)
    }

    // Client-side: Process ServerHello
    pub async fn process_server_hello(
        &mut self,
        hello: ServerHello,
    ) -> Result<ClientFinished, HandshakeError> {
        if self.state != HandshakeState::ClientHelloSent {
            return Err(HandshakeError::InvalidStateTransition {
                from: self.state,
                to: HandshakeState::ServerHelloReceived,
            });
        }

        // Verify version
        if hello.version != crate::tunnel::PROTOCOL_VERSION {
            return Err(HandshakeError::InvalidVersion(hello.version));
        }

        // Validate timestamp for replay protection
        validate_timestamp(hello.timestamp_ms)?;
        self.peer_timestamp_ms = Some(hello.timestamp_ms);

        // Store server random
        self.server_random = hello.random;

        // Add to transcript
        let hello_bytes = bincode::serialize(&hello)
            .map_err(|e| HandshakeError::SerializationError(e.to_string()))?;
        self.transcript.extend_from_slice(&hello_bytes);

        // Verify server certificate chain
        verify_certificate_chain(&hello.certificate, &self.ca_cert)
            .map_err(|_| HandshakeError::CertVerificationFailed)?;

        // Verify certificate validity period (NotBefore/NotAfter)
        verify_certificate_validity(&hello.certificate)?;

        // Verify hostname if configured
        if let Some(ref expected_hostname) = self.expected_peer_hostname {
            verify_certificate_hostname(&hello.certificate, expected_hostname).map_err(|_| {
                HandshakeError::HostnameVerificationFailed {
                    expected: expected_hostname.clone(),
                }
            })?;
        }

        // Deserialize server public key from bytes
        let server_public_key = HybridPublicKey::from_bytes(&hello.server_public_key)
            .map_err(|e| HandshakeError::KeyExchangeError(e.to_string()))?;
        self.server_public_key = Some(server_public_key.clone());

        // Deserialize server's ciphertext from bytes
        let server_ct = HybridCiphertext::from_bytes(&hello.server_kex_ct)
            .map_err(|e| HandshakeError::KeyExchangeError(e.to_string()))?;

        // Use the keypair we generated in create_client_hello to decapsulate
        let client_keypair = self.client_keypair.as_ref().ok_or_else(|| {
            HandshakeError::KeyExchangeError("Client keypair not found".to_string())
        })?;
        let shared_from_server = self
            .key_manager
            .decapsulate_hybrid(client_keypair, &server_ct)
            .map_err(|e| HandshakeError::KeyExchangeError(e.to_string()))?;

        self.shared_secret_server = Some(shared_from_server.as_bytes().to_vec());

        // Encapsulate to server's public key
        let (shared_to_server, client_ct) = self
            .key_manager
            .encapsulate_hybrid(&server_public_key)
            .map_err(|e| HandshakeError::KeyExchangeError(e.to_string()))?;

        self.shared_secret_client = Some(shared_to_server.as_bytes().to_vec());

        let client_ct_bytes = client_ct.as_bytes().to_vec();

        // Calculate verify_data
        let verify_data = self.calculate_verify_data(true);

        let finished = ClientFinished {
            certificate: self
                .our_cert
                .clone()
                .ok_or(HandshakeError::CertNotAvailable)?,
            client_kex_ct: client_ct_bytes,
            verify_data,
        };

        // Add to transcript
        let finished_bytes = bincode::serialize(&finished)
            .map_err(|e| HandshakeError::SerializationError(e.to_string()))?;
        self.transcript.extend_from_slice(&finished_bytes);

        self.state = HandshakeState::ClientFinishedSent;

        Ok(finished)
    }

    // Client-side: Process ServerFinished
    pub async fn process_server_finished(
        &mut self,
        finished: ServerFinished,
    ) -> Result<(), HandshakeError> {
        if self.state != HandshakeState::ClientFinishedSent {
            return Err(HandshakeError::InvalidStateTransition {
                from: self.state,
                to: HandshakeState::Established,
            });
        }

        // IMPORTANT: Verify server's verify_data BEFORE adding server_finished to transcript
        // The server computed verify_data before adding server_finished, so we must too
        let expected_verify_data = self.calculate_verify_data(false);
        if finished.verify_data != expected_verify_data {
            self.state = HandshakeState::Failed;
            return Err(HandshakeError::VerificationFailed);
        }

        // Add to transcript AFTER verifying
        let finished_bytes = bincode::serialize(&finished)
            .map_err(|e| HandshakeError::SerializationError(e.to_string()))?;
        self.transcript.extend_from_slice(&finished_bytes);

        self.state = HandshakeState::Established;
        Ok(())
    }

    // Server-side: Process ClientHello
    pub async fn process_client_hello(
        &mut self,
        hello: ClientHello,
    ) -> Result<ServerHello, HandshakeError> {
        if self.state != HandshakeState::Idle {
            return Err(HandshakeError::InvalidStateTransition {
                from: self.state,
                to: HandshakeState::ServerHelloReceived,
            });
        }

        // Verify version
        if hello.version != crate::tunnel::PROTOCOL_VERSION {
            return Err(HandshakeError::InvalidVersion(hello.version));
        }

        // Validate timestamp for replay protection
        validate_timestamp(hello.timestamp_ms)?;
        self.peer_timestamp_ms = Some(hello.timestamp_ms);

        // Check for compatible KEM
        if !hello.supported_kems.contains(&KemAlgorithm::Hybrid) {
            return Err(HandshakeError::NoCompatibleKem);
        }

        // Store client random
        self.client_random = hello.random;

        // Record handshake timestamp for our response
        self.handshake_timestamp_ms = current_timestamp_ms();

        // Add to transcript
        let hello_bytes = bincode::serialize(&hello)
            .map_err(|e| HandshakeError::SerializationError(e.to_string()))?;
        self.transcript.extend_from_slice(&hello_bytes);

        // Deserialize client public key from bytes
        let client_public_key = HybridPublicKey::from_bytes(&hello.client_public_key)
            .map_err(|e| HandshakeError::KeyExchangeError(e.to_string()))?;
        self.client_public_key = Some(client_public_key.clone());

        // Generate server random
        let mut rng = rand::rng();
        rng.fill_bytes(&mut self.server_random);

        // Generate ephemeral keypair and store it for later decapsulation
        let server_keypair = self.key_manager.generate_ephemeral_keypair();
        let server_public_key_bytes = server_keypair.public_key().as_bytes().to_vec();

        self.server_public_key = Some(server_keypair.public_key().clone());
        self.server_keypair = Some(server_keypair);

        // Encapsulate to client's public key
        let (shared_to_client, server_ct) = self
            .key_manager
            .encapsulate_hybrid(&client_public_key)
            .map_err(|e| HandshakeError::KeyExchangeError(e.to_string()))?;

        self.shared_secret_client = Some(shared_to_client.as_bytes().to_vec());

        let server_ct_bytes = server_ct.as_bytes().to_vec();

        let server_hello = ServerHello {
            version: crate::tunnel::PROTOCOL_VERSION,
            random: self.server_random,
            selected_kem: KemAlgorithm::Hybrid,
            certificate: self
                .our_cert
                .clone()
                .ok_or(HandshakeError::CertNotAvailable)?,
            server_public_key: server_public_key_bytes,
            server_kex_ct: server_ct_bytes,
            timestamp_ms: self.handshake_timestamp_ms,
        };

        // Add to transcript
        let server_hello_bytes = bincode::serialize(&server_hello)
            .map_err(|e| HandshakeError::SerializationError(e.to_string()))?;
        self.transcript.extend_from_slice(&server_hello_bytes);

        Ok(server_hello)
    }

    // Server-side: Process ClientFinished
    pub async fn process_client_finished(
        &mut self,
        finished: ClientFinished,
    ) -> Result<ServerFinished, HandshakeError> {
        // Verify client certificate chain
        verify_certificate_chain(&finished.certificate, &self.ca_cert)
            .map_err(|_| HandshakeError::CertVerificationFailed)?;

        // Verify certificate validity period (NotBefore/NotAfter)
        verify_certificate_validity(&finished.certificate)?;

        // Verify hostname if configured (for mutual TLS scenarios)
        if let Some(ref expected_hostname) = self.expected_peer_hostname {
            verify_certificate_hostname(&finished.certificate, expected_hostname).map_err(
                |_| HandshakeError::HostnameVerificationFailed {
                    expected: expected_hostname.clone(),
                },
            )?;
        }

        // Deserialize client ciphertext from bytes
        let client_ct = HybridCiphertext::from_bytes(&finished.client_kex_ct)
            .map_err(|e| HandshakeError::KeyExchangeError(e.to_string()))?;

        // Use the keypair we generated in process_client_hello to decapsulate
        let server_keypair = self.server_keypair.as_ref().ok_or_else(|| {
            HandshakeError::KeyExchangeError("Server keypair not found".to_string())
        })?;
        let shared_from_client = self
            .key_manager
            .decapsulate_hybrid(server_keypair, &client_ct)
            .map_err(|e| HandshakeError::KeyExchangeError(e.to_string()))?;

        self.shared_secret_server = Some(shared_from_client.as_bytes().to_vec());

        // IMPORTANT: Verify client's verify_data BEFORE adding client_finished to transcript
        // The client computed verify_data before adding client_finished, so we must too
        let expected_verify_data = self.calculate_verify_data(true);
        if finished.verify_data != expected_verify_data {
            self.state = HandshakeState::Failed;
            return Err(HandshakeError::VerificationFailed);
        }

        // Add client_finished to transcript AFTER verifying
        let finished_bytes = bincode::serialize(&finished)
            .map_err(|e| HandshakeError::SerializationError(e.to_string()))?;
        self.transcript.extend_from_slice(&finished_bytes);

        // Calculate server's verify_data
        let verify_data = self.calculate_verify_data(false);

        let server_finished = ServerFinished { verify_data };

        // Add to transcript
        let server_finished_bytes = bincode::serialize(&server_finished)
            .map_err(|e| HandshakeError::SerializationError(e.to_string()))?;
        self.transcript.extend_from_slice(&server_finished_bytes);

        self.state = HandshakeState::Established;

        Ok(server_finished)
    }

    // Common methods
    pub fn state(&self) -> HandshakeState {
        self.state
    }

    pub fn is_established(&self) -> bool {
        self.state == HandshakeState::Established
    }

    pub fn get_session_key(&self) -> Option<Vec<u8>> {
        if !self.is_established() {
            return None;
        }

        // IMPORTANT: Use canonical order for shared secrets (client_to_server, server_to_client)
        // regardless of which side is computing, to ensure both sides derive the same key.
        //
        // The naming is from each side's local perspective:
        // - CLIENT's shared_secret_client = client encap to server pubkey (client -> server)
        // - CLIENT's shared_secret_server = client decap of server's ct (server -> client)
        // - SERVER's shared_secret_client = server encap to client pubkey (server -> client)
        // - SERVER's shared_secret_server = server decap of client's ct (client -> server)
        //
        // So the mapping to canonical direction is:
        // - client_to_server = CLIENT's ss_client = SERVER's ss_server
        // - server_to_client = CLIENT's ss_server = SERVER's ss_client
        let (client_to_server_ss, server_to_client_ss) = if self.is_client_role {
            (&self.shared_secret_client, &self.shared_secret_server)
        } else {
            (&self.shared_secret_server, &self.shared_secret_client)
        };

        // Combine both shared secrets in canonical order
        let mut combined = Vec::new();
        if let Some(ref ss) = client_to_server_ss {
            combined.extend_from_slice(ss);
        }
        if let Some(ref ss) = server_to_client_ss {
            combined.extend_from_slice(ss);
        }

        if combined.is_empty() {
            return None;
        }

        // Hash to derive final session key
        let mut hasher = Sha256::new();
        hasher.update(&combined);
        hasher.update(self.client_random);
        hasher.update(self.server_random);
        let result = hasher.finalize();

        Some(result.to_vec())
    }

    // Calculate verify_data for handshake verification
    // Includes timestamps for replay protection
    fn calculate_verify_data(&self, is_client: bool) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.transcript);
        hasher.update(if is_client { b"client" } else { b"server" });

        // Include timestamps in verify_data for replay protection
        // IMPORTANT: Use canonical order (client_ts, server_ts) regardless of which side
        // is computing, to ensure both sides compute the same hash.
        // For client role: handshake_timestamp_ms is client_ts, peer_timestamp_ms is server_ts
        // For server role: handshake_timestamp_ms is server_ts, peer_timestamp_ms is client_ts
        let (client_ts, server_ts) = if self.is_client_role {
            (
                self.handshake_timestamp_ms,
                self.peer_timestamp_ms.unwrap_or(0),
            )
        } else {
            (
                self.peer_timestamp_ms.unwrap_or(0),
                self.handshake_timestamp_ms,
            )
        };

        hasher.update(client_ts.to_le_bytes());
        hasher.update(server_ts.to_le_bytes());

        // IMPORTANT: Use canonical order for shared secrets (client_to_server, server_to_client)
        // regardless of which side is computing, to ensure both sides compute the same hash.
        //
        // The naming is from each side's local perspective:
        // - CLIENT's shared_secret_client = client encap to server pubkey (client -> server)
        // - CLIENT's shared_secret_server = client decap of server's ct (server -> client)
        // - SERVER's shared_secret_client = server encap to client pubkey (server -> client)
        // - SERVER's shared_secret_server = server decap of client's ct (client -> server)
        //
        // So the mapping to canonical direction is:
        // - client_to_server = CLIENT's ss_client = SERVER's ss_server
        // - server_to_client = CLIENT's ss_server = SERVER's ss_client
        let (client_to_server_ss, server_to_client_ss) = if self.is_client_role {
            (&self.shared_secret_client, &self.shared_secret_server)
        } else {
            (&self.shared_secret_server, &self.shared_secret_client)
        };

        if let Some(ref ss) = client_to_server_ss {
            hasher.update(ss);
        }
        if let Some(ref ss) = server_to_client_ss {
            hasher.update(ss);
        }

        let result = hasher.finalize();
        let mut verify_data = [0u8; 32];
        verify_data.copy_from_slice(&result);
        verify_data
    }

    /// Set the expected peer hostname for certificate verification
    pub fn set_expected_peer_hostname(&mut self, hostname: String) {
        self.expected_peer_hostname = Some(hostname);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kem_algorithm_conversion() {
        assert_eq!(KemAlgorithm::from_u8(0x01), Some(KemAlgorithm::Hybrid));
        assert_eq!(KemAlgorithm::from_u8(0x02), Some(KemAlgorithm::Mlkem768));
        assert_eq!(
            KemAlgorithm::from_u8(0x03),
            Some(KemAlgorithm::Mceliece460896)
        );
        assert_eq!(KemAlgorithm::from_u8(0xFF), None);
    }

    #[test]
    fn test_handshake_state() {
        let key_manager = Arc::new(KeyManager::new(3600, 1800));
        let mut ctx = HandshakeContext::new_client(key_manager, vec![], vec![], vec![]);

        assert_eq!(ctx.state(), HandshakeState::Idle);
        assert!(!ctx.is_established());

        ctx.create_client_hello().unwrap();
        assert_eq!(ctx.state(), HandshakeState::ClientHelloSent);
    }

    #[test]
    fn test_timestamp_validation() {
        // Valid timestamp (now)
        let now_ms = current_timestamp_ms();
        assert!(validate_timestamp(now_ms).is_ok());

        // Slightly old but valid timestamp
        let old_but_valid = now_ms - 10_000; // 10 seconds ago
        assert!(validate_timestamp(old_but_valid).is_ok());

        // Too old timestamp (should fail)
        let too_old = now_ms - 60_000; // 60 seconds ago
        assert!(validate_timestamp(too_old).is_err());

        // Future timestamp with acceptable skew
        let future_ok = now_ms + 60_000; // 1 minute in future
        assert!(validate_timestamp(future_ok).is_ok());

        // Future timestamp too far ahead (should fail)
        let too_future = now_ms + 600_000; // 10 minutes in future
        assert!(validate_timestamp(too_future).is_err());
    }

    #[test]
    fn test_client_hello_has_timestamp() {
        let key_manager = Arc::new(KeyManager::new(3600, 1800));
        let mut ctx = HandshakeContext::new_client(key_manager, vec![], vec![], vec![]);

        let before = current_timestamp_ms();
        let hello = ctx.create_client_hello().unwrap();
        let after = current_timestamp_ms();

        assert!(hello.timestamp_ms > 0);
        assert!(hello.timestamp_ms >= before);
        assert!(hello.timestamp_ms <= after);
    }
}
