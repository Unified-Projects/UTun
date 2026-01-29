use ipnetwork::IpNetwork;
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
#[allow(clippy::enum_variant_names)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    ReadError(#[from] std::io::Error),

    #[error("Failed to parse config: {0}")]
    ParseError(#[from] toml::de::Error),

    #[error("Validation error: {0}")]
    ValidationError(String),
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub source: Option<SourceConfig>,
    pub dest: Option<DestConfig>,
    pub auth: AuthConfig,
    pub crypto: CryptoConfig,
    pub logging: LoggingConfig,
    pub metrics: MetricsConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SourceConfig {
    #[serde(default = "default_listen_ip")]
    pub listen_ip: String,

    #[serde(default = "default_source_port")]
    pub listen_port: u16,

    pub dest_host: String,
    pub dest_tunnel_port: u16,

    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_ms: u64,

    #[serde(default = "default_keep_alive")]
    pub keep_alive_interval_ms: u64,

    #[serde(default)]
    pub allowed_outbound: AllowedOutboundConfig,

    #[serde(default)]
    pub exposed_ports: Vec<ExposedPortConfig>,

    // For backwards compatibility
    #[serde(skip)]
    pub client_cert_path: PathBuf,
    #[serde(skip)]
    pub client_key_path: PathBuf,
    #[serde(skip)]
    pub ca_cert_path: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DestConfig {
    #[serde(default = "default_listen_ip")]
    pub listen_ip: String,

    pub tunnel_port: u16,

    pub exposed_services: Vec<ServiceConfig>,

    #[serde(default = "default_max_per_service")]
    pub max_connections_per_service: usize,

    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_ms: u64,

    #[serde(default = "default_target_timeout")]
    pub target_connect_timeout_ms: u64,

    #[serde(default)]
    pub connection_filter: ConnectionFilterConfig,

    // For backwards compatibility
    #[serde(skip)]
    pub server_cert_path: PathBuf,
    #[serde(skip)]
    pub server_key_path: PathBuf,
    #[serde(skip)]
    pub ca_cert_path: PathBuf,
}

#[derive(Debug, Deserialize)]
pub struct AuthConfig {
    #[serde(default = "default_mtls")]
    pub use_mtls: bool,

    pub ca_cert_path: PathBuf,

    pub client_cert_path: Option<PathBuf>,
    pub client_key_path: Option<PathBuf>,

    pub server_cert_path: Option<PathBuf>,
    pub server_key_path: Option<PathBuf>,

    #[serde(default = "default_verify_client")]
    pub verify_client_cert: bool,
}

#[derive(Debug, Deserialize)]
pub struct CryptoConfig {
    #[serde(default = "default_kem_mode")]
    pub kem_mode: KemMode,

    #[serde(default = "default_rotation_interval")]
    pub key_rotation_interval_seconds: u64,

    #[serde(default = "default_rehandshake")]
    pub rehandshake_before_expiry_seconds: u64,

    /// Maximum handshake message size in bytes.
    /// Default depends on kem_mode: 64KB for mlkem768, 2MB for hybrid/mceliece.
    /// Classic McEliece public keys are ~500KB, so hybrid mode needs larger buffers.
    #[serde(default)]
    pub max_handshake_size: Option<u32>,
}

impl CryptoConfig {
    /// Get the effective max handshake size based on KEM mode
    pub fn effective_max_handshake_size(&self) -> u32 {
        self.max_handshake_size.unwrap_or_else(|| {
            match self.kem_mode {
                // ML-KEM-768 has ~1.5KB keys, 64KB is plenty
                KemMode::Mlkem768 => 64 * 1024,
                // Classic McEliece has ~500KB public keys, need 2MB for safety
                KemMode::Mceliece460896 => 2 * 1024 * 1024,
                // Hybrid uses both, so needs the larger buffer
                KemMode::Hybrid => 2 * 1024 * 1024,
            }
        })
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KemMode {
    Hybrid,
    Mlkem768,
    Mceliece460896,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Both,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AllowedOutboundConfig {
    #[serde(default = "default_allow_all")]
    pub allowed_ips: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExposedPortConfig {
    pub port: u16,
    #[serde(default = "default_protocol")]
    pub protocol: Protocol,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServiceConfig {
    pub name: String,
    pub port: u16,
    pub target_ip: String,
    pub target_port: u16,
    #[serde(default = "default_protocol_string")]
    pub protocol: String,
    pub description: Option<String>,
}

impl ServiceConfig {
    pub fn get_protocol(&self) -> crate::tunnel::Protocol {
        match self.protocol.to_lowercase().as_str() {
            "udp" => crate::tunnel::Protocol::Udp,
            _ => crate::tunnel::Protocol::Tcp,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ConnectionFilterConfig {
    #[serde(default = "default_allow_all")]
    pub allowed_source_ips: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,

    #[serde(default = "default_log_format")]
    pub format: String,

    #[serde(default = "default_timestamp")]
    pub include_timestamp: bool,
}

#[derive(Debug, Deserialize)]
pub struct MetricsConfig {
    #[serde(default = "default_metrics_enabled")]
    pub enabled: bool,

    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,

    #[serde(default = "default_metrics_bind")]
    pub metrics_bind_ip: String,
}

// Default value functions
fn default_listen_ip() -> String {
    "0.0.0.0".to_string()
}
fn default_source_port() -> u16 {
    8443
}
fn default_max_connections() -> usize {
    10000
}
fn default_connection_timeout() -> u64 {
    30000
}
fn default_keep_alive() -> u64 {
    30000
}
fn default_max_per_service() -> usize {
    100
}
fn default_target_timeout() -> u64 {
    5000
}
fn default_mtls() -> bool {
    true
}
fn default_verify_client() -> bool {
    true
}
fn default_kem_mode() -> KemMode {
    KemMode::Hybrid
}
fn default_rotation_interval() -> u64 {
    3600
}
fn default_rehandshake() -> u64 {
    300
}
fn default_allow_all() -> Vec<String> {
    vec![]
} // Empty = deny all by default (secure default)
fn default_protocol() -> Protocol {
    Protocol::Tcp
}
fn default_protocol_string() -> String {
    "tcp".to_string()
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_log_format() -> String {
    "json".to_string()
}
fn default_timestamp() -> bool {
    true
}
fn default_metrics_enabled() -> bool {
    true
}
fn default_metrics_port() -> u16 {
    9090
}
fn default_metrics_bind() -> String {
    "127.0.0.1".to_string()
} // Bind to localhost only for security

/// Load configuration from file
pub fn load_config(path: &Path) -> Result<Config, ConfigError> {
    let content = fs::read_to_string(path)?;
    let mut config: Config = toml::from_str(&content)?;

    // Populate backwards compatibility fields
    if let Some(ref mut source) = config.source {
        source.client_cert_path = config.auth.client_cert_path.clone().unwrap_or_default();
        source.client_key_path = config.auth.client_key_path.clone().unwrap_or_default();
        source.ca_cert_path = config.auth.ca_cert_path.clone();
    }

    if let Some(ref mut dest) = config.dest {
        dest.server_cert_path = config.auth.server_cert_path.clone().unwrap_or_default();
        dest.server_key_path = config.auth.server_key_path.clone().unwrap_or_default();
        dest.ca_cert_path = config.auth.ca_cert_path.clone();
    }

    validate_config(&config)?;
    Ok(config)
}

/// Validate configuration
fn validate_config(config: &Config) -> Result<(), ConfigError> {
    // Validate IP ranges
    if let Some(ref source) = config.source {
        for ip in &source.allowed_outbound.allowed_ips {
            ip.parse::<IpNetwork>().map_err(|e| {
                ConfigError::ValidationError(format!("Invalid IP range '{}': {}", ip, e))
            })?;
        }
    }

    if let Some(ref dest) = config.dest {
        for ip in &dest.connection_filter.allowed_source_ips {
            ip.parse::<IpNetwork>().map_err(|e| {
                ConfigError::ValidationError(format!("Invalid IP range '{}': {}", ip, e))
            })?;
        }

        // Validate service target IPs
        for service in &dest.exposed_services {
            service.target_ip.parse::<std::net::IpAddr>().map_err(|e| {
                ConfigError::ValidationError(format!(
                    "Invalid target IP '{}' for service '{}': {}",
                    service.target_ip, service.name, e
                ))
            })?;
        }
    }

    // Validate paths exist
    if !config.auth.ca_cert_path.exists() {
        return Err(ConfigError::ValidationError(format!(
            "CA certificate not found: {:?}",
            config.auth.ca_cert_path
        )));
    }

    Ok(())
}

impl SourceConfig {
    /// Check if IP is allowed for outbound connections
    pub fn is_ip_allowed(&self, ip: std::net::IpAddr) -> bool {
        for cidr in &self.allowed_outbound.allowed_ips {
            if let Ok(network) = cidr.parse::<IpNetwork>() {
                if network.contains(ip) {
                    return true;
                }
            }
        }
        false
    }
}

impl DestConfig {
    /// Check if source IP is allowed
    pub fn is_source_allowed(&self, ip: std::net::IpAddr) -> bool {
        for cidr in &self.connection_filter.allowed_source_ips {
            if let Ok(network) = cidr.parse::<IpNetwork>() {
                if network.contains(ip) {
                    return true;
                }
            }
        }
        false
    }
}
