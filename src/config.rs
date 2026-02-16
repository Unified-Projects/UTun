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
#[allow(dead_code)] // Config fields loaded from TOML
pub struct Config {
    pub source: Option<SourceConfig>,
    pub dest: Option<DestConfig>,
    pub auth: AuthConfig,
    pub crypto: CryptoConfig,
    pub logging: LoggingConfig,
    pub metrics: MetricsConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)] // Config fields loaded from TOML
pub struct SourceConfig {
    #[serde(default = "default_listen_ip")]
    pub listen_ip: String,

    #[serde(default = "default_source_port")]
    pub listen_port: u16,

    #[serde(default)]
    pub mode: SourceMode,

    pub dest_host: String,
    pub dest_tunnel_port: u16,

    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_ms: u64,

    #[serde(default = "default_keep_alive")]
    pub keep_alive_interval_ms: u64,

    // Heartbeat configuration
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_ms: u64,

    #[serde(default = "default_heartbeat_timeout")]
    pub heartbeat_timeout_ms: u64,

    #[serde(default = "default_max_missed_pongs")]
    pub max_missed_pongs: u8,

    // Reconnection configuration
    #[serde(default = "default_reconnection_enabled")]
    pub reconnection_enabled: bool,

    #[serde(default = "default_max_reconnect_attempts")]
    pub max_reconnect_attempts: u32, // 0 = infinite

    #[serde(default = "default_initial_reconnect_delay")]
    pub initial_reconnect_delay_ms: u64,

    #[serde(default = "default_max_reconnect_delay")]
    pub max_reconnect_delay_ms: u64,

    #[serde(default = "default_frame_buffer_size")]
    pub frame_buffer_size: usize,

    // Channel configuration
    #[serde(default = "default_connection_channel_size")]
    pub connection_channel_size: usize,

    // Circuit breaker configuration
    #[serde(default = "default_circuit_breaker_window_secs")]
    pub circuit_breaker_window_secs: u64,

    #[serde(default = "default_circuit_breaker_max_restarts")]
    pub circuit_breaker_max_restarts: usize,

    #[serde(default)]
    pub allowed_outbound: AllowedOutboundConfig,

    #[serde(default)]
    pub exposed_ports: Vec<ExposedPortConfig>,

    // Blue-green connection refresh
    #[serde(default = "default_connection_refresh_interval")]
    pub connection_refresh_interval_secs: u64, // 0 = disabled

    #[serde(default = "default_connection_drain_timeout")]
    pub connection_drain_timeout_secs: u64,

    // For backwards compatibility
    #[serde(skip)]
    pub client_cert_path: PathBuf,
    #[serde(skip)]
    pub client_key_path: PathBuf,
    #[serde(skip)]
    pub ca_cert_path: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)] // Config fields loaded from TOML
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

    // Channel configuration
    #[serde(default = "default_connection_channel_size")]
    pub connection_channel_size: usize,

    #[serde(default)]
    pub connection_filter: ConnectionFilterConfig,

    /// Interval in seconds between stale connection cleanup sweeps
    #[serde(default = "default_stale_cleanup_interval")]
    pub stale_cleanup_interval_secs: u64,

    // For backwards compatibility
    #[serde(skip)]
    pub server_cert_path: PathBuf,
    #[serde(skip)]
    pub server_key_path: PathBuf,
    #[serde(skip)]
    pub ca_cert_path: PathBuf,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Config fields loaded from TOML
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
#[allow(dead_code)] // Config fields loaded from TOML
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
        self.max_handshake_size.unwrap_or(match self.kem_mode {
            // ML-KEM-768 has ~1.5KB keys, 64KB is plenty
            KemMode::Mlkem768 => 64 * 1024,
            // Classic McEliece has ~500KB public keys, need 2MB for safety
            KemMode::Mceliece460896 => 2 * 1024 * 1024,
            // Hybrid uses both, so needs the larger buffer
            KemMode::Hybrid => 2 * 1024 * 1024,
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

impl Protocol {
    /// Convert config Protocol to tunnel Protocol
    /// For Both, defaults to Tcp (caller should handle creating multiple listeners if needed)
    pub fn to_tunnel_protocol(self) -> crate::tunnel::Protocol {
        match self {
            Protocol::Tcp | Protocol::Both => crate::tunnel::Protocol::Tcp,
            Protocol::Udp => crate::tunnel::Protocol::Udp,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum SourceMode {
    #[default]
    Transparent,
    Protocol,
    Hybrid,
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
#[allow(dead_code)] // Config fields loaded from TOML
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
    #[allow(dead_code)] // Public API method
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
#[allow(dead_code)] // Config fields loaded from TOML
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

// Heartbeat defaults
fn default_heartbeat_interval() -> u64 {
    15000
}
fn default_heartbeat_timeout() -> u64 {
    5000
}
fn default_max_missed_pongs() -> u8 {
    3
}

// Reconnection defaults
fn default_reconnection_enabled() -> bool {
    true
}
fn default_max_reconnect_attempts() -> u32 {
    0
} // 0 = infinite
fn default_initial_reconnect_delay() -> u64 {
    1000
}
fn default_max_reconnect_delay() -> u64 {
    60000
}
fn default_frame_buffer_size() -> usize {
    1000
}
fn default_connection_channel_size() -> usize {
    1024
}
fn default_circuit_breaker_window_secs() -> u64 {
    60
}
fn default_circuit_breaker_max_restarts() -> usize {
    5
}
fn default_stale_cleanup_interval() -> u64 {
    15
}
fn default_connection_refresh_interval() -> u64 {
    3600
} // 1 hour
fn default_connection_drain_timeout() -> u64 {
    60
}

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

        // Validate exposed_ports
        let mut seen_ports = std::collections::HashSet::new();
        for exposed in &source.exposed_ports {
            if !seen_ports.insert(exposed.port) {
                return Err(ConfigError::ValidationError(format!(
                    "Duplicate port {} in exposed_ports",
                    exposed.port
                )));
            }
        }

        // Validate mode requirements
        match source.mode {
            SourceMode::Transparent | SourceMode::Hybrid => {
                if source.exposed_ports.is_empty() {
                    return Err(ConfigError::ValidationError(
                        "Transparent/Hybrid mode requires at least one exposed_port".to_string(),
                    ));
                }
            }
            SourceMode::Protocol => {
                if source.exposed_ports.is_empty() {
                    tracing::warn!(
                        "Protocol mode without exposed_ports - no port restrictions will be enforced"
                    );
                }
            }
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
    #[allow(dead_code)] // Public API method
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
    #[allow(dead_code)] // Public API method
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
