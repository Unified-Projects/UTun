use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::{mpsc, watch, Mutex, RwLock};
use tokio::time::{timeout, Duration};

// Maximum frame size to prevent memory exhaustion (1MB)
const MAX_FRAME_SIZE: u32 = 1024 * 1024;

// Handshake timeout per message (increased for large McEliece keys)
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

// Frame read timeout (must exceed heartbeat interval to allow pongs during idle periods)
const FRAME_READ_TIMEOUT: Duration = Duration::from_secs(60);
use super::{
    ConnectionError, ConnectionManager, Frame, FrameCodec, FrameError, FrameType, HandshakeContext,
    HandshakeError, Protocol,
};
use crate::config::{CryptoConfig, SourceConfig};
use crate::crypto::{DerivedKeyMaterial, KeyManager, SessionCrypto};
use crate::health::{HealthMonitor, HealthStatus};

#[derive(Debug, Error)]
pub enum SourceError {
    #[error("Handshake error: {0}")]
    HandshakeError(#[from] HandshakeError),

    #[error("Frame error: {0}")]
    FrameError(#[from] FrameError),

    #[error("Connection error: {0}")]
    ConnectionError(#[from] ConnectionError),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Not connected to destination")]
    NotConnected,

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Frame size {size} exceeds maximum {max}")]
    FrameTooLarge { size: u32, max: u32 },

    #[error("Read timeout - connection may be stalled")]
    Timeout,
}

pub struct SourceMetrics {
    pub connections_accepted: std::sync::atomic::AtomicU64,
    pub bytes_sent: std::sync::atomic::AtomicU64,
    pub bytes_received: std::sync::atomic::AtomicU64,
}

impl Default for SourceMetrics {
    fn default() -> Self {
        Self {
            connections_accepted: std::sync::atomic::AtomicU64::new(0),
            bytes_sent: std::sync::atomic::AtomicU64::new(0),
            bytes_received: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl SourceMetrics {
    pub fn new() -> Self {
        Self::default()
    }
}

pub struct PortListener {
    pub port: u16,
    pub protocol: Protocol,
    pub listener: TcpListener,
}

#[derive(Default)]
#[allow(dead_code)] // Used by multi-port listener mode
pub struct ListenerManager {
    listeners: Vec<PortListener>,
}

impl ListenerManager {
    #[allow(dead_code)] // Public API method
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(dead_code)] // Public API method
    pub async fn add_listener(
        &mut self,
        listen_ip: &str,
        port: u16,
        protocol: Protocol,
    ) -> Result<(), SourceError> {
        let addr = format!("{}:{}", listen_ip, port);
        let (listener, actual_port) = bind_with_reuse(&addr)
            .await
            .map_err(|e| SourceError::ConfigError(format!("Failed to bind to {}: {}", addr, e)))?;
        tracing::info!(
            "Listening on {}:{} (protocol: {:?})",
            listen_ip,
            actual_port,
            protocol
        );

        self.listeners.push(PortListener {
            port: actual_port,
            protocol,
            listener,
        });

        Ok(())
    }

    #[allow(dead_code)] // Public API method
    pub fn listeners(&self) -> &[PortListener] {
        &self.listeners
    }
}

struct HeartbeatState {
    last_activity: Arc<RwLock<Instant>>,
    last_ping_seq: Arc<RwLock<Option<u32>>>,
    last_ping_time: Arc<RwLock<Option<Instant>>>,
    consecutive_misses: Arc<RwLock<u8>>,
    rtt_avg_us: Arc<RwLock<Option<u64>>>,
    pong_received: Arc<AtomicBool>,
}

impl HeartbeatState {
    fn new() -> Self {
        Self {
            last_activity: Arc::new(RwLock::new(Instant::now())),
            last_ping_seq: Arc::new(RwLock::new(None)),
            last_ping_time: Arc::new(RwLock::new(None)),
            consecutive_misses: Arc::new(RwLock::new(0)),
            rtt_avg_us: Arc::new(RwLock::new(None)),
            pong_received: Arc::new(AtomicBool::new(false)),
        }
    }

    async fn reset(&self) {
        *self.last_activity.write().await = Instant::now();
        *self.last_ping_seq.write().await = None;
        *self.last_ping_time.write().await = None;
        *self.consecutive_misses.write().await = 0;
        *self.rtt_avg_us.write().await = None;
        self.pong_received.store(false, Ordering::SeqCst);
    }

    async fn record_activity(&self) {
        *self.last_activity.write().await = Instant::now();
    }

    async fn should_send_ping(&self, interval_ms: u64) -> bool {
        self.last_activity.read().await.elapsed() >= Duration::from_millis(interval_ms)
    }

    async fn record_ping_sent(&self, seq: u32) {
        *self.last_ping_seq.write().await = Some(seq);
        *self.last_ping_time.write().await = Some(Instant::now());
        self.record_activity().await;
    }

    async fn record_pong_received(&self, seq: u32) -> Option<Duration> {
        if *self.last_ping_seq.read().await == Some(seq) {
            *self.consecutive_misses.write().await = 0;

            if let Some(sent_time) = *self.last_ping_time.read().await {
                let rtt = sent_time.elapsed();
                let rtt_us = rtt.as_micros() as u64;

                // EMA: 0.2 * current + 0.8 * old
                let mut avg = self.rtt_avg_us.write().await;
                *avg = Some(match *avg {
                    Some(old) => (rtt_us * 2 + old * 8) / 10,
                    None => rtt_us,
                });

                self.record_activity().await;
                return Some(rtt);
            }
        }
        None
    }

    async fn record_ping_timeout(&self) -> u8 {
        let mut misses = self.consecutive_misses.write().await;
        *misses = misses.saturating_add(1);
        *misses
    }

    #[allow(dead_code)]
    async fn get_rtt_avg_us(&self) -> Option<u64> {
        *self.rtt_avg_us.read().await
    }
}

pub struct ReconnectionManager {
    attempt: AtomicU32,
    last_delay_ms: Arc<RwLock<u64>>,
    config: SourceConfig,
    health_monitor: Arc<HealthMonitor>,
}

impl ReconnectionManager {
    pub fn new(config: SourceConfig, health_monitor: Arc<HealthMonitor>) -> Self {
        Self {
            attempt: AtomicU32::new(0),
            last_delay_ms: Arc::new(RwLock::new(0)),
            config,
            health_monitor,
        }
    }

    async fn calculate_backoff(&self) -> Duration {
        let attempt = self.attempt.load(Ordering::SeqCst);

        if attempt == 0 {
            return Duration::from_millis(0);
        }

        if attempt == 1 {
            return Duration::from_millis(self.config.initial_reconnect_delay_ms);
        }

        let last = *self.last_delay_ms.read().await;
        let base = self.config.initial_reconnect_delay_ms;
        let max = self.config.max_reconnect_delay_ms;

        // Decorrelated jitter
        let upper = std::cmp::min(max, last * 3);
        let delay = if upper > base {
            use rand::Rng;
            let mut rng = rand::rng();
            rng.random_range(base..=upper)
        } else {
            base
        };

        *self.last_delay_ms.write().await = delay;
        Duration::from_millis(delay)
    }

    pub async fn reconnect<F, Fut>(&self, connect_fn: F) -> Result<(), SourceError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<(), SourceError>>,
    {
        let max_attempts = self.config.max_reconnect_attempts;

        loop {
            let attempt = self.attempt.fetch_add(1, Ordering::SeqCst);

            if max_attempts > 0 && attempt >= max_attempts {
                tracing::error!("Max reconnection attempts ({}) exceeded", max_attempts);
                self.health_monitor
                    .set_status(HealthStatus::Unhealthy)
                    .await;
                return Err(SourceError::ConfigError(
                    "Max reconnection attempts exceeded".to_string(),
                ));
            }

            let delay = self.calculate_backoff().await;
            if !delay.is_zero() {
                tracing::info!("Reconnection attempt {} after {:?}", attempt + 1, delay);
                self.health_monitor
                    .set_status(HealthStatus::Connecting)
                    .await;
                tokio::time::sleep(delay).await;
            }

            match connect_fn().await {
                Ok(_) => {
                    tracing::info!("Reconnection successful after {} attempts", attempt + 1);
                    self.reset();
                    self.health_monitor.set_status(HealthStatus::Healthy).await;
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!("Reconnection attempt {} failed: {}", attempt + 1, e);
                    self.health_monitor.record_error().await;

                    // Extended backoff after 10 failures
                    if attempt >= 10 {
                        tracing::warn!("Circuit breaker activated, using extended backoff");
                        tokio::time::sleep(Duration::from_secs(30)).await;
                    }
                }
            }
        }
    }

    pub fn reset(&self) {
        self.attempt.store(0, Ordering::SeqCst);
    }

    #[allow(dead_code)] // Public API method
    pub fn get_attempt_count(&self) -> u32 {
        self.attempt.load(Ordering::SeqCst)
    }
}

#[derive(Debug)]
enum TunnelRecoverySignal {
    HeartbeatDead { session_id: u64 },
    DemuxExited { session_id: u64 },
    WriterExited { session_id: u64 },
}

impl TunnelRecoverySignal {
    fn session_id(&self) -> u64 {
        match self {
            TunnelRecoverySignal::HeartbeatDead { session_id } => *session_id,
            TunnelRecoverySignal::DemuxExited { session_id } => *session_id,
            TunnelRecoverySignal::WriterExited { session_id } => *session_id,
        }
    }
}

struct TunnelSession {
    session_id: u64,
    frame_codec: Arc<FrameCodec>,
    write_queue_tx: mpsc::UnboundedSender<Frame>,
    connection_registry: Arc<RwLock<HashMap<u32, mpsc::Sender<Frame>>>>,
    heartbeat_state: Arc<HeartbeatState>,
    session_shutdown: watch::Sender<bool>,
}

impl std::fmt::Debug for TunnelSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelSession")
            .field("session_id", &self.session_id)
            .field("registry_len", &"<async>")
            .finish()
    }
}

/// Bind a TcpListener with SO_REUSEADDR/SO_REUSEPORT, falling back to +5 ports if busy.
async fn bind_with_reuse(addr: &str) -> std::io::Result<(TcpListener, u16)> {
    let mut socket_addr: SocketAddr = addr
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    let original_port = socket_addr.port();
    let mut last_error = None;

    for attempt in 0..6 {
        let current_port = original_port + attempt;

        match socket_addr {
            SocketAddr::V4(ref mut addr) => addr.set_port(current_port),
            SocketAddr::V6(ref mut addr) => addr.set_port(current_port),
        }

        if attempt > 0 {
            tracing::warn!(
                "Port {} in use, trying fallback port {}",
                original_port,
                current_port
            );
        }

        let socket = match socket_addr {
            SocketAddr::V4(_) => TcpSocket::new_v4()?,
            SocketAddr::V6(_) => TcpSocket::new_v6()?,
        };

        socket.set_reuseaddr(true)?;
        #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
        socket.set_reuseport(true)?;

        match socket.bind(socket_addr) {
            Ok(_) => {
                if attempt > 0 {
                    tracing::warn!(
                        "Bound to fallback port {} instead of configured {}",
                        current_port,
                        original_port
                    );
                }
                let listener = socket.listen(1024)?;
                return Ok((listener, current_port));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                last_error = Some(e);
                continue;
            }
            Err(e) => return Err(e),
        }
    }

    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "All fallback ports exhausted",
        )
    }))
}

pub struct SourceContainer {
    config: SourceConfig,
    key_manager: Arc<KeyManager>,
    connection_manager: Arc<ConnectionManager>,
    shutdown: watch::Sender<bool>,
    metrics: Arc<SourceMetrics>,
    health_monitor: Arc<HealthMonitor>,
    max_handshake_size: u32,
    ping_sequence: Arc<AtomicU32>,
    tunnel_metrics: Arc<super::resilience::TunnelMetrics>,
    circuit_breaker: Arc<super::resilience::CircuitBreaker>,
    active_session: Arc<RwLock<Option<Arc<TunnelSession>>>>,
    retiring_sessions: Arc<Mutex<Vec<Arc<TunnelSession>>>>,
    recovery_tx: mpsc::UnboundedSender<TunnelRecoverySignal>,
    recovery_rx: Arc<Mutex<Option<mpsc::UnboundedReceiver<TunnelRecoverySignal>>>>,
    session_counter: Arc<AtomicU64>,
}

impl SourceContainer {
    pub async fn new(
        config: SourceConfig,
        crypto_config: CryptoConfig,
    ) -> Result<Self, SourceError> {
        let key_manager = Arc::new(KeyManager::new(3600, 300)); // 1 hour rotation, 5 min window
        let connection_manager = Arc::new(ConnectionManager::new_with_channel_size(
            config.max_connections,
            config.connection_timeout_ms,
            config.connection_channel_size,
        ));

        let (shutdown_tx, _) = watch::channel(false);

        let health_monitor = Arc::new(HealthMonitor::new());
        health_monitor.set_status(HealthStatus::Starting).await;

        let max_handshake_size = crypto_config.effective_max_handshake_size();

        let tunnel_metrics = Arc::new(super::resilience::TunnelMetrics::new());
        let circuit_breaker = Arc::new(super::resilience::CircuitBreaker::new(
            Duration::from_secs(config.circuit_breaker_window_secs),
            config.circuit_breaker_max_restarts,
        ));

        let (recovery_tx, recovery_rx) = mpsc::unbounded_channel();

        Ok(Self {
            config,
            key_manager,
            connection_manager,
            shutdown: shutdown_tx,
            metrics: Arc::new(SourceMetrics::new()),
            health_monitor,
            max_handshake_size,
            ping_sequence: Arc::new(AtomicU32::new(0)),
            tunnel_metrics,
            circuit_breaker,
            active_session: Arc::new(RwLock::new(None)),
            retiring_sessions: Arc::new(Mutex::new(Vec::new())),
            recovery_tx,
            recovery_rx: Arc::new(Mutex::new(Some(recovery_rx))),
            session_counter: Arc::new(AtomicU64::new(1)),
        })
    }

    pub async fn start(&self) -> Result<(), SourceError> {
        if self.config.reconnection_enabled {
            let reconnection_manager =
                ReconnectionManager::new(self.config.clone(), self.health_monitor.clone());

            reconnection_manager
                .reconnect(|| async {
                    let session = self.establish_session().await?;
                    let mut active = self.active_session.write().await;
                    *active = Some(session);
                    Ok(())
                })
                .await
        } else {
            let session = self.establish_session().await?;
            let mut active = self.active_session.write().await;
            *active = Some(session);
            Ok(())
        }
    }

    pub async fn setup_listeners(&self) -> Result<Vec<PortListener>, SourceError> {
        use crate::config::SourceMode;

        let mut listeners = Vec::new();

        match self.config.mode {
            SourceMode::Transparent | SourceMode::Hybrid => {
                // Create a listener for each exposed port
                if self.config.exposed_ports.is_empty() {
                    tracing::warn!(
                        "No exposed_ports configured, falling back to single listener on port {}",
                        self.config.listen_port
                    );
                    let addr = format!("{}:{}", self.config.listen_ip, self.config.listen_port);
                    let (listener, actual_port) = bind_with_reuse(&addr).await.map_err(|e| {
                        SourceError::ConfigError(format!("Failed to bind to {}: {}", addr, e))
                    })?;
                    tracing::info!(
                        "Listening on {}:{} (protocol: {:?})",
                        self.config.listen_ip,
                        actual_port,
                        Protocol::Tcp
                    );

                    listeners.push(PortListener {
                        port: actual_port,
                        protocol: Protocol::Tcp,
                        listener,
                    });
                } else {
                    for exposed in &self.config.exposed_ports {
                        let addr = format!("{}:{}", self.config.listen_ip, exposed.port);
                        let (listener, actual_port) =
                            bind_with_reuse(&addr).await.map_err(|e| {
                                SourceError::ConfigError(format!(
                                    "Failed to bind to {}: {}",
                                    addr, e
                                ))
                            })?;
                        let protocol = exposed.protocol.to_tunnel_protocol();
                        tracing::info!(
                            "Listening on {}:{} (protocol: {:?})",
                            self.config.listen_ip,
                            actual_port,
                            protocol
                        );

                        listeners.push(PortListener {
                            port: actual_port,
                            protocol,
                            listener,
                        });
                    }
                }
            }
            SourceMode::Protocol => {
                // Single entry point on listen_port
                let addr = format!("{}:{}", self.config.listen_ip, self.config.listen_port);
                let (listener, actual_port) = bind_with_reuse(&addr).await.map_err(|e| {
                    SourceError::ConfigError(format!("Failed to bind to {}: {}", addr, e))
                })?;
                tracing::info!(
                    "Listening on {}:{} (protocol: {:?})",
                    self.config.listen_ip,
                    actual_port,
                    Protocol::Tcp
                );

                listeners.push(PortListener {
                    port: actual_port,
                    protocol: Protocol::Tcp,
                    listener,
                });
            }
        }

        Ok(listeners)
    }

    pub async fn stop(&self) {
        tracing::info!("Stopping source container");
        let _ = self.shutdown.send(true);

        if let Some(session) = self.active_session.write().await.take() {
            self.teardown_session(&session).await;
        }

        {
            let mut retiring = self.retiring_sessions.lock().await;
            for session in retiring.drain(..) {
                self.teardown_session(&session).await;
            }
        }

        self.connection_manager.close_all().await;
    }

    #[allow(dead_code)] // Public API method
    pub fn is_running(&self) -> bool {
        !*self.shutdown.borrow()
    }

    pub fn health_monitor(&self) -> Arc<HealthMonitor> {
        self.health_monitor.clone()
    }

    async fn establish_session(&self) -> Result<Arc<TunnelSession>, SourceError> {
        let stream = self.connect_tcp().await?;
        let (codec, read_half, write_half) = self.perform_handshake_on(stream).await?;
        let session = self.create_session(codec, read_half, write_half);
        Ok(session)
    }

    async fn connect_tcp(&self) -> Result<TcpStream, SourceError> {
        let dest_addr = format!("{}:{}", self.config.dest_host, self.config.dest_tunnel_port);
        self.health_monitor
            .set_status(HealthStatus::Connecting)
            .await;
        let stream = TcpStream::connect(&dest_addr).await?;
        Ok(stream)
    }

    async fn perform_handshake_on(
        &self,
        mut stream: TcpStream,
    ) -> Result<(Arc<FrameCodec>, OwnedReadHalf, OwnedWriteHalf), SourceError> {
        use crate::crypto::file_access::validate_file_access;
        validate_file_access(
            &self.config.client_cert_path,
            &self.config.client_key_path,
            "client",
        )
        .map_err(|e| SourceError::ConfigError(e.to_string()))?;

        let client_cert = std::fs::read(&self.config.client_cert_path)
            .map_err(|e| SourceError::ConfigError(format!("Failed to read client cert: {}", e)))?;
        let client_key = std::fs::read(&self.config.client_key_path)
            .map_err(|e| SourceError::ConfigError(format!("Failed to read client key: {}", e)))?;
        let ca_cert = std::fs::read(&self.config.ca_cert_path)
            .map_err(|e| SourceError::ConfigError(format!("Failed to read CA cert: {}", e)))?;

        let mut handshake_ctx = HandshakeContext::new_client(
            self.key_manager.clone(),
            client_cert,
            client_key,
            ca_cert,
        );

        let client_hello = handshake_ctx
            .create_client_hello()
            .map_err(SourceError::HandshakeError)?;
        let hello_bytes = bincode::serialize(&client_hello)
            .map_err(|e| SourceError::ConfigError(format!("Serialization failed: {}", e)))?;

        stream.write_u32(hello_bytes.len() as u32).await?;
        stream.write_all(&hello_bytes).await?;
        stream.flush().await?;

        // ServerHello
        let len = match timeout(HANDSHAKE_TIMEOUT, stream.read_u32()).await {
            Ok(Ok(l)) => l,
            Ok(Err(e)) => return Err(SourceError::IoError(e)),
            Err(_) => return Err(SourceError::Timeout),
        };

        if len > self.max_handshake_size {
            return Err(SourceError::FrameTooLarge {
                size: len,
                max: self.max_handshake_size,
            });
        }

        let mut buf = vec![0u8; len as usize];
        match timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(SourceError::IoError(e)),
            Err(_) => return Err(SourceError::Timeout),
        }

        let server_hello = bincode::deserialize(&buf)
            .map_err(|e| SourceError::ConfigError(format!("Deserialization failed: {}", e)))?;

        let client_finished = handshake_ctx.process_server_hello(server_hello).await?;

        let finished_bytes = bincode::serialize(&client_finished)
            .map_err(|e| SourceError::ConfigError(format!("Serialization failed: {}", e)))?;

        stream.write_u32(finished_bytes.len() as u32).await?;
        stream.write_all(&finished_bytes).await?;
        stream.flush().await?;

        // ServerFinished
        let len = match timeout(HANDSHAKE_TIMEOUT, stream.read_u32()).await {
            Ok(Ok(l)) => l,
            Ok(Err(e)) => return Err(SourceError::IoError(e)),
            Err(_) => return Err(SourceError::Timeout),
        };

        if len > self.max_handshake_size {
            return Err(SourceError::FrameTooLarge {
                size: len,
                max: self.max_handshake_size,
            });
        }

        let mut buf = vec![0u8; len as usize];
        match timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(SourceError::IoError(e)),
            Err(_) => return Err(SourceError::Timeout),
        }

        let server_finished = bincode::deserialize(&buf)
            .map_err(|e| SourceError::ConfigError(format!("Deserialization failed: {}", e)))?;

        handshake_ctx
            .process_server_finished(server_finished)
            .await?;

        let session_key = handshake_ctx
            .get_session_key()
            .ok_or(SourceError::ConfigError(
                "Failed to derive session key".to_string(),
            ))?;

        use hkdf::Hkdf;
        use sha2::Sha256;

        let hkdf = Hkdf::<Sha256>::new(None, &session_key);

        let mut enc_key = [0u8; 32];
        let mut mac_key = [0u8; 32];

        hkdf.expand(b"encryption", &mut enc_key)
            .map_err(|_| SourceError::ConfigError("Key derivation failed".to_string()))?;
        hkdf.expand(b"authentication", &mut mac_key)
            .map_err(|_| SourceError::ConfigError("Key derivation failed".to_string()))?;

        let derived_key = DerivedKeyMaterial::from_parts(&enc_key, &mac_key);

        let session_crypto = SessionCrypto::from_key_material(&derived_key);
        let frame_codec = Arc::new(FrameCodec::new(Arc::new(session_crypto)));

        self.health_monitor.mark_tunnel_established();
        self.health_monitor.set_status(HealthStatus::Healthy).await;
        self.health_monitor.record_success().await;

        let (read_half, write_half) = stream.into_split();

        Ok((frame_codec, read_half, write_half))
    }

    fn create_session(
        &self,
        frame_codec: Arc<FrameCodec>,
        read_half: OwnedReadHalf,
        write_half: OwnedWriteHalf,
    ) -> Arc<TunnelSession> {
        let session_id = self.session_counter.fetch_add(1, Ordering::SeqCst);
        let (session_shutdown_tx, session_shutdown_rx) = watch::channel(false);
        let heartbeat_state = Arc::new(HeartbeatState::new());
        let connection_registry: Arc<RwLock<HashMap<u32, mpsc::Sender<Frame>>>> =
            Arc::new(RwLock::new(HashMap::new()));

        let (write_queue_tx, write_queue_rx) = mpsc::unbounded_channel::<Frame>();

        Self::spawn_writer_for_session(
            session_id,
            frame_codec.clone(),
            self.tunnel_metrics.clone(),
            self.recovery_tx.clone(),
            session_shutdown_rx.clone(),
            write_half,
            write_queue_rx,
        );

        let session = Arc::new(TunnelSession {
            session_id,
            frame_codec: frame_codec.clone(),
            write_queue_tx,
            connection_registry: connection_registry.clone(),
            heartbeat_state: heartbeat_state.clone(),
            session_shutdown: session_shutdown_tx,
        });

        Self::spawn_demux_for_session(
            session_id,
            connection_registry,
            frame_codec,
            heartbeat_state.clone(),
            self.health_monitor.clone(),
            self.recovery_tx.clone(),
            session_shutdown_rx.clone(),
            read_half,
        );

        Self::spawn_heartbeat_for_session(
            session_id,
            session.write_queue_tx.clone(),
            heartbeat_state,
            self.health_monitor.clone(),
            self.ping_sequence.clone(),
            self.tunnel_metrics.clone(),
            self.recovery_tx.clone(),
            session_shutdown_rx,
            Duration::from_millis(self.config.heartbeat_interval_ms),
            Duration::from_millis(self.config.heartbeat_timeout_ms),
            self.config.max_missed_pongs,
        );

        tracing::info!(
            "Session {} established with demux/writer/heartbeat tasks",
            session_id
        );
        session
    }

    async fn read_frame_for_session(
        frame_codec: &FrameCodec,
        stream: &mut OwnedReadHalf,
        heartbeat_state: &HeartbeatState,
        health_monitor: &HealthMonitor,
    ) -> Result<Frame, SourceError> {
        let len = match timeout(FRAME_READ_TIMEOUT, stream.read_u32()).await {
            Ok(Ok(l)) => l,
            Ok(Err(e)) => return Err(SourceError::IoError(e)),
            Err(_) => return Err(SourceError::Timeout),
        };

        if len > MAX_FRAME_SIZE {
            return Err(SourceError::FrameTooLarge {
                size: len,
                max: MAX_FRAME_SIZE,
            });
        }

        let mut buf = vec![0u8; len as usize];
        match timeout(FRAME_READ_TIMEOUT, stream.read_exact(&mut buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(SourceError::IoError(e)),
            Err(_) => return Err(SourceError::Timeout),
        }

        let wire_frame = super::WireFrame::new(buf);
        let frame = frame_codec.decode(&wire_frame)?;

        if frame.frame_type() == FrameType::Pong {
            let seq = frame.sequence();
            heartbeat_state.pong_received.store(true, Ordering::SeqCst);
            if let Some(rtt) = heartbeat_state.record_pong_received(seq).await {
                tracing::debug!("Received pong (seq={}) RTT: {:?}", seq, rtt);
                health_monitor.record_success().await;
            }
        }

        Ok(frame)
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_demux_for_session(
        session_id: u64,
        registry: Arc<RwLock<HashMap<u32, mpsc::Sender<Frame>>>>,
        frame_codec: Arc<FrameCodec>,
        heartbeat_state: Arc<HeartbeatState>,
        health_monitor: Arc<HealthMonitor>,
        recovery_tx: mpsc::UnboundedSender<TunnelRecoverySignal>,
        mut session_shutdown_rx: watch::Receiver<bool>,
        mut read_half: OwnedReadHalf,
    ) {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = session_shutdown_rx.changed() => {
                        tracing::info!("Session {}: demux shutting down", session_id);
                        break;
                    }
                    frame_result = SourceContainer::read_frame_for_session(
                        &frame_codec, &mut read_half, &heartbeat_state, &health_monitor
                    ) => {
                        match frame_result {
                            Ok(frame) => {
                                let frame_type = frame.frame_type();
                                let conn_id = frame.connection_id();

                                match frame_type {
                                    FrameType::Data | FrameType::ConnectAck => {
                                        let registry_read = registry.read().await;

                                        if let Some(tx) = registry_read.get(&conn_id) {
                                            if tx.send(frame).await.is_err() {
                                                tracing::debug!(
                                                    "Session {}: connection {} channel closed, removing",
                                                    session_id, conn_id
                                                );
                                                drop(registry_read);
                                                let mut registry_write = registry.write().await;
                                                registry_write.remove(&conn_id);
                                            }
                                        } else {
                                            tracing::warn!(
                                                "Session {}: frame for unknown connection: {}",
                                                session_id, conn_id
                                            );
                                        }
                                    }
                                    FrameType::Pong => {}

                                    _ => {}
                                }
                            }
                            Err(e) => {
                                tracing::error!("Session {}: demux read error: {}", session_id, e);
                                let _ = recovery_tx.send(TunnelRecoverySignal::DemuxExited { session_id });
                                break;
                            }
                        }
                    }
                }
            }
            tracing::warn!("Session {}: demux task exited", session_id);
        });

        tracing::info!("Session {}: demux task spawned", session_id);
    }

    fn spawn_writer_for_session(
        session_id: u64,
        frame_codec: Arc<FrameCodec>,
        tunnel_metrics: Arc<super::resilience::TunnelMetrics>,
        recovery_tx: mpsc::UnboundedSender<TunnelRecoverySignal>,
        mut session_shutdown_rx: watch::Receiver<bool>,
        mut write_half: OwnedWriteHalf,
        mut write_queue_rx: mpsc::UnboundedReceiver<Frame>,
    ) {
        let _ = &tunnel_metrics;

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = session_shutdown_rx.changed() => {
                        tracing::info!("Session {}: writer shutting down", session_id);
                        break;
                    }
                    Some(frame) = write_queue_rx.recv() => {
                        let wire_frame = match frame_codec.encode(&frame) {
                            Ok(w) => w,
                            Err(e) => {
                                tracing::error!("Session {}: encode error: {}", session_id, e);
                                continue;
                            }
                        };

                        if let Err(e) = write_half.write_u32(wire_frame.len() as u32).await {
                            tracing::error!("Session {}: write length error: {}", session_id, e);
                            let _ = recovery_tx.send(TunnelRecoverySignal::WriterExited { session_id });
                            break;
                        }
                        if let Err(e) = write_half.write_all(wire_frame.as_bytes()).await {
                            tracing::error!("Session {}: write data error: {}", session_id, e);
                            let _ = recovery_tx.send(TunnelRecoverySignal::WriterExited { session_id });
                            break;
                        }
                        if let Err(e) = write_half.flush().await {
                            tracing::error!("Session {}: flush error: {}", session_id, e);
                            let _ = recovery_tx.send(TunnelRecoverySignal::WriterExited { session_id });
                            break;
                        }
                    }
                }
            }
            tracing::warn!("Session {}: writer task exited", session_id);
        });

        tracing::info!("Session {}: writer task spawned", session_id);
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_heartbeat_for_session(
        session_id: u64,
        write_queue_tx: mpsc::UnboundedSender<Frame>,
        heartbeat_state: Arc<HeartbeatState>,
        health_monitor: Arc<HealthMonitor>,
        ping_sequence: Arc<AtomicU32>,
        tunnel_metrics: Arc<super::resilience::TunnelMetrics>,
        recovery_tx: mpsc::UnboundedSender<TunnelRecoverySignal>,
        mut session_shutdown_rx: watch::Receiver<bool>,
        interval: Duration,
        timeout_duration: Duration,
        max_missed: u8,
    ) {
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(interval);
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    _ = timer.tick() => {
                        if heartbeat_state.should_send_ping(interval.as_millis() as u64).await {
                            let seq = ping_sequence.fetch_add(1, Ordering::SeqCst);
                            let ping = Frame::new_ping(seq);

                            tracing::debug!("Session {}: sending heartbeat ping (seq={})", session_id, seq);

                            // Clear before send to avoid pong/timeout race
                            heartbeat_state.pong_received.store(false, Ordering::SeqCst);

                            if write_queue_tx.send(ping).is_err() {
                                tracing::error!(
                                    "Session {}: heartbeat send failed (queue closed)",
                                    session_id
                                );
                                let _ = recovery_tx.send(TunnelRecoverySignal::HeartbeatDead { session_id });
                                break;
                            }

                            heartbeat_state.record_ping_sent(seq).await;

                            tokio::time::sleep(timeout_duration).await;

                            if !heartbeat_state.pong_received.load(Ordering::SeqCst) {
                                let total = heartbeat_state.record_ping_timeout().await;
                                tracing::warn!(
                                    "Session {}: heartbeat timeout (seq={}), consecutive misses: {}",
                                    session_id, seq, total
                                );

                                health_monitor.record_error().await;
                                tunnel_metrics.record_heartbeat_timeout();

                                if total >= max_missed {
                                    tracing::error!(
                                        "Session {}: heartbeat dead, {} consecutive timeouts",
                                        session_id, total
                                    );
                                    health_monitor.set_status(HealthStatus::Unhealthy).await;
                                    let _ = recovery_tx.send(TunnelRecoverySignal::HeartbeatDead { session_id });
                                    break;
                                } else if total >= max_missed / 2 {
                                    health_monitor.set_status(HealthStatus::Degraded).await;
                                }
                            }
                        }
                    }
                    _ = session_shutdown_rx.changed() => {
                        tracing::info!("Session {}: heartbeat shutting down", session_id);
                        break;
                    }
                }
            }
        });
    }

    async fn teardown_session(&self, session: &Arc<TunnelSession>) {
        tracing::info!("Tearing down session {}", session.session_id);
        let _ = session.session_shutdown.send(true);
        session.connection_registry.write().await.clear();
    }

    async fn reconnect_tunnel(&self) -> Result<(), SourceError> {
        if !self.circuit_breaker.should_allow_restart().await {
            return Err(SourceError::ConfigError(
                "Circuit breaker open -- too many recent restarts".to_string(),
            ));
        }

        self.tunnel_metrics.record_reconnection_attempt();

        let reconnection_manager =
            ReconnectionManager::new(self.config.clone(), self.health_monitor.clone());

        reconnection_manager
            .reconnect(|| async {
                let session = self.establish_session().await?;
                let mut active = self.active_session.write().await;
                *active = Some(session);
                Ok(())
            })
            .await
    }

    async fn create_new_session(&self) -> Result<Arc<TunnelSession>, SourceError> {
        self.establish_session().await
    }

    async fn retire_session(&self, session: Arc<TunnelSession>) {
        let drain_timeout = Duration::from_secs(self.config.connection_drain_timeout_secs);
        let retiring = self.retiring_sessions.clone();

        {
            let mut sessions = retiring.lock().await;
            sessions.push(session.clone());
        }

        let session_id = session.session_id;
        tokio::spawn(async move {
            let deadline = Instant::now() + drain_timeout;

            loop {
                let count = session.connection_registry.read().await.len();
                if count == 0 {
                    tracing::info!("Session {} drained cleanly", session_id);
                    break;
                }
                if Instant::now() >= deadline {
                    tracing::warn!(
                        "Session {} drain timeout, {} connections remaining",
                        session_id,
                        count
                    );
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }

            let _ = session.session_shutdown.send(true);
            session.connection_registry.write().await.clear();

            let mut sessions = retiring.lock().await;
            sessions.retain(|s| s.session_id != session_id);

            tracing::info!("Session {} fully retired", session_id);
        });
    }

    pub async fn handle_client(
        &self,
        mut stream: TcpStream,
        addr: SocketAddr,
        target_port: u16,
        protocol: Protocol,
    ) -> Result<(), SourceError> {
        let session = {
            let guard = self.active_session.read().await;
            guard.clone().ok_or(SourceError::NotConnected)?
        };

        let (conn, tx_from_tunnel, _rx_to_tunnel) = self
            .connection_manager
            .create_connection(addr, protocol, target_port)
            .await?;

        let conn_id = conn.id();

        {
            let mut registry = session.connection_registry.write().await;
            registry.insert(conn_id, tx_from_tunnel);
        }

        let mut rx_from_tunnel = {
            let mut rx_guard = conn.rx_from_tunnel.write().await;
            rx_guard.take().ok_or(SourceError::ConfigError(
                "rx_from_tunnel already taken".to_string(),
            ))?
        };

        let connect_frame = Frame::new_connect(conn_id, target_port, protocol);
        session
            .write_queue_tx
            .send(connect_frame)
            .map_err(|_| SourceError::NotConnected)?;

        let ack_frame =
            match tokio::time::timeout(Duration::from_secs(5), rx_from_tunnel.recv()).await {
                Ok(Some(frame)) => frame,
                Ok(None) => {
                    tracing::error!(
                        "Connection {} channel closed while waiting for CONNECT_ACK",
                        conn_id
                    );
                    session.connection_registry.write().await.remove(&conn_id);
                    self.connection_manager.remove_connection(conn_id).await;
                    return Err(SourceError::ConfigError(
                        "Channel closed while waiting for CONNECT_ACK".to_string(),
                    ));
                }
                Err(_) => {
                    tracing::debug!("Connection {} timeout waiting for CONNECT_ACK", conn_id);
                    let mut fin_frame = Frame::new_data(conn_id, 0, &[]).unwrap();
                    fin_frame.set_fin();
                    let _ = session.write_queue_tx.send(fin_frame);
                    session.connection_registry.write().await.remove(&conn_id);
                    self.connection_manager.remove_connection(conn_id).await;
                    return Ok(());
                }
            };

        if ack_frame.frame_type() != FrameType::ConnectAck {
            session.connection_registry.write().await.remove(&conn_id);
            self.connection_manager.remove_connection(conn_id).await;
            return Err(SourceError::ConfigError("Expected CONNECT_ACK".to_string()));
        }

        if ack_frame.payload().is_empty() || ack_frame.payload()[0] == 0 {
            session.connection_registry.write().await.remove(&conn_id);
            self.connection_manager.remove_connection(conn_id).await;
            return Err(SourceError::ConfigError("Connection rejected".to_string()));
        }

        conn.set_state(super::ConnectionState::Established).await;

        let conn_clone = conn.clone();
        let session_for_task = session.clone();
        let conn_manager = self.connection_manager.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                tokio::select! {
                    result = stream.read(&mut buf) => {
                        match result {
                            Ok(0) => {
                                let mut close_frame = Frame::new_data(conn_clone.id(), 0, &[]).unwrap();
                                close_frame.set_fin();
                                let _ = session_for_task.write_queue_tx.send(close_frame);
                                break;
                            }
                            Ok(n) => {
                                session_for_task.heartbeat_state.record_activity().await;

                                let frame = Frame::new_data(conn_clone.id(), 0, &buf[..n]).unwrap();
                                if session_for_task.write_queue_tx.send(frame).is_err() {
                                    tracing::error!("Session write queue closed, ending client handler");
                                    break;
                                }
                                conn_clone.record_send(n);
                            }
                            Err(e) => {
                                tracing::error!("Client read error: {}", e);
                                break;
                            }
                        }
                    }

                    frame = rx_from_tunnel.recv() => {
                        match frame {
                            Some(f) => {
                                session_for_task.heartbeat_state.record_activity().await;

                                if let Err(e) = stream.write_all(f.payload()).await {
                                    tracing::error!("Failed to write to client: {}", e);
                                    break;
                                }
                                conn_clone.record_receive(f.payload().len());

                                if f.is_fin() {
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                }
            }

            {
                let mut registry = session_for_task.connection_registry.write().await;
                registry.remove(&conn_clone.id());
            }
            conn_clone.set_state(super::ConnectionState::Closed).await;
            conn_manager.remove_connection(conn_clone.id()).await;
        });

        Ok(())
    }

    pub async fn connection_count(&self) -> usize {
        self.connection_manager.connection_count().await
    }

    pub async fn registry_count(&self) -> usize {
        let guard = self.active_session.read().await;
        match guard.as_ref() {
            Some(session) => session.connection_registry.read().await.len(),
            None => 0,
        }
    }

    pub async fn send_frame(&self, frame: Frame) -> Result<(), SourceError> {
        let guard = self.active_session.read().await;
        if let Some(ref session) = *guard {
            session
                .write_queue_tx
                .send(frame)
                .map_err(|_| SourceError::NotConnected)?;
            Ok(())
        } else {
            Err(SourceError::NotConnected)
        }
    }

    #[allow(dead_code)]
    pub async fn receive_frame(&self) -> Result<Frame, SourceError> {
        Err(SourceError::NotConnected)
    }

    pub async fn run(&self) -> Result<(), SourceError> {
        let listeners = self.setup_listeners().await?;

        if listeners.is_empty() {
            return Err(SourceError::ConfigError(
                "No listeners configured".to_string(),
            ));
        }

        tracing::info!("Running with {} listener(s)", listeners.len());

        let mut recovery_rx = {
            let mut rx_guard = self.recovery_rx.lock().await;
            rx_guard.take().ok_or(SourceError::ConfigError(
                "recovery_rx already taken -- run() called twice?".to_string(),
            ))?
        };

        let refresh_secs = self.config.connection_refresh_interval_secs;
        let refresh_interval = if refresh_secs > 0 {
            Duration::from_secs(refresh_secs)
        } else {
            Duration::from_secs(365 * 24 * 3600)
        };
        let mut refresh_timer = tokio::time::interval(refresh_interval);
        refresh_timer.tick().await;

        let (tx, mut rx) =
            tokio::sync::mpsc::unbounded_channel::<(TcpStream, SocketAddr, u16, Protocol)>();

        let mut listener_handles = Vec::new();

        for port_listener in listeners {
            let port = port_listener.port;
            let protocol = port_listener.protocol;
            let listener = port_listener.listener;
            let tx_clone = tx.clone();
            let mut shutdown_rx = self.shutdown.subscribe();

            let handle = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        result = listener.accept() => {
                            match result {
                                Ok((stream, addr)) => {
                                    if tx_clone.send((stream, addr, port, protocol)).is_err() {
                                        tracing::error!("Failed to send accepted connection to channel");
                                        break;
                                    }
                                }
                                Err(e) => {
                                    tracing::error!("Accept error on port {}: {}", port, e);
                                }
                            }
                        }
                        _ = shutdown_rx.changed() => {
                            tracing::debug!("Listener on port {} shutting down", port);
                            break;
                        }
                    }
                }
            });

            listener_handles.push(handle);
        }

        drop(tx);

        let mut shutdown_rx = self.shutdown.subscribe();

        loop {
            tokio::select! {
                Some((stream, addr, port, protocol)) = rx.recv() => {
                    self.metrics.connections_accepted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    let self_clone = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = self_clone.handle_client(stream, addr, port, protocol).await {
                            tracing::error!("Client handler error: {}", e);
                        }
                    });
                }

                _ = shutdown_rx.changed() => {
                    tracing::info!("Shutdown signal received");
                    break;
                }

                Some(signal) = recovery_rx.recv() => {
                    let signal_session_id = signal.session_id();
                    tracing::warn!("Recovery signal received: {:?}", signal);

                    while recovery_rx.try_recv().is_ok() {}

                    let active_session_id = {
                        let guard = self.active_session.read().await;
                        guard.as_ref().map(|s| s.session_id)
                    };

                    if active_session_id != Some(signal_session_id) {
                        tracing::info!(
                            "Ignoring recovery signal for old session {} (active: {:?})",
                            signal_session_id, active_session_id
                        );
                        continue;
                    }

                    if !self.config.reconnection_enabled {
                        tracing::error!("Tunnel dead but reconnection disabled -- shutting down");
                        break;
                    }

                    if let Some(session) = self.active_session.write().await.take() {
                        self.teardown_session(&session).await;
                    }

                    match self.reconnect_tunnel().await {
                        Ok(()) => {
                            tracing::info!("Tunnel recovery successful, resuming operations");
                        }
                        Err(e) => {
                            tracing::error!("Tunnel recovery failed permanently: {}", e);
                            break;
                        }
                    }
                }

                _ = refresh_timer.tick() => {
                    if self.config.connection_refresh_interval_secs == 0 {
                        continue;
                    }

                    tracing::info!("Proactive blue-green connection refresh triggered");

                    match self.create_new_session().await {
                        Ok(new_session) => {
                            let old_session = {
                                let mut active = self.active_session.write().await;
                                let old = active.take();
                                *active = Some(new_session);
                                old
                            };

                            if let Some(old) = old_session {
                                self.retire_session(old).await;
                            }

                            tracing::info!("Blue-green refresh complete");
                        }
                        Err(e) => {
                            tracing::error!(
                                "Blue-green refresh failed, keeping current connection: {}",
                                e
                            );
                        }
                    }
                }
            }
        }

        for handle in listener_handles {
            let _ = handle.await;
        }

        Ok(())
    }
}

impl Clone for SourceContainer {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            key_manager: self.key_manager.clone(),
            connection_manager: self.connection_manager.clone(),
            shutdown: self.shutdown.clone(),
            metrics: self.metrics.clone(),
            health_monitor: self.health_monitor.clone(),
            max_handshake_size: self.max_handshake_size,
            ping_sequence: self.ping_sequence.clone(),
            tunnel_metrics: self.tunnel_metrics.clone(),
            circuit_breaker: self.circuit_breaker.clone(),
            active_session: self.active_session.clone(),
            retiring_sessions: self.retiring_sessions.clone(),
            recovery_tx: self.recovery_tx.clone(),
            recovery_rx: self.recovery_rx.clone(),
            session_counter: self.session_counter.clone(),
        }
    }
}
