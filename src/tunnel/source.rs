use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, RwLock};
use tokio::time::{timeout, Duration};

// Maximum frame size to prevent memory exhaustion (1MB)
const MAX_FRAME_SIZE: u32 = 1024 * 1024;

// Handshake timeout per message (increased for large McEliece keys)
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

// Frame read timeout (30 seconds)
const FRAME_READ_TIMEOUT: Duration = Duration::from_secs(30);
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

pub struct ListenerManager {
    listeners: Vec<PortListener>,
}

impl ListenerManager {
    pub fn new() -> Self {
        Self {
            listeners: Vec::new(),
        }
    }

    pub async fn add_listener(
        &mut self,
        listen_ip: &str,
        port: u16,
        protocol: Protocol,
    ) -> Result<(), SourceError> {
        let addr = format!("{}:{}", listen_ip, port);
        let listener = TcpListener::bind(&addr).await.map_err(|e| {
            SourceError::ConfigError(format!("Failed to bind to {}: {}", addr, e))
        })?;
        tracing::info!("Listening on {} (protocol: {:?})", addr, protocol);

        self.listeners.push(PortListener {
            port,
            protocol,
            listener,
        });

        Ok(())
    }

    pub fn listeners(&self) -> &[PortListener] {
        &self.listeners
    }
}

/// Tracks heartbeat state for ping/pong exchanges
struct HeartbeatState {
    last_activity: Arc<RwLock<Instant>>,
    last_ping_seq: Arc<RwLock<Option<u32>>>,
    last_ping_time: Arc<RwLock<Option<Instant>>>,
    consecutive_misses: Arc<RwLock<u8>>,
    rtt_avg_us: Arc<RwLock<Option<u64>>>,
}

impl HeartbeatState {
    fn new() -> Self {
        Self {
            last_activity: Arc::new(RwLock::new(Instant::now())),
            last_ping_seq: Arc::new(RwLock::new(None)),
            last_ping_time: Arc::new(RwLock::new(None)),
            consecutive_misses: Arc::new(RwLock::new(0)),
            rtt_avg_us: Arc::new(RwLock::new(None)),
        }
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

                // Exponential moving average: new = 0.2 * current + 0.8 * old
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

    async fn get_consecutive_misses(&self) -> u8 {
        *self.consecutive_misses.read().await
    }

    async fn get_rtt_avg_us(&self) -> Option<u64> {
        *self.rtt_avg_us.read().await
    }
}

/// Manages automatic reconnection with exponential backoff
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

    /// Calculate next backoff delay using decorrelated jitter
    async fn calculate_backoff(&self) -> Duration {
        let attempt = self.attempt.load(Ordering::SeqCst);

        if attempt == 0 {
            return Duration::from_millis(0); // First retry immediate
        }

        if attempt == 1 {
            return Duration::from_millis(self.config.initial_reconnect_delay_ms);
        }

        let last = *self.last_delay_ms.read().await;
        let base = self.config.initial_reconnect_delay_ms;
        let max = self.config.max_reconnect_delay_ms;

        // Decorrelated jitter: random_between(base, last * 3)
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

    /// Attempt reconnection with backoff
    pub async fn reconnect<F, Fut>(&self, connect_fn: F) -> Result<(), SourceError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<(), SourceError>>,
    {
        let max_attempts = self.config.max_reconnect_attempts;

        loop {
            let attempt = self.attempt.fetch_add(1, Ordering::SeqCst);

            // Check if max attempts exceeded
            if max_attempts > 0 && attempt >= max_attempts {
                tracing::error!("Max reconnection attempts ({}) exceeded", max_attempts);
                self.health_monitor
                    .set_status(HealthStatus::Unhealthy)
                    .await;
                return Err(SourceError::ConfigError(
                    "Max reconnection attempts exceeded".to_string(),
                ));
            }

            // Calculate and apply backoff
            let delay = self.calculate_backoff().await;
            if !delay.is_zero() {
                tracing::info!("Reconnection attempt {} after {:?}", attempt + 1, delay);
                self.health_monitor
                    .set_status(HealthStatus::Connecting)
                    .await;
                tokio::time::sleep(delay).await;
            }

            // Attempt connection
            match connect_fn().await {
                Ok(_) => {
                    tracing::info!("Reconnection successful after {} attempts", attempt + 1);
                    self.reset();
                    self.health_monitor
                        .set_status(HealthStatus::Healthy)
                        .await;
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!("Reconnection attempt {} failed: {}", attempt + 1, e);
                    self.health_monitor.record_error().await;

                    // Circuit breaker: extended backoff after 10 failures
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

    pub fn get_attempt_count(&self) -> u32 {
        self.attempt.load(Ordering::SeqCst)
    }
}

pub struct SourceContainer {
    config: SourceConfig,
    key_manager: Arc<KeyManager>,
    connection_manager: Arc<ConnectionManager>,
    frame_codec: Arc<RwLock<Option<Arc<FrameCodec>>>>,
    tunnel_stream: Arc<RwLock<Option<TcpStream>>>,
    shutdown: watch::Sender<bool>,
    metrics: Arc<SourceMetrics>,
    health_monitor: Arc<HealthMonitor>,
    /// Maximum handshake message size (depends on KEM mode)
    max_handshake_size: u32,
    heartbeat_state: Arc<HeartbeatState>,
    ping_sequence: Arc<AtomicU32>,
}

impl SourceContainer {
    pub async fn new(
        config: SourceConfig,
        crypto_config: CryptoConfig,
    ) -> Result<Self, SourceError> {
        let key_manager = Arc::new(KeyManager::new(3600, 300)); // 1 hour rotation, 5 min window
        let connection_manager = Arc::new(ConnectionManager::new(
            config.max_connections,
            config.connection_timeout_ms,
        ));

        let (shutdown_tx, _) = watch::channel(false);

        let health_monitor = Arc::new(HealthMonitor::new());
        // Set initial status to Starting
        health_monitor.set_status(HealthStatus::Starting).await;

        let max_handshake_size = crypto_config.effective_max_handshake_size();
        tracing::info!(
            "Using max handshake size: {} bytes ({} KB) for KEM mode {:?}",
            max_handshake_size,
            max_handshake_size / 1024,
            crypto_config.kem_mode
        );

        Ok(Self {
            config,
            key_manager,
            connection_manager,
            frame_codec: Arc::new(RwLock::new(None)),
            tunnel_stream: Arc::new(RwLock::new(None)),
            shutdown: shutdown_tx,
            metrics: Arc::new(SourceMetrics::new()),
            health_monitor,
            max_handshake_size,
            heartbeat_state: Arc::new(HeartbeatState::new()),
            ping_sequence: Arc::new(AtomicU32::new(0)),
        })
    }

    pub async fn start(&self) -> Result<(), SourceError> {
        tracing::info!("Starting source container");

        if self.config.reconnection_enabled {
            // Connect with reconnection (includes handshake and heartbeat)
            self.connect_to_dest().await?;
        } else {
            // Original flow without reconnection
            self.connect_to_dest().await?;
            self.perform_handshake().await?;
            self.spawn_heartbeat_task().await?;
        }

        tracing::info!("Source container started successfully");
        Ok(())
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
                    let listener = TcpListener::bind(&addr).await.map_err(|e| {
                        SourceError::ConfigError(format!("Failed to bind to {}: {}", addr, e))
                    })?;
                    tracing::info!("Listening on {} (protocol: {:?})", addr, Protocol::Tcp);

                    listeners.push(PortListener {
                        port: self.config.listen_port,
                        protocol: Protocol::Tcp,
                        listener,
                    });
                } else {
                    for exposed in &self.config.exposed_ports {
                        let addr = format!("{}:{}", self.config.listen_ip, exposed.port);
                        let listener = TcpListener::bind(&addr).await.map_err(|e| {
                            SourceError::ConfigError(format!("Failed to bind to {}: {}", addr, e))
                        })?;
                        let protocol = exposed.protocol.to_tunnel_protocol();
                        tracing::info!("Listening on {} (protocol: {:?})", addr, protocol);

                        listeners.push(PortListener {
                            port: exposed.port,
                            protocol,
                            listener,
                        });
                    }
                }
            }
            SourceMode::Protocol => {
                // Single entry point on listen_port
                let addr = format!("{}:{}", self.config.listen_ip, self.config.listen_port);
                let listener = TcpListener::bind(&addr).await.map_err(|e| {
                    SourceError::ConfigError(format!("Failed to bind to {}: {}", addr, e))
                })?;
                tracing::info!("Listening on {} (protocol: {:?})", addr, Protocol::Tcp);

                listeners.push(PortListener {
                    port: self.config.listen_port,
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
        self.connection_manager.close_all().await;
    }

    pub fn is_running(&self) -> bool {
        !*self.shutdown.borrow()
    }

    pub fn health_monitor(&self) -> Arc<HealthMonitor> {
        self.health_monitor.clone()
    }

    pub async fn connect_to_dest(&self) -> Result<(), SourceError> {
        if !self.config.reconnection_enabled {
            // Original single-attempt logic
            return self.connect_to_dest_once().await;
        }

        let reconnection_manager = ReconnectionManager::new(
            self.config.clone(),
            self.health_monitor.clone(),
        );

        reconnection_manager
            .reconnect(|| async {
                self.connect_to_dest_once().await?;
                self.perform_handshake().await?;
                self.spawn_heartbeat_task().await?;
                Ok(())
            })
            .await
    }

    async fn connect_to_dest_once(&self) -> Result<(), SourceError> {
        let dest_addr = format!("{}:{}", self.config.dest_host, self.config.dest_tunnel_port);
        tracing::info!("Connecting to destination at {}", dest_addr);

        // Set status to Connecting
        self.health_monitor
            .set_status(HealthStatus::Connecting)
            .await;

        let stream = TcpStream::connect(&dest_addr).await?;
        tracing::info!("Connected to destination");

        let mut tunnel_stream = self.tunnel_stream.write().await;
        *tunnel_stream = Some(stream);

        Ok(())
    }

    pub async fn perform_handshake(&self) -> Result<(), SourceError> {
        tracing::info!("Starting handshake with destination");

        // Validate certificate access before attempting to read
        use crate::crypto::file_access::validate_file_access;
        validate_file_access(
            &self.config.client_cert_path,
            &self.config.client_key_path,
            "client",
        )
        .map_err(|e| SourceError::ConfigError(e.to_string()))?;

        // Load certificates
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

        // Send ClientHello
        let client_hello = handshake_ctx
            .create_client_hello()
            .map_err(SourceError::HandshakeError)?;
        let hello_bytes = bincode::serialize(&client_hello)
            .map_err(|e| SourceError::ConfigError(format!("Serialization failed: {}", e)))?;

        {
            let mut tunnel_stream = self.tunnel_stream.write().await;
            let stream = tunnel_stream.as_mut().ok_or(SourceError::NotConnected)?;

            stream.write_u32(hello_bytes.len() as u32).await?;
            stream.write_all(&hello_bytes).await?;
            stream.flush().await?;
        }

        // Receive ServerHello with size validation and timeout
        let server_hello_bytes = {
            let mut tunnel_stream = self.tunnel_stream.write().await;
            let stream = tunnel_stream.as_mut().ok_or(SourceError::NotConnected)?;

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
            buf
        };

        let server_hello = bincode::deserialize(&server_hello_bytes)
            .map_err(|e| SourceError::ConfigError(format!("Deserialization failed: {}", e)))?;

        let client_finished = handshake_ctx.process_server_hello(server_hello).await?;

        // Send ClientFinished
        let finished_bytes = bincode::serialize(&client_finished)
            .map_err(|e| SourceError::ConfigError(format!("Serialization failed: {}", e)))?;

        {
            let mut tunnel_stream = self.tunnel_stream.write().await;
            let stream = tunnel_stream.as_mut().ok_or(SourceError::NotConnected)?;

            stream.write_u32(finished_bytes.len() as u32).await?;
            stream.write_all(&finished_bytes).await?;
            stream.flush().await?;
        }

        // Receive ServerFinished with size validation and timeout
        let server_finished_bytes = {
            let mut tunnel_stream = self.tunnel_stream.write().await;
            let stream = tunnel_stream.as_mut().ok_or(SourceError::NotConnected)?;

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
            buf
        };

        let server_finished = bincode::deserialize(&server_finished_bytes)
            .map_err(|e| SourceError::ConfigError(format!("Deserialization failed: {}", e)))?;

        handshake_ctx
            .process_server_finished(server_finished)
            .await?;

        // Get session key and initialize crypto
        let session_key = handshake_ctx
            .get_session_key()
            .ok_or(SourceError::ConfigError(
                "Failed to derive session key".to_string(),
            ))?;

        // Use proper HKDF to derive separate encryption and MAC keys
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

        let mut codec = self.frame_codec.write().await;
        *codec = Some(frame_codec);

        // Mark tunnel as established and set status to Healthy
        self.health_monitor.mark_tunnel_established();
        self.health_monitor.set_status(HealthStatus::Healthy).await;
        self.health_monitor.record_success().await;

        tracing::info!("Handshake completed successfully");
        Ok(())
    }

    /// Spawns background task to send periodic heartbeat pings
    async fn spawn_heartbeat_task(&self) -> Result<(), SourceError> {
        if !self.config.reconnection_enabled {
            return Ok(());
        }

        let interval = Duration::from_millis(self.config.heartbeat_interval_ms);
        let timeout_duration = Duration::from_millis(self.config.heartbeat_timeout_ms);
        let max_missed = self.config.max_missed_pongs;

        let state = self.heartbeat_state.clone();
        let container = Arc::new(self.clone());
        let health = self.health_monitor.clone();
        let ping_seq = self.ping_sequence.clone();
        let mut shutdown = self.shutdown.subscribe();

        tokio::spawn(async move {
            let mut timer = tokio::time::interval(interval);
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    _ = timer.tick() => {
                        // Only send ping if idle for interval duration
                        if state.should_send_ping(interval.as_millis() as u64).await {
                            let seq = ping_seq.fetch_add(1, Ordering::SeqCst);
                            let ping = Frame::new_ping(seq);

                            tracing::debug!("Sending heartbeat ping (seq={})", seq);

                            match container.send_frame(ping).await {
                                Ok(_) => {
                                    state.record_ping_sent(seq).await;

                                    // Wait for pong (processed in receive_frame)
                                    tokio::time::sleep(timeout_duration).await;

                                    // Check if pong was received
                                    let misses = state.get_consecutive_misses().await;
                                    if misses > 0 {
                                        let total = state.record_ping_timeout().await;
                                        tracing::warn!("Heartbeat timeout (seq={}), consecutive misses: {}", seq, total);

                                        health.record_error().await;

                                        if total >= max_missed {
                                            tracing::error!("Heartbeat failed: {} consecutive timeouts", total);
                                            health.set_status(HealthStatus::Unhealthy).await;
                                            // Trigger reconnection (will be handled by reconnection manager)
                                        } else if total >= max_missed / 2 {
                                            health.set_status(HealthStatus::Degraded).await;
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::error!("Failed to send heartbeat: {}", e);
                                    health.record_error().await;
                                }
                            }
                        }
                    }
                    _ = shutdown.changed() => {
                        tracing::info!("Heartbeat task shutting down");
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    pub async fn handle_client(
        &self,
        mut stream: TcpStream,
        addr: SocketAddr,
        target_port: u16,
        protocol: Protocol,
    ) -> Result<(), SourceError> {
        tracing::info!(
            "New client connection from {} targeting port {} ({:?})",
            addr, target_port, protocol
        );

        let (conn, _tx_from_tunnel, mut rx_to_tunnel) = self
            .connection_manager
            .create_connection(addr, protocol, target_port)
            .await?;

        // Send CONNECT frame with actual target port
        let connect_frame = Frame::new_connect(conn.id(), target_port, protocol);
        self.send_frame(connect_frame).await?;

        // Wait for CONNECT_ACK
        let ack_frame = self.receive_frame().await?;
        if ack_frame.frame_type() != FrameType::ConnectAck {
            return Err(SourceError::ConfigError("Expected CONNECT_ACK".to_string()));
        }

        if ack_frame.payload().is_empty() || ack_frame.payload()[0] == 0 {
            return Err(SourceError::ConfigError("Connection rejected".to_string()));
        }

        conn.set_state(super::ConnectionState::Established).await;

        // Bidirectional forwarding
        let conn_clone = conn.clone();
        let self_clone = Arc::new(self.clone());

        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                tokio::select! {
                    // Read from client, send to tunnel
                    result = stream.read(&mut buf) => {
                        match result {
                            Ok(0) => {
                                // Client closed connection
                                let mut close_frame = Frame::new_data(conn_clone.id(), 0, &[]).unwrap();
                                close_frame.set_fin();
                                let _ = self_clone.send_frame(close_frame).await;
                                break;
                            }
                            Ok(n) => {
                                // Record activity to prevent unnecessary pings
                                self_clone.heartbeat_state.record_activity().await;

                                let frame = Frame::new_data(conn_clone.id(), 0, &buf[..n]).unwrap();
                                if let Err(e) = self_clone.send_frame(frame).await {
                                    tracing::error!("Failed to send frame: {}", e);
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

                    // Receive from tunnel, write to client
                    frame = rx_to_tunnel.recv() => {
                        match frame {
                            Some(f) => {
                                // Record activity
                                self_clone.heartbeat_state.record_activity().await;

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

            conn_clone.set_state(super::ConnectionState::Closed).await;
        });

        Ok(())
    }

    pub async fn send_frame(&self, frame: Frame) -> Result<(), SourceError> {
        let codec = self.frame_codec.read().await;
        let codec = codec.as_ref().ok_or(SourceError::NotConnected)?;

        let wire_frame = codec.encode(&frame)?;

        let mut tunnel_stream = self.tunnel_stream.write().await;
        let stream = tunnel_stream.as_mut().ok_or(SourceError::NotConnected)?;

        stream.write_u32(wire_frame.len() as u32).await?;
        stream.write_all(wire_frame.as_bytes()).await?;
        stream.flush().await?;

        Ok(())
    }

    pub async fn receive_frame(&self) -> Result<Frame, SourceError> {
        let mut tunnel_stream = self.tunnel_stream.write().await;
        let stream = tunnel_stream.as_mut().ok_or(SourceError::NotConnected)?;

        // Read frame length with timeout
        let len = match timeout(FRAME_READ_TIMEOUT, stream.read_u32()).await {
            Ok(Ok(l)) => l,
            Ok(Err(e)) => return Err(SourceError::IoError(e)),
            Err(_) => return Err(SourceError::Timeout),
        };

        // Validate frame size before allocation
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

        let codec = self.frame_codec.read().await;
        let codec = codec.as_ref().ok_or(SourceError::NotConnected)?;

        let wire_frame = super::WireFrame::new(buf);
        let frame = codec.decode(&wire_frame)?;

        // Handle Pong frames for heartbeat
        if frame.frame_type() == FrameType::Pong {
            let seq = frame.sequence();
            if let Some(rtt) = self.heartbeat_state.record_pong_received(seq).await {
                tracing::debug!("Received pong (seq={}) RTT: {:?}", seq, rtt);
                self.health_monitor.record_success().await;
            }
        }

        Ok(frame)
    }

    pub async fn run(&self) -> Result<(), SourceError> {
        // Setup all listeners
        let listeners = self.setup_listeners().await?;

        if listeners.is_empty() {
            return Err(SourceError::ConfigError(
                "No listeners configured".to_string(),
            ));
        }

        tracing::info!("Running with {} listener(s)", listeners.len());

        // Create a channel for accepted connections
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(
            TcpStream,
            SocketAddr,
            u16,
            Protocol,
        )>();

        // Spawn a task for each listener
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

        // Drop the original sender so the channel closes when all listener tasks finish
        drop(tx);

        // Main loop: process accepted connections
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
            }
        }

        // Wait for all listener tasks to finish
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
            frame_codec: self.frame_codec.clone(),
            tunnel_stream: self.tunnel_stream.clone(),
            shutdown: self.shutdown.clone(),
            metrics: self.metrics.clone(),
            health_monitor: self.health_monitor.clone(),
            max_handshake_size: self.max_handshake_size,
            heartbeat_state: self.heartbeat_state.clone(),
            ping_sequence: self.ping_sequence.clone(),
        }
    }
}
