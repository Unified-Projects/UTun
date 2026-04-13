use super::{
    ConnectionError, ConnectionManager, Frame, FrameCodec, FrameError, FrameType, HandshakeContext,
    HandshakeError, Protocol,
};
use crate::config::{CryptoConfig, DestConfig, ServiceConfig};
use crate::crypto::{DerivedKeyMaterial, KeyManager, SessionCrypto};
use crate::health::{HealthMonitor, HealthStatus};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, Mutex, OwnedSemaphorePermit, RwLock, Semaphore};
use tokio::time::{timeout, timeout_at, Duration, Instant};

// Maximum frame size to prevent memory exhaustion (1MB)
const MAX_FRAME_SIZE: u32 = 1024 * 1024;

// Frame read timeout (must exceed heartbeat interval to allow pings during idle periods)
const FRAME_READ_TIMEOUT: Duration = Duration::from_secs(60);

// Handshake timeout per message (increased for large McEliece keys)
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Probe interval for checking if a target port has become available.
const PORT_PROBE_INTERVAL: Duration = Duration::from_millis(500);

/// Maximum number of in-flight handshakes processed at once.
const MAX_CONCURRENT_HANDSHAKES: usize = 64;

/// Maximum accepted handshakes from a single IP within the rolling window.
const MAX_HANDSHAKES_PER_IP: usize = 16;

/// Rolling window used for per-IP handshake admission control.
const HANDSHAKE_RATE_WINDOW: Duration = Duration::from_secs(10);

/// Tracks the readiness state of a single target port.
/// When a port is detected as unavailable, a background probe task is spawned
/// that periodically checks if the port has come back up.
struct PortReadinessEntry {
    ready_tx: watch::Sender<bool>,
}

/// Monitors target service ports and provides a mechanism for callers to wait
/// until a port becomes reachable rather than failing immediately.
struct PortWatcher {
    /// Per-port readiness state keyed by `"ip:port"` target address.
    ports: RwLock<HashMap<String, Arc<PortReadinessEntry>>>,
}

impl PortWatcher {
    fn new() -> Self {
        Self {
            ports: RwLock::new(HashMap::new()),
        }
    }

    /// Returns the readiness entry for the given target address, creating one
    /// (assumed ready) if it does not yet exist.
    async fn get_or_create(&self, target_addr: &str) -> Arc<PortReadinessEntry> {
        // Fast path: read lock
        {
            let ports = self.ports.read().await;
            if let Some(entry) = ports.get(target_addr) {
                return entry.clone();
            }
        }
        // Slow path: write lock to insert
        let mut ports = self.ports.write().await;
        ports
            .entry(target_addr.to_string())
            .or_insert_with(|| {
                let (ready_tx, _) = watch::channel(true);
                Arc::new(PortReadinessEntry {
                    ready_tx, // assume ready until proven otherwise
                })
            })
            .clone()
    }

    /// Mark a port as unavailable and spawn a background probe task that will
    /// flip it back to ready once a TCP connection succeeds. If a probe task
    /// is already running (the port is already marked down), this is a no-op.
    async fn mark_unavailable(&self, target_addr: String, shutdown: watch::Receiver<bool>) {
        let entry = self.get_or_create(&target_addr).await;

        // If already marked down, a probe task is already running.
        if !*entry.ready_tx.borrow() {
            return;
        }
        entry.ready_tx.send_replace(false);

        tracing::warn!(
            "Target {} is unavailable -- starting port readiness watcher",
            target_addr
        );

        let entry_clone = entry.clone();
        let addr = target_addr.clone();
        let mut shutdown_rx = shutdown;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(PORT_PROBE_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        match timeout(PORT_PROBE_INTERVAL, TcpStream::connect(&addr)).await {
                            Ok(Ok(_)) => {
                                tracing::info!(
                                    "Target {} is now reachable -- resuming connections",
                                    addr
                                );
                                entry_clone.ready_tx.send_replace(true);
                                return;
                            }
                            Ok(Err(_)) | Err(_) => {
                                // Still unavailable, keep probing.
                            }
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        tracing::debug!("Port watcher for {} shutting down", addr);
                        return;
                    }
                }
            }
        });
    }

    /// Wait until the target address becomes ready, or until `deadline` is
    /// reached. Returns `true` if the port is (now) ready, `false` on timeout.
    async fn wait_until_ready(&self, target_addr: &str, deadline: Instant) -> bool {
        let entry = self.get_or_create(target_addr).await;
        let mut ready_rx = entry.ready_tx.subscribe();

        if *ready_rx.borrow() {
            return true;
        }

        tracing::debug!(
            "Waiting up to {:?} for target {} to become available",
            deadline,
            target_addr
        );

        match timeout_at(deadline, async {
            loop {
                if *ready_rx.borrow() {
                    return true;
                }
                if ready_rx.changed().await.is_err() {
                    return false;
                }
            }
        })
        .await
        {
            Ok(ready) => ready,
            Err(_) => *ready_rx.borrow(),
        }
    }
}

#[derive(Debug, Error)]
pub enum DestError {
    #[error("Handshake error: {0}")]
    HandshakeError(#[from] HandshakeError),

    #[error("Frame error: {0}")]
    FrameError(#[from] FrameError),

    #[error("Connection error: {0}")]
    ConnectionError(#[from] ConnectionError),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Service not found: {0}")]
    ServiceNotFound(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Frame size {size} exceeds maximum {max}")]
    FrameTooLarge { size: u32, max: u32 },

    #[error("Frame read timeout - connection may be stalled")]
    Timeout,
}

pub struct DestMetrics {
    pub tunnels_accepted: std::sync::atomic::AtomicU64,
    pub connections_forwarded: std::sync::atomic::AtomicU64,
    pub bytes_sent: std::sync::atomic::AtomicU64,
    pub bytes_received: std::sync::atomic::AtomicU64,
}

impl Default for DestMetrics {
    fn default() -> Self {
        Self {
            tunnels_accepted: std::sync::atomic::AtomicU64::new(0),
            connections_forwarded: std::sync::atomic::AtomicU64::new(0),
            bytes_sent: std::sync::atomic::AtomicU64::new(0),
            bytes_received: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl DestMetrics {
    pub fn new() -> Self {
        Self::default()
    }
}

pub struct ServiceRegistry {
    services: HashMap<u16, ServiceConfig>,
}

impl ServiceRegistry {
    pub fn new(services: Vec<ServiceConfig>) -> Self {
        let mut map = HashMap::new();
        for service in services {
            map.insert(service.port, service);
        }

        Self { services: map }
    }

    pub fn get_service(&self, port: u16) -> Option<&ServiceConfig> {
        self.services.get(&port)
    }

    pub fn get_by_name(&self, name: &str) -> Option<&ServiceConfig> {
        self.services.values().find(|s| s.name == name)
    }
}

/// Stores the write half of a target connection for forwarding data.
/// Writer is behind a Mutex so the HashMap only needs a read lock for data forwarding.
struct TargetConnection {
    writer: Mutex<OwnedWriteHalf>,
}

#[derive(Clone)]
struct ServerHandshakeMaterial {
    server_cert: Arc<[u8]>,
    server_key: Arc<[u8]>,
    ca_cert: Arc<[u8]>,
}

pub struct DestContainer {
    config: DestConfig,
    key_manager: Arc<KeyManager>,
    connection_manager: Arc<ConnectionManager>,
    service_registry: Arc<ServiceRegistry>,
    frame_codec: Arc<RwLock<Option<Arc<FrameCodec>>>>,
    shutdown: watch::Sender<bool>,
    metrics: Arc<DestMetrics>,
    health_monitor: Arc<HealthMonitor>,
    /// Maps connection_id -> target connection write half for data forwarding
    target_connections: Arc<RwLock<HashMap<u32, Arc<TargetConnection>>>>,
    /// Channel to send response frames back to the tunnel
    response_tx: Arc<RwLock<Option<mpsc::Sender<Frame>>>>,
    /// Maximum handshake message size (depends on KEM mode)
    max_handshake_size: u32,
    /// Channel size configuration
    channel_size: usize,
    /// Watches target ports and allows callers to wait for them to become available
    port_watcher: Arc<PortWatcher>,
    /// Preloaded certificate material used during the handshake path.
    handshake_material: ServerHandshakeMaterial,
    /// Limits expensive in-flight handshakes.
    handshake_limiter: Arc<Semaphore>,
    /// Per-IP rolling handshake counters for basic admission control.
    handshake_attempts: Arc<Mutex<HashMap<IpAddr, VecDeque<Instant>>>>,
}

impl DestContainer {
    pub async fn new(config: DestConfig, crypto_config: CryptoConfig) -> Result<Self, DestError> {
        let channel_size = config.connection_channel_size;
        let handshake_material = load_server_handshake_material(&config)?;

        let key_manager = Arc::new(KeyManager::new(3600, 300)); // 1 hour rotation, 5 min window
        let connection_manager = Arc::new(ConnectionManager::new_with_channel_size(
            config.max_connections_per_service * config.exposed_services.len(),
            config.connection_timeout_ms,
            channel_size,
        ));
        let service_registry = Arc::new(ServiceRegistry::new(config.exposed_services.clone()));

        let (shutdown_tx, _) = watch::channel(false);

        let health_monitor = Arc::new(HealthMonitor::new());
        // Set initial status to Starting
        health_monitor.set_status(HealthStatus::Starting).await;

        let max_handshake_size = crypto_config.effective_max_handshake_size();

        Ok(Self {
            config,
            key_manager,
            connection_manager,
            service_registry,
            frame_codec: Arc::new(RwLock::new(None)),
            shutdown: shutdown_tx,
            metrics: Arc::new(DestMetrics::new()),
            health_monitor,
            target_connections: Arc::new(RwLock::new(HashMap::new())),
            response_tx: Arc::new(RwLock::new(None)),
            max_handshake_size,
            channel_size,
            port_watcher: Arc::new(PortWatcher::new()),
            handshake_material,
            handshake_limiter: Arc::new(Semaphore::new(MAX_CONCURRENT_HANDSHAKES)),
            handshake_attempts: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn start(&self) -> Result<(), DestError> {
        // Set status to Connecting as we wait for source to connect
        self.health_monitor
            .set_status(HealthStatus::Connecting)
            .await;
        Ok(())
    }

    pub async fn stop(&self) {
        tracing::info!("Stopping destination container");
        let _ = self.shutdown.send(true);
        self.connection_manager.close_all().await;
    }

    pub fn is_running(&self) -> bool {
        !*self.shutdown.borrow()
    }

    pub fn health_monitor(&self) -> Arc<HealthMonitor> {
        self.health_monitor.clone()
    }

    fn is_source_allowed(&self, ip: IpAddr) -> bool {
        if self.config.connection_filter.allowed_source_ips.is_empty() {
            return true;
        }

        self.config.is_source_allowed(ip)
    }

    async fn admit_handshake(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let window_start = now - HANDSHAKE_RATE_WINDOW;

        let mut attempts = self.handshake_attempts.lock().await;
        let per_ip_attempts = attempts.entry(ip).or_default();
        while per_ip_attempts.front().is_some_and(|ts| *ts < window_start) {
            per_ip_attempts.pop_front();
        }

        if per_ip_attempts.len() >= MAX_HANDSHAKES_PER_IP {
            return false;
        }

        per_ip_attempts.push_back(now);
        true
    }

    fn spawn_stale_cleanup_task(&self) -> tokio::task::JoinHandle<()> {
        let cleanup_cm = self.connection_manager.clone();
        let cleanup_tc = self.target_connections.clone();
        let cleanup_interval = Duration::from_secs(self.config.stale_cleanup_interval_secs);
        let mut cleanup_shutdown = self.shutdown.subscribe();

        tokio::spawn(async move {
            let mut timer = tokio::time::interval(cleanup_interval);
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = timer.tick() => {
                        let removed_ids = cleanup_cm.cleanup_stale().await;
                        if !removed_ids.is_empty() {
                            tracing::debug!("Stale cleanup removed {} connections from ConnectionManager", removed_ids.len());
                            let mut tc = cleanup_tc.write().await;
                            for id in &removed_ids {
                                tc.remove(id);
                            }
                        }
                    }
                    _ = cleanup_shutdown.changed() => {
                        tracing::debug!("Stale cleanup task shutting down");
                        break;
                    }
                }
            }
        })
    }

    pub async fn handle_tunnel_connection(
        &self,
        mut stream: TcpStream,
        addr: SocketAddr,
        handshake_permit: OwnedSemaphorePermit,
    ) -> Result<(), DestError> {
        tracing::info!("New tunnel connection from {}", addr);
        self.metrics
            .tunnels_accepted
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Perform handshake
        let session_key = self.perform_server_handshake(&mut stream).await?;
        drop(handshake_permit);

        // Initialize crypto - Use proper HKDF to derive separate encryption and MAC keys
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hkdf = Hkdf::<Sha256>::new(None, &session_key);

        let mut enc_key = [0u8; 32];
        let mut mac_key = [0u8; 32];

        hkdf.expand(b"encryption", &mut enc_key)
            .map_err(|_| DestError::ConfigError("Key derivation failed".to_string()))?;
        hkdf.expand(b"authentication", &mut mac_key)
            .map_err(|_| DestError::ConfigError("Key derivation failed".to_string()))?;

        let derived_key = DerivedKeyMaterial::from_parts(&mac_key, &enc_key);

        let session_crypto = SessionCrypto::from_key_material(&derived_key);
        let frame_codec = Arc::new(FrameCodec::new(Arc::new(session_crypto)));

        let mut codec = self.frame_codec.write().await;
        *codec = Some(frame_codec.clone());
        drop(codec);

        // Create a bounded channel for response frames so backpressure is applied
        // before tunnel writes can accumulate unbounded memory.
        let (response_tx, mut response_rx) = mpsc::channel::<Frame>(self.channel_size);

        // Store the response sender
        {
            let mut tx = self.response_tx.write().await;
            *tx = Some(response_tx.clone());
        }

        // Log channel configuration
        tracing::info!(
            "Response channel configured with capacity {} for connection from {}",
            self.channel_size,
            addr
        );

        // Handle incoming frames
        let connection_manager = self.connection_manager.clone();
        let service_registry = self.service_registry.clone();
        let metrics = self.metrics.clone();

        // Set TCP_NODELAY for lower latency on the tunnel socket
        stream.set_nodelay(true).ok();

        // Split stream for concurrent read/write
        let (mut read_half, mut write_half) = stream.into_split();

        // Spawn writer task to handle response frames with batch flush optimization
        let frame_codec_clone = frame_codec.clone();
        let writer_handle = tokio::spawn(async move {
            while let Some(frame) = response_rx.recv().await {
                // Collect this frame plus any additional pending frames for batch write
                let mut frames_to_write = vec![frame];
                while let Ok(extra) = response_rx.try_recv() {
                    frames_to_write.push(extra);
                }

                let mut write_error = false;
                for f in &frames_to_write {
                    let wire_frame = match frame_codec_clone.encode(f) {
                        Ok(w) => w,
                        Err(e) => {
                            tracing::error!("Failed to encode response: {}", e);
                            continue;
                        }
                    };

                    if let Err(e) = write_half.write_u32(wire_frame.len() as u32).await {
                        tracing::error!("Failed to write response length: {}", e);
                        write_error = true;
                        break;
                    }

                    if let Err(e) = write_half.write_all(wire_frame.as_bytes()).await {
                        tracing::error!("Failed to write response: {}", e);
                        write_error = true;
                        break;
                    }
                }

                if write_error {
                    break;
                }

                // Single flush after the entire batch
                if let Err(e) = write_half.flush().await {
                    tracing::error!("Failed to flush: {}", e);
                    break;
                }
            }
        });

        let mut tunnel_shutdown_rx = self.shutdown.subscribe();
        let mut read_buf = Vec::with_capacity(8192);
        loop {
            let len = tokio::select! {
                result = timeout(FRAME_READ_TIMEOUT, read_half.read_u32()) => {
                    match result {
                        Ok(Ok(l)) => l,
                        Ok(Err(e)) => {
                            tracing::debug!("Stream closed: {}", e);
                            break;
                        }
                        Err(_) => {
                            tracing::warn!("Frame length read timeout - closing connection");
                            drop(response_tx);
                            let _ = writer_handle.await;
                            return Err(DestError::Timeout);
                        }
                    }
                }
                _ = tunnel_shutdown_rx.changed() => {
                    tracing::info!("Tunnel handler received shutdown signal");
                    break;
                }
            };

            if len > MAX_FRAME_SIZE {
                tracing::error!("Frame size {} exceeds maximum {}", len, MAX_FRAME_SIZE);
                drop(response_tx);
                let _ = writer_handle.await;
                return Err(DestError::FrameTooLarge {
                    size: len,
                    max: MAX_FRAME_SIZE,
                });
            }

            if len == 0 {
                continue;
            }

            let len_usize = len as usize;
            if read_buf.len() < len_usize {
                read_buf.resize(len_usize, 0);
            }
            match timeout(
                FRAME_READ_TIMEOUT,
                read_half.read_exact(&mut read_buf[..len_usize]),
            )
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    tracing::error!("Failed to read frame: {}", e);
                    break;
                }
                Err(_) => {
                    tracing::warn!("Frame data read timeout - closing connection");
                    drop(response_tx);
                    let _ = writer_handle.await;
                    return Err(DestError::Timeout);
                }
            }

            let wire_frame = super::WireFrame::new(read_buf[..len_usize].to_vec());
            let frame = match frame_codec.decode(&wire_frame) {
                Ok(f) => f,
                Err(e) => {
                    tracing::error!("Failed to decode frame: {}", e);
                    continue;
                }
            };

            // Handle frame
            let response = self
                .handle_frame_internal(
                    frame,
                    &connection_manager,
                    &service_registry,
                    &metrics,
                    &response_tx,
                )
                .await;

            // Send response if any (through the channel)
            if let Some(resp_frame) = response {
                if response_tx.send(resp_frame).await.is_err() {
                    tracing::error!("Failed to send response - channel closed");
                    break;
                }
            }
        }

        // Clean up: drop sender and wait for writer task
        drop(response_tx);
        {
            let mut tx = self.response_tx.write().await;
            *tx = None;
        }
        let _ = writer_handle.await;

        // Clear target connections and connection manager
        {
            let mut connections = self.target_connections.write().await;
            connections.clear();
        }
        self.connection_manager.close_all().await;

        Ok(())
    }

    async fn perform_server_handshake(&self, stream: &mut TcpStream) -> Result<Vec<u8>, DestError> {
        let mut handshake_ctx = HandshakeContext::new_server(
            self.key_manager.clone(),
            self.handshake_material.server_cert.as_ref().to_vec(),
            self.handshake_material.server_key.as_ref().to_vec(),
            self.handshake_material.ca_cert.as_ref().to_vec(),
        );

        // Receive ClientHello with size validation and timeout
        let len = match timeout(HANDSHAKE_TIMEOUT, stream.read_u32()).await {
            Ok(Ok(l)) => l,
            Ok(Err(e)) => return Err(DestError::IoError(e)),
            Err(_) => return Err(DestError::Timeout),
        };

        if len > self.max_handshake_size {
            return Err(DestError::FrameTooLarge {
                size: len,
                max: self.max_handshake_size,
            });
        }

        let mut buf = vec![0u8; len as usize];
        match timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(DestError::IoError(e)),
            Err(_) => return Err(DestError::Timeout),
        }

        let client_hello = bincode::deserialize(&buf)
            .map_err(|e| DestError::ConfigError(format!("Deserialization failed: {}", e)))?;

        // Process and send ServerHello
        let server_hello = handshake_ctx.process_client_hello(client_hello).await?;
        let hello_bytes = bincode::serialize(&server_hello)
            .map_err(|e| DestError::ConfigError(format!("Serialization failed: {}", e)))?;

        stream.write_u32(hello_bytes.len() as u32).await?;
        stream.write_all(&hello_bytes).await?;
        stream.flush().await?;

        // Receive ClientFinished with size validation and timeout
        let len = match timeout(HANDSHAKE_TIMEOUT, stream.read_u32()).await {
            Ok(Ok(l)) => l,
            Ok(Err(e)) => return Err(DestError::IoError(e)),
            Err(_) => return Err(DestError::Timeout),
        };

        if len > self.max_handshake_size {
            return Err(DestError::FrameTooLarge {
                size: len,
                max: self.max_handshake_size,
            });
        }

        let mut buf = vec![0u8; len as usize];
        match timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(DestError::IoError(e)),
            Err(_) => return Err(DestError::Timeout),
        }

        let client_finished = bincode::deserialize(&buf)
            .map_err(|e| DestError::ConfigError(format!("Deserialization failed: {}", e)))?;

        // Process and send ServerFinished
        let server_finished = handshake_ctx
            .process_client_finished(client_finished)
            .await?;
        let finished_bytes = bincode::serialize(&server_finished)
            .map_err(|e| DestError::ConfigError(format!("Serialization failed: {}", e)))?;

        stream.write_u32(finished_bytes.len() as u32).await?;
        stream.write_all(&finished_bytes).await?;
        stream.flush().await?;

        // Get session key
        let session_key = handshake_ctx
            .get_session_key()
            .ok_or(DestError::ConfigError(
                "Failed to derive session key".to_string(),
            ))?;

        // Mark tunnel as established and set status to Healthy
        self.health_monitor.mark_tunnel_established();
        self.health_monitor.set_status(HealthStatus::Healthy).await;
        self.health_monitor.record_success().await;

        Ok(session_key)
    }

    async fn handle_frame_internal(
        &self,
        frame: Frame,
        connection_manager: &Arc<ConnectionManager>,
        service_registry: &Arc<ServiceRegistry>,
        metrics: &Arc<DestMetrics>,
        response_tx: &mpsc::Sender<Frame>,
    ) -> Option<Frame> {
        match frame.frame_type() {
            FrameType::Connect => {
                // Parse connect frame
                if frame.payload().len() < 3 {
                    tracing::error!("Invalid CONNECT frame payload");
                    return Some(Frame::new_connect_ack(frame.connection_id(), false));
                }

                let port = u16::from_be_bytes([frame.payload()[0], frame.payload()[1]]);
                let protocol = Protocol::from_u8(frame.payload()[2]).unwrap_or(Protocol::Tcp);
                let connection_id = frame.connection_id();

                // Look up service
                let service = match service_registry.get_service(port) {
                    Some(s) => s.clone(),
                    None => {
                        tracing::error!("Service not found for port {}", port);
                        return Some(Frame::new_connect_ack(connection_id, false));
                    }
                };

                let self_clone = self.clone();
                let response_tx_clone = response_tx.clone();

                tokio::spawn(async move {
                    self_clone
                        .process_connect_request(
                            connection_id,
                            port,
                            protocol,
                            service,
                            response_tx_clone,
                        )
                        .await;
                });

                None
            }

            FrameType::Data => {
                // Forward data to target connection
                let connection_id = frame.connection_id();
                let payload = frame.payload();

                if payload.is_empty() && frame.is_fin() {
                    // Close indication - remove from both maps
                    {
                        let mut connections = self.target_connections.write().await;
                        connections.remove(&connection_id);
                    }
                    connection_manager.remove_connection(connection_id).await;
                    return None;
                }

                // Look up target connection with a read lock, then lock per-connection Mutex
                let target_conn = {
                    let connections = self.target_connections.read().await;
                    connections.get(&connection_id).cloned()
                };

                if let Some(target_conn) = target_conn {
                    let mut writer = target_conn.writer.lock().await;
                    if let Err(e) = writer.write_all(payload).await {
                        let kind = e.kind();
                        let is_transient = matches!(
                            kind,
                            std::io::ErrorKind::WouldBlock
                                | std::io::ErrorKind::Interrupted
                                | std::io::ErrorKind::TimedOut
                        );

                        if is_transient {
                            tracing::warn!(
                                "Transient write error on target {}, retrying: {}",
                                connection_id,
                                e
                            );
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            if let Err(e2) = writer.write_all(payload).await {
                                tracing::error!(
                                    "Retry failed for target {}: {}",
                                    connection_id,
                                    e2
                                );
                                drop(writer);
                                let mut connections = self.target_connections.write().await;
                                connections.remove(&connection_id);
                                connection_manager.remove_connection(connection_id).await;
                            } else {
                                metrics.bytes_sent.fetch_add(
                                    payload.len() as u64,
                                    std::sync::atomic::Ordering::Relaxed,
                                );
                            }
                        } else {
                            tracing::error!("Failed to write to target {}: {}", connection_id, e);
                            drop(writer);
                            let mut connections = self.target_connections.write().await;
                            connections.remove(&connection_id);
                            connection_manager.remove_connection(connection_id).await;
                        }
                    } else {
                        metrics
                            .bytes_sent
                            .fetch_add(payload.len() as u64, std::sync::atomic::Ordering::Relaxed);
                    }
                } else {
                    tracing::warn!("No target connection for id {}", connection_id);
                }

                None
            }

            FrameType::Ping => Some(Frame::new_pong(frame.sequence())),

            FrameType::Close => {
                // Close connection
                let connection_id = frame.connection_id();
                let _ = connection_manager.remove_connection(connection_id).await;

                // Also remove target connection
                let mut connections = self.target_connections.write().await;
                connections.remove(&connection_id);

                None
            }

            _ => {
                tracing::warn!("Unhandled frame type: {:?}", frame.frame_type());
                None
            }
        }
    }

    pub async fn handle_frame(&self, frame: Frame) -> Result<Option<Frame>, FrameError> {
        let response_tx = self.response_tx.read().await.clone();
        if let Some(ref tx) = response_tx {
            let response = self
                .handle_frame_internal(
                    frame,
                    &self.connection_manager,
                    &self.service_registry,
                    &self.metrics,
                    tx,
                )
                .await;
            Ok(response)
        } else {
            // No active tunnel connection - can't handle frame
            tracing::warn!("Cannot handle frame: no active tunnel connection");
            Ok(None)
        }
    }

    /// Number of connections tracked by the ConnectionManager
    pub async fn connection_count(&self) -> usize {
        self.connection_manager.connection_count().await
    }

    /// Number of active target TCP connections
    pub async fn target_connection_count(&self) -> usize {
        self.target_connections.read().await.len()
    }

    pub async fn run(&self) -> Result<(), DestError> {
        let listener = TcpListener::bind(format!(
            "{}:{}",
            self.config.listen_ip, self.config.tunnel_port
        ))
        .await?;
        tracing::info!(
            "Listening for tunnel connections on {}:{}",
            self.config.listen_ip,
            self.config.tunnel_port
        );

        let mut shutdown_rx = self.shutdown.subscribe();
        let cleanup_handle = self.spawn_stale_cleanup_task();

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            if !self.is_source_allowed(addr.ip()) {
                                tracing::warn!("Rejected tunnel connection from unauthorized source {}", addr);
                                continue;
                            }

                            if !self.admit_handshake(addr.ip()).await {
                                tracing::warn!("Rate limiting tunnel handshake from {}", addr);
                                continue;
                            }

                            let handshake_permit = match self.handshake_limiter.clone().try_acquire_owned() {
                                Ok(permit) => permit,
                                Err(_) => {
                                    tracing::warn!(
                                        "Rejecting tunnel connection from {} because handshake capacity is exhausted",
                                        addr
                                    );
                                    continue;
                                }
                            };

                            let self_clone = self.clone();
                            tokio::spawn(async move {
                                if let Err(e) = self_clone
                                    .handle_tunnel_connection(stream, addr, handshake_permit)
                                    .await
                                {
                                    tracing::error!("Tunnel handler error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!("Accept error: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    tracing::info!("Shutdown signal received");
                    break;
                }
            }
        }

        cleanup_handle.abort();
        let _ = cleanup_handle.await;

        Ok(())
    }
}

impl Clone for DestContainer {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            key_manager: self.key_manager.clone(),
            connection_manager: self.connection_manager.clone(),
            service_registry: self.service_registry.clone(),
            frame_codec: self.frame_codec.clone(),
            shutdown: self.shutdown.clone(),
            metrics: self.metrics.clone(),
            health_monitor: self.health_monitor.clone(),
            target_connections: self.target_connections.clone(),
            response_tx: self.response_tx.clone(),
            max_handshake_size: self.max_handshake_size,
            channel_size: self.channel_size,
            port_watcher: self.port_watcher.clone(),
            handshake_material: self.handshake_material.clone(),
            handshake_limiter: self.handshake_limiter.clone(),
            handshake_attempts: self.handshake_attempts.clone(),
        }
    }
}

fn load_server_handshake_material(
    config: &DestConfig,
) -> Result<ServerHandshakeMaterial, DestError> {
    use crate::crypto::file_access::validate_file_access;

    validate_file_access(&config.server_cert_path, &config.server_key_path, "server")
        .map_err(|e| DestError::ConfigError(e.to_string()))?;

    let server_cert = std::fs::read(&config.server_cert_path)
        .map_err(|e| DestError::ConfigError(format!("Failed to read server cert: {}", e)))?;
    let server_key = std::fs::read(&config.server_key_path)
        .map_err(|e| DestError::ConfigError(format!("Failed to read server key: {}", e)))?;
    let ca_cert = std::fs::read(&config.ca_cert_path)
        .map_err(|e| DestError::ConfigError(format!("Failed to read CA cert: {}", e)))?;

    Ok(ServerHandshakeMaterial {
        server_cert: Arc::<[u8]>::from(server_cert),
        server_key: Arc::<[u8]>::from(server_key),
        ca_cert: Arc::<[u8]>::from(ca_cert),
    })
}

impl DestContainer {
    async fn process_connect_request(
        &self,
        connection_id: u32,
        port: u16,
        protocol: Protocol,
        service: ServiceConfig,
        response_tx: mpsc::Sender<Frame>,
    ) {
        let connection_manager = self.connection_manager.clone();
        let metrics = self.metrics.clone();
        let target_addr = format!("{}:{}", service.target_ip, service.target_port);
        let connect_timeout = Duration::from_millis(self.config.target_connect_timeout_ms);
        let deadline = Instant::now() + connect_timeout;

        let target_stream = match self
            .connect_target_with_recovery(&target_addr, deadline)
            .await
        {
            Ok(stream) => stream,
            Err(err) => {
                tracing::error!("Failed to connect to target {}: {}", target_addr, err);
                let _ = response_tx
                    .send(Frame::new_connect_ack(connection_id, false))
                    .await;
                return;
            }
        };

        target_stream.set_nodelay(true).ok();

        let parsed_addr = match target_addr.parse() {
            Ok(addr) => addr,
            Err(e) => {
                tracing::error!("Invalid target address {}: {}", target_addr, e);
                let _ = response_tx
                    .send(Frame::new_connect_ack(connection_id, false))
                    .await;
                return;
            }
        };

        let conn_result = connection_manager
            .create_connection_with_id(connection_id, parsed_addr, protocol, port)
            .await;

        let (conn, _tx, _rx) = match conn_result {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to create connection: {}", e);
                let _ = response_tx
                    .send(Frame::new_connect_ack(connection_id, false))
                    .await;
                return;
            }
        };

        let (target_read, target_write) = target_stream.into_split();
        {
            let mut connections = self.target_connections.write().await;
            connections.insert(
                connection_id,
                Arc::new(TargetConnection {
                    writer: Mutex::new(target_write),
                }),
            );
        }

        let response_tx_clone = response_tx.clone();
        let target_connections = self.target_connections.clone();
        let conn_clone = conn.clone();
        let cm_clone = connection_manager.clone();

        tokio::spawn(async move {
            let mut target_read = target_read;
            let mut buf = vec![0u8; 8192];

            loop {
                match target_read.read(&mut buf).await {
                    Ok(0) => {
                        if let Ok(mut close_frame) = Frame::new_data(connection_id, 0, &[]) {
                            close_frame.set_fin();
                            let _ = response_tx_clone.send(close_frame).await;
                        }
                        break;
                    }
                    Ok(n) => {
                        conn_clone.record_receive(n);
                        conn_clone.touch();
                        if let Ok(data_frame) = Frame::new_data(connection_id, 0, &buf[..n]) {
                            if response_tx_clone.send(data_frame).await.is_err() {
                                tracing::error!("Failed to send data frame - channel closed");
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Error reading from target {}: {}", connection_id, e);
                        break;
                    }
                }
            }

            {
                let mut connections = target_connections.write().await;
                connections.remove(&connection_id);
            }
            cm_clone.remove_connection(connection_id).await;
        });

        metrics
            .connections_forwarded
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let _ = response_tx
            .send(Frame::new_connect_ack(connection_id, true))
            .await;
    }

    async fn connect_target_with_recovery(
        &self,
        target_addr: &str,
        deadline: Instant,
    ) -> std::io::Result<TcpStream> {
        match connect_with_deadline(target_addr, deadline).await {
            Ok(stream) => Ok(stream),
            Err(initial_err) => {
                tracing::warn!(
                    "Target {} not reachable ({}), waiting for port to become available",
                    target_addr,
                    initial_err
                );

                self.port_watcher
                    .mark_unavailable(target_addr.to_string(), self.shutdown.subscribe())
                    .await;

                if !self
                    .port_watcher
                    .wait_until_ready(target_addr, deadline)
                    .await
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("Target {target_addr} did not become available before timeout"),
                    ));
                }

                match connect_with_deadline(target_addr, deadline).await {
                    Ok(stream) => Ok(stream),
                    Err(err) => {
                        self.port_watcher
                            .mark_unavailable(target_addr.to_string(), self.shutdown.subscribe())
                            .await;
                        Err(err)
                    }
                }
            }
        }
    }
}

async fn connect_with_deadline(target_addr: &str, deadline: Instant) -> std::io::Result<TcpStream> {
    match timeout_at(deadline, TcpStream::connect(target_addr)).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("Timed out connecting to {target_addr}"),
        )),
    }
}
