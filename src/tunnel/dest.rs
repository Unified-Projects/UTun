use super::{
    ConnectionError, ConnectionManager, Frame, FrameCodec, FrameError, FrameType, HandshakeContext,
    HandshakeError, Protocol,
};
use crate::config::{CryptoConfig, DestConfig, ServiceConfig};
use crate::crypto::{DerivedKeyMaterial, KeyManager, SessionCrypto};
use crate::health::{HealthMonitor, HealthStatus};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, RwLock};
use tokio::time::{timeout, Duration};

// Maximum frame size to prevent memory exhaustion (1MB)
const MAX_FRAME_SIZE: u32 = 1024 * 1024;

// Frame read timeout (must exceed heartbeat interval to allow pings during idle periods)
const FRAME_READ_TIMEOUT: Duration = Duration::from_secs(60);

// Handshake timeout per message (increased for large McEliece keys)
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

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

/// Stores the write half of a target connection for forwarding data
struct TargetConnection {
    writer: OwnedWriteHalf,
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
    target_connections: Arc<RwLock<HashMap<u32, TargetConnection>>>,
    /// Channel to send response frames back to the tunnel
    response_tx: Arc<RwLock<Option<mpsc::UnboundedSender<Frame>>>>,
    /// Maximum handshake message size (depends on KEM mode)
    max_handshake_size: u32,
    /// Channel size configuration
    channel_size: usize,
}

impl DestContainer {
    pub async fn new(config: DestConfig, crypto_config: CryptoConfig) -> Result<Self, DestError> {
        let channel_size = config.connection_channel_size;

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

    pub async fn handle_tunnel_connection(
        &self,
        mut stream: TcpStream,
        addr: SocketAddr,
    ) -> Result<(), DestError> {
        tracing::info!("New tunnel connection from {}", addr);
        self.metrics
            .tunnels_accepted
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Perform handshake
        let session_key = self.perform_server_handshake(&mut stream).await?;

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

        // Create channel for response frames from target connections
        // Use unbounded to prevent backpressure deadlock (monitored via metrics)
        let (response_tx, mut response_rx) = mpsc::unbounded_channel::<Frame>();

        // Store the response sender
        {
            let mut tx = self.response_tx.write().await;
            *tx = Some(response_tx.clone());
        }

        // Log channel configuration
        tracing::info!(
            "Response channel configured as unbounded for connection from {}",
            addr
        );

        // Handle incoming frames
        let connection_manager = self.connection_manager.clone();
        let service_registry = self.service_registry.clone();
        let metrics = self.metrics.clone();

        // Split stream for concurrent read/write
        let (mut read_half, mut write_half) = stream.into_split();

        // Spawn writer task to handle response frames
        let frame_codec_clone = frame_codec.clone();
        let writer_handle = tokio::spawn(async move {
            while let Some(frame) = response_rx.recv().await {
                let wire_frame = match frame_codec_clone.encode(&frame) {
                    Ok(w) => w,
                    Err(e) => {
                        tracing::error!("Failed to encode response: {}", e);
                        continue;
                    }
                };

                if let Err(e) = write_half.write_u32(wire_frame.len() as u32).await {
                    tracing::error!("Failed to write response length: {}", e);
                    break;
                }

                if let Err(e) = write_half.write_all(wire_frame.as_bytes()).await {
                    tracing::error!("Failed to write response: {}", e);
                    break;
                }

                if let Err(e) = write_half.flush().await {
                    tracing::error!("Failed to flush: {}", e);
                    break;
                }
            }
        });

        loop {
            // Read frame length with timeout
            let len = match timeout(FRAME_READ_TIMEOUT, read_half.read_u32()).await {
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
            };

            // CRITICAL: Validate size before allocation to prevent memory exhaustion
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

            // Read frame data with timeout
            let mut buf = vec![0u8; len as usize];
            match timeout(FRAME_READ_TIMEOUT, read_half.read_exact(&mut buf)).await {
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

            // Decode frame
            let wire_frame = super::WireFrame::new(buf);
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
                if response_tx.send(resp_frame).is_err() {
                    tracing::error!("Failed to send response - channel closed");
                    break;
                }
            }
        }

        // Clean up: drop sender and wait for writer task
        drop(response_tx);
        let _ = writer_handle.await;

        // Clear target connections
        {
            let mut connections = self.target_connections.write().await;
            connections.clear();
        }

        Ok(())
    }

    async fn perform_server_handshake(&self, stream: &mut TcpStream) -> Result<Vec<u8>, DestError> {
        // Validate certificate access before attempting to read
        use crate::crypto::file_access::validate_file_access;
        validate_file_access(
            &self.config.server_cert_path,
            &self.config.server_key_path,
            "server",
        )
        .map_err(|e| DestError::ConfigError(e.to_string()))?;

        // Load certificates
        let server_cert = std::fs::read(&self.config.server_cert_path)
            .map_err(|e| DestError::ConfigError(format!("Failed to read server cert: {}", e)))?;
        let server_key = std::fs::read(&self.config.server_key_path)
            .map_err(|e| DestError::ConfigError(format!("Failed to read server key: {}", e)))?;
        let ca_cert = std::fs::read(&self.config.ca_cert_path)
            .map_err(|e| DestError::ConfigError(format!("Failed to read CA cert: {}", e)))?;

        let mut handshake_ctx = HandshakeContext::new_server(
            self.key_manager.clone(),
            server_cert,
            server_key,
            ca_cert,
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
        response_tx: &mpsc::UnboundedSender<Frame>,
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
                    Some(s) => s,
                    None => {
                        tracing::error!("Service not found for port {}", port);
                        return Some(Frame::new_connect_ack(connection_id, false));
                    }
                };

                // Connect to target
                let target_addr = format!("{}:{}", service.target_ip, service.target_port);
                let target_stream = match TcpStream::connect(&target_addr).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!("Failed to connect to target: {}", e);
                        return Some(Frame::new_connect_ack(connection_id, false));
                    }
                };

                // Create connection record
                let parsed_addr = match target_addr.parse() {
                    Ok(addr) => addr,
                    Err(e) => {
                        tracing::error!("Invalid target address {}: {}", target_addr, e);
                        return Some(Frame::new_connect_ack(connection_id, false));
                    }
                };

                let conn_result = connection_manager
                    .create_connection(parsed_addr, protocol, port)
                    .await;

                let (conn, _tx, _rx) = match conn_result {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!("Failed to create connection: {}", e);
                        return Some(Frame::new_connect_ack(connection_id, false));
                    }
                };

                // Split target stream for bidirectional forwarding
                let (target_read, target_write) = target_stream.into_split();

                // Store write half for forwarding data TO target
                {
                    let mut connections = self.target_connections.write().await;
                    connections.insert(
                        connection_id,
                        TargetConnection {
                            writer: target_write,
                        },
                    );
                }

                // Spawn task to read FROM target and send back through tunnel
                let response_tx_clone = response_tx.clone();
                let target_connections = self.target_connections.clone();
                let conn_clone = conn.clone();

                tokio::spawn(async move {
                    let mut target_read = target_read;
                    let mut buf = vec![0u8; 8192];

                    loop {
                        match target_read.read(&mut buf).await {
                            Ok(0) => {
                                // Target closed connection, send FIN frame
                                if let Ok(mut close_frame) = Frame::new_data(connection_id, 0, &[])
                                {
                                    close_frame.set_fin();
                                    let _ = response_tx_clone.send(close_frame);
                                }
                                break;
                            }
                            Ok(n) => {
                                // Forward data from target to tunnel
                                conn_clone.record_receive(n);
                                if let Ok(data_frame) = Frame::new_data(connection_id, 0, &buf[..n])
                                {
                                    if response_tx_clone.send(data_frame).is_err() {
                                        tracing::error!(
                                            "Failed to send data frame - channel closed"
                                        );
                                        break;
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::error!(
                                    "Error reading from target {}: {}",
                                    connection_id,
                                    e
                                );
                                break;
                            }
                        }
                    }

                    // Clean up connection
                    let mut connections = target_connections.write().await;
                    connections.remove(&connection_id);
                });

                metrics
                    .connections_forwarded
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                Some(Frame::new_connect_ack(connection_id, true))
            }

            FrameType::Data => {
                // Forward data to target connection
                let connection_id = frame.connection_id();
                let payload = frame.payload();

                if payload.is_empty() && frame.is_fin() {
                    // Close indication
                    let mut connections = self.target_connections.write().await;
                    connections.remove(&connection_id);
                    return None;
                }

                // Look up target connection and forward data
                let mut connections = self.target_connections.write().await;
                if let Some(target_conn) = connections.get_mut(&connection_id) {
                    if let Err(e) = target_conn.writer.write_all(payload).await {
                        tracing::error!("Failed to write to target {}: {}", connection_id, e);
                        connections.remove(&connection_id);
                    } else if let Err(e) = target_conn.writer.flush().await {
                        tracing::error!("Failed to flush target {}: {}", connection_id, e);
                        connections.remove(&connection_id);
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
        // Get the response channel if available
        let response_tx = self.response_tx.read().await;
        if let Some(ref tx) = *response_tx {
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

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            let self_clone = self.clone();
                            tokio::spawn(async move {
                                if let Err(e) = self_clone.handle_tunnel_connection(stream, addr).await {
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
        }
    }
}
