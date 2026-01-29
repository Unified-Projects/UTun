use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, RwLock};
use tokio::time::{timeout, Duration};

// Maximum frame size to prevent memory exhaustion (1MB)
const MAX_FRAME_SIZE: u32 = 1024 * 1024;

// Maximum handshake message size (64KB)
const MAX_HANDSHAKE_SIZE: u32 = 64 * 1024;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);

// Frame read timeout (30 seconds)
const FRAME_READ_TIMEOUT: Duration = Duration::from_secs(30);
use super::{
    ConnectionError, ConnectionManager, Frame, FrameCodec, FrameError, FrameType, HandshakeContext,
    HandshakeError, Protocol,
};
use crate::config::SourceConfig;
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

pub struct SourceContainer {
    config: SourceConfig,
    key_manager: Arc<KeyManager>,
    connection_manager: Arc<ConnectionManager>,
    frame_codec: Arc<RwLock<Option<Arc<FrameCodec>>>>,
    tunnel_stream: Arc<RwLock<Option<TcpStream>>>,
    shutdown: watch::Sender<bool>,
    metrics: Arc<SourceMetrics>,
    health_monitor: Arc<HealthMonitor>,
}

impl SourceContainer {
    pub async fn new(config: SourceConfig) -> Result<Self, SourceError> {
        let key_manager = Arc::new(KeyManager::new(3600, 300)); // 1 hour rotation, 5 min window
        let connection_manager = Arc::new(ConnectionManager::new(
            config.max_connections,
            config.connection_timeout_ms,
        ));

        let (shutdown_tx, _) = watch::channel(false);

        let health_monitor = Arc::new(HealthMonitor::new());
        // Set initial status to Starting
        health_monitor.set_status(HealthStatus::Starting).await;

        Ok(Self {
            config,
            key_manager,
            connection_manager,
            frame_codec: Arc::new(RwLock::new(None)),
            tunnel_stream: Arc::new(RwLock::new(None)),
            shutdown: shutdown_tx,
            metrics: Arc::new(SourceMetrics::new()),
            health_monitor,
        })
    }

    pub async fn start(&self) -> Result<(), SourceError> {
        tracing::info!("Starting source container");

        // Connect to destination
        self.connect_to_dest().await?;

        // Perform handshake
        self.perform_handshake().await?;

        tracing::info!("Source container started successfully");
        Ok(())
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

            if len > MAX_HANDSHAKE_SIZE {
                return Err(SourceError::FrameTooLarge {
                    size: len,
                    max: MAX_HANDSHAKE_SIZE,
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

            if len > MAX_HANDSHAKE_SIZE {
                return Err(SourceError::FrameTooLarge {
                    size: len,
                    max: MAX_HANDSHAKE_SIZE,
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

    pub async fn handle_client(
        &self,
        mut stream: TcpStream,
        addr: SocketAddr,
    ) -> Result<(), SourceError> {
        tracing::info!("New client connection from {}", addr);

        // For now, use port 0 as a placeholder - this would come from config
        let (conn, _tx_from_tunnel, mut rx_to_tunnel) = self
            .connection_manager
            .create_connection(addr, Protocol::Tcp, 0)
            .await?;

        // Send CONNECT frame
        let connect_frame = Frame::new_connect(conn.id(), 22, Protocol::Tcp); // SSH example
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

        Ok(frame)
    }

    pub async fn run(&self) -> Result<(), SourceError> {
        let listener = TcpListener::bind(format!(
            "{}:{}",
            self.config.listen_ip, self.config.listen_port
        ))
        .await?;
        tracing::info!(
            "Listening on {}:{}",
            self.config.listen_ip,
            self.config.listen_port
        );

        let mut shutdown_rx = self.shutdown.subscribe();

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            self.metrics.connections_accepted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                            let self_clone = self.clone();
                            tokio::spawn(async move {
                                if let Err(e) = self_clone.handle_client(stream, addr).await {
                                    tracing::error!("Client handler error: {}", e);
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
        }
    }
}
