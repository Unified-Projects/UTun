use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

const UDP_BUFFER_SIZE: usize = 9000;

#[derive(Debug, Error)]
pub enum UdpProxyError {
    #[error("Socket bind failed: {0}")]
    BindFailed(String),

    #[error("No available port in range")]
    NoPortAvailable,

    #[error("Association expired: {0}")]
    AssociationExpired(u32),

    #[error("Association limit exceeded")]
    AssociationLimitExceeded,

    #[error("Send failed: {0}")]
    SendFailed(String),

    #[error("Packet too large: {0} bytes")]
    PacketTooLarge(usize),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

#[derive(Debug)]
pub struct UdpAssociationStats {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub duration: Duration,
}

#[derive(Debug, Clone)]
pub struct UdpAssociation {
    id: u32,
    client_addr: SocketAddr,
    server_socket: Arc<UdpSocket>,
    target_addr: SocketAddr,
    created_at: Instant,
    last_activity: Instant,
    packets_sent: u64,
    packets_received: u64,
    bytes_sent: u64,
    bytes_received: u64,
}

impl UdpAssociation {
    pub async fn new(
        id: u32,
        client_addr: SocketAddr,
        target_addr: SocketAddr,
    ) -> Result<Self, UdpProxyError> {
        let bind_addr: SocketAddr = if target_addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };

        let server_socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| UdpProxyError::BindFailed(e.to_string()))?;

        let now = Instant::now();

        Ok(Self {
            id,
            client_addr,
            server_socket: Arc::new(server_socket),
            target_addr,
            created_at: now,
            last_activity: now,
            packets_sent: 0,
            packets_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
        })
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn client_addr(&self) -> SocketAddr {
        self.client_addr
    }

    pub fn target_addr(&self) -> SocketAddr {
        self.target_addr
    }

    pub fn refresh(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }

    pub async fn send_to_target(&mut self, data: &[u8]) -> Result<(), UdpProxyError> {
        self.server_socket
            .send_to(data, self.target_addr)
            .await
            .map_err(|e| UdpProxyError::SendFailed(e.to_string()))?;

        self.packets_sent += 1;
        self.bytes_sent += data.len() as u64;
        self.refresh();

        Ok(())
    }

    pub async fn recv_from_target(&self) -> Result<(Vec<u8>, SocketAddr), UdpProxyError> {
        let mut buf = vec![0u8; UDP_BUFFER_SIZE]; // Much smaller than 65535
        let (len, addr) = self.server_socket.recv_from(&mut buf).await?;

        // Validate reasonable packet size
        if len > UDP_BUFFER_SIZE {
            return Err(UdpProxyError::PacketTooLarge(len));
        }

        buf.truncate(len);
        Ok((buf, addr))
    }

    pub fn stats(&self) -> UdpAssociationStats {
        UdpAssociationStats {
            packets_sent: self.packets_sent,
            packets_received: self.packets_received,
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
            duration: self.created_at.elapsed(),
        }
    }
}

impl Drop for UdpAssociation {
    fn drop(&mut self) {
        // Explicitly close socket and log for monitoring
        tracing::trace!("Dropping UDP association {}", self.id);
        // Socket automatically closed by Drop, but log for monitoring
    }
}

pub struct UdpProxyConfig {
    pub listen_addr: SocketAddr,
    pub association_timeout: Duration,
    pub max_associations: usize,
    pub buffer_size: usize,
    pub cleanup_interval: Duration,
}

impl Default for UdpProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8443".parse().unwrap(),
            association_timeout: Duration::from_secs(300),
            max_associations: 10000,
            buffer_size: 65535,
            cleanup_interval: Duration::from_secs(60),
        }
    }
}

pub struct UdpProxy {
    config: UdpProxyConfig,
    socket: Option<Arc<UdpSocket>>,
    associations: Arc<RwLock<HashMap<SocketAddr, UdpAssociation>>>,
    next_association_id: AtomicU32,
    cleanup_handle: Option<JoinHandle<()>>,
}

impl UdpProxy {
    pub fn new(config: UdpProxyConfig) -> Self {
        Self {
            config,
            socket: None,
            associations: Arc::new(RwLock::new(HashMap::new())),
            next_association_id: AtomicU32::new(1),
            cleanup_handle: None,
        }
    }

    pub async fn start(&mut self) -> Result<(), UdpProxyError> {
        let socket = UdpSocket::bind(self.config.listen_addr)
            .await
            .map_err(|e| UdpProxyError::BindFailed(e.to_string()))?;

        self.socket = Some(Arc::new(socket));

        let associations = Arc::clone(&self.associations);
        let timeout = self.config.association_timeout;
        let cleanup_interval = self.config.cleanup_interval;

        let cleanup_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            loop {
                interval.tick().await;

                // Collect expired addresses without holding write lock
                let expired: Vec<_> = {
                    let assocs = associations.read().await;
                    assocs
                        .iter()
                        .filter(|(_, a)| a.is_expired(timeout))
                        .map(|(&k, _)| k)
                        .collect()
                };

                // Only acquire write lock for removal
                if !expired.is_empty() {
                    let count = expired.len();
                    let mut assocs = associations.write().await;
                    for addr in expired {
                        assocs.remove(&addr);
                    }
                    tracing::debug!("Cleaned up {} expired UDP associations", count);
                }
            }
        });

        self.cleanup_handle = Some(cleanup_handle);

        Ok(())
    }

    pub async fn stop(&mut self) {
        if let Some(handle) = self.cleanup_handle.take() {
            handle.abort();
        }
        self.socket = None;
        self.associations.write().await.clear();
    }

    pub async fn get_or_create_association(
        &self,
        client_addr: SocketAddr,
        target_addr: SocketAddr,
    ) -> Result<UdpAssociation, UdpProxyError> {
        // Hold write lock for entire operation to prevent TOCTOU
        let mut assocs = self.associations.write().await;

        // Check for existing association
        if let Some(assoc) = assocs.get_mut(&client_addr) {
            assoc.refresh();
            return Ok(assoc.clone());
        }

        // Check limit while still holding lock
        if assocs.len() >= self.config.max_associations {
            return Err(UdpProxyError::AssociationLimitExceeded);
        }

        // Create new association while holding lock
        // Note: This does I/O (socket bind) while holding the lock, which is not ideal
        // for performance but is necessary for security. The socket bind is fast.
        let id = self.next_association_id.fetch_add(1, Ordering::Relaxed);
        let assoc = UdpAssociation::new(id, client_addr, target_addr).await?;

        // Insert while still holding lock - no gap for race condition
        assocs.insert(client_addr, assoc.clone());

        Ok(assoc)
    }

    pub async fn remove_association(&self, client_addr: &SocketAddr) {
        self.associations.write().await.remove(client_addr);
    }

    pub async fn handle_client_packet(
        &self,
        data: &[u8],
        client_addr: SocketAddr,
        target_addr: SocketAddr,
    ) -> Result<(), UdpProxyError> {
        let mut assoc = self
            .get_or_create_association(client_addr, target_addr)
            .await?;
        assoc.send_to_target(data).await?;

        let mut assocs = self.associations.write().await;
        if let Some(existing) = assocs.get_mut(&client_addr) {
            existing.packets_sent = assoc.packets_sent;
            existing.bytes_sent = assoc.bytes_sent;
            existing.refresh();
        }

        Ok(())
    }

    pub async fn handle_target_response(
        &self,
        data: &[u8],
        client_addr: SocketAddr,
    ) -> Result<(), UdpProxyError> {
        let socket = self
            .socket
            .as_ref()
            .ok_or_else(|| UdpProxyError::BindFailed("Socket not initialized".to_string()))?;

        socket.send_to(data, client_addr).await?;

        let mut assocs = self.associations.write().await;
        if let Some(assoc) = assocs.get_mut(&client_addr) {
            assoc.packets_received += 1;
            assoc.bytes_received += data.len() as u64;
            assoc.refresh();
        }

        Ok(())
    }

    pub async fn run(&self, mut shutdown: watch::Receiver<bool>) -> Result<(), UdpProxyError> {
        let socket = self
            .socket
            .as_ref()
            .ok_or_else(|| UdpProxyError::BindFailed("Socket not initialized".to_string()))?;

        let mut buf = vec![0u8; self.config.buffer_size];

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    break;
                }
                result = socket.recv_from(&mut buf) => {
                    let (_len, _addr) = result?;
                }
            }
        }

        Ok(())
    }

    pub async fn association_count(&self) -> usize {
        self.associations.read().await.len()
    }
}
