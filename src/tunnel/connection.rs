use super::{Frame, Protocol};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::{mpsc, RwLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Connecting,
    Handshaking,
    Established,
    Closing,
    Closed,
}

pub struct Connection {
    id: u32,
    remote_addr: SocketAddr,
    state: RwLock<ConnectionState>,
    last_activity: RwLock<Instant>,
    bytes_received: AtomicU64,
    bytes_sent: AtomicU64,
    service_name: RwLock<Option<String>>,
    target_addr: RwLock<Option<SocketAddr>>,
    tx_to_tunnel: mpsc::Sender<Frame>,
    rx_from_tunnel: RwLock<Option<mpsc::Receiver<Frame>>>,
}

impl Connection {
    pub fn new(
        id: u32,
        remote_addr: SocketAddr,
        _protocol: Protocol,
        _service_port: u16,
    ) -> (Self, mpsc::Sender<Frame>, mpsc::Receiver<Frame>) {
        let (tx_to_tunnel, rx_to_tunnel) = mpsc::channel(100);
        let (tx_from_tunnel, rx_from_tunnel) = mpsc::channel(100);

        let conn = Self {
            id,
            remote_addr,
            state: RwLock::new(ConnectionState::Connecting),
            last_activity: RwLock::new(Instant::now()),
            bytes_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            service_name: RwLock::new(None),
            target_addr: RwLock::new(None),
            tx_to_tunnel,
            rx_from_tunnel: RwLock::new(Some(rx_from_tunnel)),
        };

        (conn, tx_from_tunnel, rx_to_tunnel)
    }

    pub async fn set_state(&self, state: ConnectionState) {
        let mut s = self.state.write().await;
        *s = state;
    }

    pub async fn state(&self) -> ConnectionState {
        *self.state.read().await
    }

    pub fn record_send(&self, bytes: usize) {
        self.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_receive(&self, bytes: usize) {
        self.bytes_received
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }

    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    pub async fn set_service(&self, name: String, target: SocketAddr) {
        let mut sn = self.service_name.write().await;
        *sn = Some(name);
        let mut ta = self.target_addr.write().await;
        *ta = Some(target);
    }

    pub async fn service_name(&self) -> Option<String> {
        self.service_name.read().await.clone()
    }

    pub async fn target_addr(&self) -> Option<SocketAddr> {
        *self.target_addr.read().await
    }

    pub async fn send_to_tunnel(&self, frame: Frame) -> Result<(), ConnectionError> {
        self.tx_to_tunnel
            .send(frame)
            .await
            .map_err(|_| ConnectionError::ChannelClosed)
    }

    pub async fn recv_from_tunnel(&self) -> Result<Frame, ConnectionError> {
        let mut rx_guard = self.rx_from_tunnel.write().await;
        if let Some(ref mut rx) = *rx_guard {
            rx.recv().await.ok_or(ConnectionError::ChannelClosed)
        } else {
            Err(ConnectionError::ChannelClosed)
        }
    }

    pub async fn touch(&self) {
        let mut last = self.last_activity.write().await;
        *last = Instant::now();
    }

    pub async fn is_idle(&self, timeout: Duration) -> bool {
        let last = self.last_activity.read().await;
        last.elapsed() > timeout
    }
}

#[derive(Debug, Error)]
pub enum ConnectionError {
    #[error("Connection timeout")]
    Timeout,

    #[error("Connection reset by peer")]
    Reset,

    #[error("Connection limit exceeded: max {max}")]
    LimitExceeded { max: usize },

    #[error("Invalid state: expected {expected:?}, got {got:?}")]
    InvalidState {
        expected: ConnectionState,
        got: ConnectionState,
    },

    #[error("Connection not found: {0}")]
    NotFound(u32),

    #[error("Service not found: port {0}")]
    ServiceNotFound(u16),

    #[error("Channel closed")]
    ChannelClosed,

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub struct ConnectionManager {
    next_id: AtomicU32,
    connections: RwLock<HashMap<u32, Arc<Connection>>>,
    max_connections: usize,
    connection_timeout: Duration,
}

impl ConnectionManager {
    pub fn new(max_connections: usize, connection_timeout_ms: u64) -> Self {
        Self {
            next_id: AtomicU32::new(1),
            connections: RwLock::new(HashMap::new()),
            max_connections,
            connection_timeout: Duration::from_millis(connection_timeout_ms),
        }
    }

    pub async fn create_connection(
        &self,
        remote_addr: SocketAddr,
        protocol: Protocol,
        service_port: u16,
    ) -> Result<(Arc<Connection>, mpsc::Sender<Frame>, mpsc::Receiver<Frame>), ConnectionError>
    {
        let mut connections = self.connections.write().await;

        if connections.len() >= self.max_connections {
            return Err(ConnectionError::LimitExceeded {
                max: self.max_connections,
            });
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (conn, tx, rx) = Connection::new(id, remote_addr, protocol, service_port);
        let conn = Arc::new(conn);

        connections.insert(id, conn.clone());

        Ok((conn, tx, rx))
    }

    pub async fn remove_connection(&self, id: u32) {
        let mut connections = self.connections.write().await;
        connections.remove(&id);
    }

    pub async fn cleanup_stale(&self) -> usize {
        let mut connections = self.connections.write().await;
        let mut to_remove = Vec::new();

        for (id, conn) in connections.iter() {
            let state = conn.state().await;
            let is_idle = conn.is_idle(self.connection_timeout).await;

            if state == ConnectionState::Closed || is_idle {
                to_remove.push(*id);
            }
        }

        for id in &to_remove {
            connections.remove(id);
        }

        to_remove.len()
    }

    pub async fn connection_count(&self) -> usize {
        let connections = self.connections.read().await;
        connections.len()
    }

    pub async fn close_all(&self) {
        let mut connections = self.connections.write().await;
        for (_, conn) in connections.iter() {
            conn.set_state(ConnectionState::Closed).await;
        }
        connections.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_connection_lifecycle() {
        let cm = ConnectionManager::new(100, 30000);
        let (conn, _, _) = cm
            .create_connection("127.0.0.1:8080".parse().unwrap(), Protocol::Tcp, 8080)
            .await
            .unwrap();

        assert_eq!(conn.state().await, ConnectionState::Connecting);
        assert_eq!(conn.bytes_sent(), 0);
        assert_eq!(conn.bytes_received(), 0);

        conn.record_send(100);
        conn.record_receive(200);

        assert_eq!(conn.bytes_sent(), 100);
        assert_eq!(conn.bytes_received(), 200);
    }

    #[tokio::test]
    async fn test_connection_limit() {
        let cm = ConnectionManager::new(1, 30000);
        let _ = cm
            .create_connection("127.0.0.1:8080".parse().unwrap(), Protocol::Tcp, 8080)
            .await
            .unwrap();

        let result = cm
            .create_connection("127.0.0.1:8081".parse().unwrap(), Protocol::Tcp, 8081)
            .await;

        assert!(matches!(result, Err(ConnectionError::LimitExceeded { .. })));
    }

    #[tokio::test]
    async fn test_connection_cleanup() {
        let cm = ConnectionManager::new(10, 100);
        let (conn, _, _) = cm
            .create_connection("127.0.0.1:8080".parse().unwrap(), Protocol::Tcp, 8080)
            .await
            .unwrap();

        assert_eq!(cm.connection_count().await, 1);

        conn.set_state(ConnectionState::Closed).await;

        let removed = cm.cleanup_stale().await;
        assert_eq!(removed, 1);
        assert_eq!(cm.connection_count().await, 0);
    }

    #[tokio::test]
    async fn test_connection_activity() {
        let (conn, _, _) =
            Connection::new(1, "127.0.0.1:8080".parse().unwrap(), Protocol::Tcp, 8080);

        assert!(!conn.is_idle(Duration::from_secs(1)).await);

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(conn.is_idle(Duration::from_millis(50)).await);

        conn.touch().await;
        assert!(!conn.is_idle(Duration::from_secs(1)).await);
    }
}
