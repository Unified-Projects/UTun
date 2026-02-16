use super::{Frame, Protocol};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::{mpsc, RwLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Connecting = 0,
    Handshaking = 1,
    Established = 2,
    Closing = 3,
    Closed = 4,
}

impl ConnectionState {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Connecting,
            1 => Self::Handshaking,
            2 => Self::Established,
            3 => Self::Closing,
            _ => Self::Closed,
        }
    }
}

#[allow(dead_code)] // Fields used by public API methods
pub struct Connection {
    id: u32,
    remote_addr: SocketAddr,
    state: AtomicU8,
    epoch: Instant,
    last_activity_us: AtomicU64,
    bytes_received: AtomicU64,
    bytes_sent: AtomicU64,
    service_name: RwLock<Option<String>>,
    target_addr: RwLock<Option<SocketAddr>>,
    tx_to_tunnel: mpsc::Sender<Frame>,
    pub rx_from_tunnel: RwLock<Option<mpsc::Receiver<Frame>>>,
}

impl Connection {
    pub fn new(
        id: u32,
        remote_addr: SocketAddr,
        _protocol: Protocol,
        _service_port: u16,
    ) -> (Self, mpsc::Sender<Frame>, mpsc::Receiver<Frame>) {
        Self::new_with_channel_size(id, remote_addr, _protocol, _service_port, 1024)
    }

    pub fn new_with_channel_size(
        id: u32,
        remote_addr: SocketAddr,
        _protocol: Protocol,
        _service_port: u16,
        channel_size: usize,
    ) -> (Self, mpsc::Sender<Frame>, mpsc::Receiver<Frame>) {
        let (tx_to_tunnel, rx_to_tunnel) = mpsc::channel(channel_size);
        let (tx_from_tunnel, rx_from_tunnel) = mpsc::channel(channel_size);

        let conn = Self {
            id,
            remote_addr,
            state: AtomicU8::new(ConnectionState::Connecting as u8),
            epoch: Instant::now(),
            last_activity_us: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            service_name: RwLock::new(None),
            target_addr: RwLock::new(None),
            tx_to_tunnel,
            rx_from_tunnel: RwLock::new(Some(rx_from_tunnel)),
        };

        (conn, tx_from_tunnel, rx_to_tunnel)
    }

    pub fn set_state(&self, state: ConnectionState) {
        self.state.store(state as u8, Ordering::Relaxed);
    }

    pub fn state(&self) -> ConnectionState {
        ConnectionState::from_u8(self.state.load(Ordering::Relaxed))
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

    #[allow(dead_code)] // Public API method
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    #[allow(dead_code)] // Public API method
    pub async fn set_service(&self, name: String, target: SocketAddr) {
        let mut sn = self.service_name.write().await;
        *sn = Some(name);
        let mut ta = self.target_addr.write().await;
        *ta = Some(target);
    }

    #[allow(dead_code)] // Public API method
    pub async fn service_name(&self) -> Option<String> {
        self.service_name.read().await.clone()
    }

    #[allow(dead_code)] // Public API method
    pub async fn target_addr(&self) -> Option<SocketAddr> {
        *self.target_addr.read().await
    }

    #[allow(dead_code)] // Public API method
    pub async fn send_to_tunnel(&self, frame: Frame) -> Result<(), ConnectionError> {
        self.tx_to_tunnel
            .send(frame)
            .await
            .map_err(|_| ConnectionError::ChannelClosed)
    }

    #[allow(dead_code)] // Public API method
    pub async fn recv_from_tunnel(&self) -> Result<Frame, ConnectionError> {
        let mut rx_guard = self.rx_from_tunnel.write().await;
        if let Some(ref mut rx) = *rx_guard {
            rx.recv().await.ok_or(ConnectionError::ChannelClosed)
        } else {
            Err(ConnectionError::ChannelClosed)
        }
    }

    pub fn touch(&self) {
        let us = self.epoch.elapsed().as_micros() as u64;
        self.last_activity_us.store(us, Ordering::Relaxed);
    }

    pub fn is_idle(&self, timeout: Duration) -> bool {
        let last_us = self.last_activity_us.load(Ordering::Relaxed);
        let now_us = self.epoch.elapsed().as_micros() as u64;
        now_us.saturating_sub(last_us) > timeout.as_micros() as u64
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

    #[error("Duplicate connection ID: {0}")]
    DuplicateId(u32),

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
    channel_size: usize,
}

impl ConnectionManager {
    pub fn new(max_connections: usize, connection_timeout_ms: u64) -> Self {
        Self::new_with_channel_size(max_connections, connection_timeout_ms, 1024)
    }

    pub fn new_with_channel_size(
        max_connections: usize,
        connection_timeout_ms: u64,
        channel_size: usize,
    ) -> Self {
        Self {
            next_id: AtomicU32::new(1),
            connections: RwLock::new(HashMap::new()),
            max_connections,
            connection_timeout: Duration::from_millis(connection_timeout_ms),
            channel_size,
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
        let (conn, tx, rx) = Connection::new_with_channel_size(
            id,
            remote_addr,
            protocol,
            service_port,
            self.channel_size,
        );
        let conn = Arc::new(conn);

        connections.insert(id, conn.clone());

        Ok((conn, tx, rx))
    }

    /// Create a connection with a caller-provided ID instead of auto-generating one.
    /// Used by the dest side to keep IDs consistent with the source's connection_id.
    pub async fn create_connection_with_id(
        &self,
        id: u32,
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

        if connections.contains_key(&id) {
            return Err(ConnectionError::DuplicateId(id));
        }

        let (conn, tx, rx) = Connection::new_with_channel_size(
            id,
            remote_addr,
            protocol,
            service_port,
            self.channel_size,
        );
        let conn = Arc::new(conn);

        connections.insert(id, conn.clone());

        Ok((conn, tx, rx))
    }

    pub async fn get_connection(&self, id: u32) -> Option<Arc<Connection>> {
        let connections = self.connections.read().await;
        connections.get(&id).cloned()
    }

    pub async fn remove_connection(&self, id: u32) {
        let mut connections = self.connections.write().await;
        connections.remove(&id);
    }

    /// Remove stale connections (closed or idle past timeout).
    /// Returns the IDs of removed connections so callers can sync other data structures.
    pub async fn cleanup_stale(&self) -> Vec<u32> {
        let to_remove: Vec<u32> = {
            let connections = self.connections.read().await;
            connections
                .iter()
                .filter(|(_, conn)| {
                    conn.state() == ConnectionState::Closed || conn.is_idle(self.connection_timeout)
                })
                .map(|(id, _)| *id)
                .collect()
        };

        if !to_remove.is_empty() {
            let mut connections = self.connections.write().await;
            for id in &to_remove {
                connections.remove(id);
            }
        }

        to_remove
    }

    pub async fn connection_count(&self) -> usize {
        let connections = self.connections.read().await;
        connections.len()
    }

    pub async fn close_all(&self) {
        let mut connections = self.connections.write().await;
        for (_, conn) in connections.iter() {
            conn.set_state(ConnectionState::Closed);
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

        assert_eq!(conn.state(), ConnectionState::Connecting);
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

        conn.set_state(ConnectionState::Closed);

        let removed = cm.cleanup_stale().await;
        assert_eq!(removed.len(), 1);
        assert_eq!(cm.connection_count().await, 0);
    }

    #[tokio::test]
    async fn test_connection_activity() {
        let (conn, _, _) =
            Connection::new(1, "127.0.0.1:8080".parse().unwrap(), Protocol::Tcp, 8080);

        assert!(!conn.is_idle(Duration::from_secs(1)));

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(conn.is_idle(Duration::from_millis(50)));

        conn.touch();
        assert!(!conn.is_idle(Duration::from_secs(1)));
    }

    #[tokio::test]
    async fn test_create_connection_with_id() {
        let cm = ConnectionManager::new(100, 30000);

        // Create with specific ID
        let (conn, _, _) = cm
            .create_connection_with_id(42, "127.0.0.1:8080".parse().unwrap(), Protocol::Tcp, 8080)
            .await
            .unwrap();
        assert_eq!(conn.id(), 42);
        assert_eq!(cm.connection_count().await, 1);

        // Verify lookup works
        let found = cm.get_connection(42).await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().id(), 42);

        // Duplicate ID should be rejected
        let result = cm
            .create_connection_with_id(42, "127.0.0.1:8081".parse().unwrap(), Protocol::Tcp, 8081)
            .await;
        assert!(matches!(result, Err(ConnectionError::DuplicateId(42))));

        // Different ID should work
        let (conn2, _, _) = cm
            .create_connection_with_id(99, "127.0.0.1:8082".parse().unwrap(), Protocol::Tcp, 8082)
            .await
            .unwrap();
        assert_eq!(conn2.id(), 99);
        assert_eq!(cm.connection_count().await, 2);
    }

    #[tokio::test]
    async fn test_cleanup_stale_returns_ids() {
        let cm = ConnectionManager::new(10, 100);

        let (conn1, _, _) = cm
            .create_connection_with_id(10, "127.0.0.1:8080".parse().unwrap(), Protocol::Tcp, 8080)
            .await
            .unwrap();
        let (conn2, _, _) = cm
            .create_connection_with_id(20, "127.0.0.1:8081".parse().unwrap(), Protocol::Tcp, 8081)
            .await
            .unwrap();
        let (_conn3, _, _) = cm
            .create_connection_with_id(30, "127.0.0.1:8082".parse().unwrap(), Protocol::Tcp, 8082)
            .await
            .unwrap();

        assert_eq!(cm.connection_count().await, 3);

        // Mark two as closed
        conn1.set_state(ConnectionState::Closed);
        conn2.set_state(ConnectionState::Closed);

        let mut removed = cm.cleanup_stale().await;
        removed.sort();
        assert_eq!(removed, vec![10, 20]);
        assert_eq!(cm.connection_count().await, 1);

        // The remaining connection should still be findable
        let found = cm.get_connection(30).await;
        assert!(found.is_some());
    }

    #[tokio::test]
    async fn test_idle_timeout_cleanup() {
        // Very short timeout (50ms)
        let cm = ConnectionManager::new(10, 50);

        let (_conn, _, _) = cm
            .create_connection_with_id(1, "127.0.0.1:8080".parse().unwrap(), Protocol::Tcp, 8080)
            .await
            .unwrap();

        assert_eq!(cm.connection_count().await, 1);

        // Wait for idle timeout
        tokio::time::sleep(Duration::from_millis(100)).await;

        let removed = cm.cleanup_stale().await;
        assert_eq!(removed, vec![1]);
        assert_eq!(cm.connection_count().await, 0);
    }
}
