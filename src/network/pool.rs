use crate::network::TcpProxyError;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

pub struct PoolConfig {
    pub max_connections_per_target: usize,
    pub max_total_connections: usize,
    pub idle_timeout: Duration,
    pub connect_timeout: Duration,
    pub max_lifetime: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections_per_target: 10,
            max_total_connections: 1000,
            idle_timeout: Duration::from_secs(60),
            connect_timeout: Duration::from_secs(10),
            max_lifetime: Duration::from_secs(3600),
        }
    }
}

pub struct PooledConnection {
    _id: u64,
    stream: TcpStream,
    target: SocketAddr,
    created_at: Instant,
    last_used: Instant,
    use_count: u32,
}

impl PooledConnection {
    pub fn new(id: u64, stream: TcpStream, target: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            _id: id,
            stream,
            target,
            created_at: now,
            last_used: now,
            use_count: 0,
        }
    }

    pub fn is_expired(&self, idle_timeout: Duration, max_lifetime: Duration) -> bool {
        self.last_used.elapsed() > idle_timeout || self.created_at.elapsed() > max_lifetime
    }

    pub fn is_healthy(&self) -> bool {
        self.stream.peer_addr().is_ok()
    }

    pub fn touch(&mut self) {
        self.last_used = Instant::now();
        self.use_count += 1;
    }

    pub fn stream(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    pub fn into_stream(self) -> TcpStream {
        self.stream
    }
}

pub struct PoolStats {
    pub total_connections: u64,
    pub idle_connections: u64,
    pub total_created: u64,
    pub total_reused: u64,
    pub targets: usize,
}

pub struct ConnectionPool {
    config: PoolConfig,
    pools: Arc<RwLock<HashMap<SocketAddr, VecDeque<PooledConnection>>>>,
    next_id: AtomicU64,
    total_connections: Arc<AtomicU64>,
    total_created: Arc<AtomicU64>,
    total_reused: Arc<AtomicU64>,
    cleanup_handle: Option<JoinHandle<()>>,
}

impl ConnectionPool {
    pub fn new(config: PoolConfig) -> Self {
        Self {
            config,
            pools: Arc::new(RwLock::new(HashMap::new())),
            next_id: AtomicU64::new(1),
            total_connections: Arc::new(AtomicU64::new(0)),
            total_created: Arc::new(AtomicU64::new(0)),
            total_reused: Arc::new(AtomicU64::new(0)),
            cleanup_handle: None,
        }
    }

    pub async fn get(&self, target: SocketAddr) -> Result<PooledConnection, TcpProxyError> {
        {
            let mut pools = self.pools.write().await;
            if let Some(pool) = pools.get_mut(&target) {
                while let Some(mut conn) = pool.pop_front() {
                    if !conn.is_expired(self.config.idle_timeout, self.config.max_lifetime)
                        && conn.is_healthy()
                    {
                        conn.touch();
                        self.total_reused.fetch_add(1, Ordering::Relaxed);
                        return Ok(conn);
                    }
                }
            }
        }

        self.create_connection(target).await
    }

    pub async fn put(&self, conn: PooledConnection) {
        if conn.is_expired(self.config.idle_timeout, self.config.max_lifetime) || !conn.is_healthy()
        {
            self.total_connections.fetch_sub(1, Ordering::Relaxed);
            return;
        }

        let target = conn.target;
        let mut pools = self.pools.write().await;
        let pool = pools.entry(target).or_insert_with(VecDeque::new);

        if pool.len() < self.config.max_connections_per_target {
            pool.push_back(conn);
        } else {
            self.total_connections.fetch_sub(1, Ordering::Relaxed);
        }
    }

    async fn create_connection(
        &self,
        target: SocketAddr,
    ) -> Result<PooledConnection, TcpProxyError> {
        // Atomically try to reserve a connection slot
        let max_connections = self.config.max_total_connections as u64;
        loop {
            let current_total = self.total_connections.load(Ordering::SeqCst);
            if current_total >= max_connections {
                return Err(TcpProxyError::ConnectionFailed(
                    "Pool connection limit exceeded".to_string(),
                ));
            }

            // Try to atomically increment the counter
            // If another thread changed it, retry the loop
            match self.total_connections.compare_exchange_weak(
                current_total,
                current_total + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(_) => continue, // Another thread modified counter, retry
            }
        }

        // We've successfully reserved a slot, now try to connect
        let connect_result =
            tokio::time::timeout(self.config.connect_timeout, TcpStream::connect(target)).await;

        match connect_result {
            Ok(Ok(stream)) => {
                let id = self.next_id.fetch_add(1, Ordering::Relaxed);
                let conn = PooledConnection::new(id, stream, target);
                self.total_created.fetch_add(1, Ordering::Relaxed);
                Ok(conn)
            }
            Ok(Err(e)) => {
                // Connection failed, release the reserved slot
                self.total_connections.fetch_sub(1, Ordering::SeqCst);
                Err(TcpProxyError::ConnectionFailed(e.to_string()))
            }
            Err(_) => {
                // Timeout, release the reserved slot
                self.total_connections.fetch_sub(1, Ordering::SeqCst);
                Err(TcpProxyError::Timeout(self.config.connect_timeout))
            }
        }
    }

    pub fn start_cleanup_task(&mut self, interval: Duration) {
        let pools = Arc::clone(&self.pools);
        let idle_timeout = self.config.idle_timeout;
        let max_lifetime = self.config.max_lifetime;
        let total_connections = Arc::clone(&self.total_connections);

        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;

                let mut pools_lock = pools.write().await;
                let mut removed = 0;

                for pool in pools_lock.values_mut() {
                    let initial_len = pool.len();
                    pool.retain(|conn| {
                        !conn.is_expired(idle_timeout, max_lifetime) && conn.is_healthy()
                    });
                    removed += initial_len - pool.len();
                }

                pools_lock.retain(|_, pool| !pool.is_empty());
                drop(pools_lock);

                total_connections.fetch_sub(removed as u64, Ordering::Relaxed);
            }
        });

        self.cleanup_handle = Some(handle);
    }

    pub fn stats(&self) -> PoolStats {
        PoolStats {
            total_connections: self.total_connections.load(Ordering::Relaxed),
            idle_connections: 0,
            total_created: self.total_created.load(Ordering::Relaxed),
            total_reused: self.total_reused.load(Ordering::Relaxed),
            targets: 0,
        }
    }
}
