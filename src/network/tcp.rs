use bytes::{Bytes, BytesMut};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

#[derive(Debug, Error)]
pub enum TcpProxyError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Stream closed")]
    StreamClosed,

    #[error("Buffer overflow: {size} exceeds {max}")]
    BufferOverflow { size: usize, max: usize },

    #[error("Timeout after {0:?}")]
    Timeout(Duration),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub struct TcpProxyConfig {
    pub listen_addr: SocketAddr,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub write_timeout: Duration,
    pub max_buffer_size: usize,
    pub keep_alive_interval: Option<Duration>,
    pub nodelay: bool,
}

impl Default for TcpProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8443".parse().unwrap(),
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
            max_buffer_size: 65536,
            keep_alive_interval: Some(Duration::from_secs(30)),
            nodelay: true,
        }
    }
}

pub struct BufferedTcpStream {
    stream: TcpStream,
    read_buffer: BytesMut,
    write_buffer: BytesMut,
    buffer_capacity: usize,
}

impl BufferedTcpStream {
    pub fn new(stream: TcpStream, buffer_capacity: usize) -> Self {
        Self {
            stream,
            read_buffer: BytesMut::with_capacity(buffer_capacity),
            write_buffer: BytesMut::with_capacity(buffer_capacity),
            buffer_capacity,
        }
    }

    pub async fn read_exact(&mut self, n: usize) -> Result<Bytes, TcpProxyError> {
        if n > self.buffer_capacity {
            return Err(TcpProxyError::BufferOverflow {
                size: n,
                max: self.buffer_capacity,
            });
        }

        while self.read_buffer.len() < n {
            let bytes_read = self.stream.read_buf(&mut self.read_buffer).await?;
            if bytes_read == 0 {
                return Err(TcpProxyError::StreamClosed);
            }
        }

        Ok(self.read_buffer.split_to(n).freeze())
    }

    pub async fn read(&mut self, n: usize) -> Result<Bytes, TcpProxyError> {
        if self.read_buffer.is_empty() {
            let bytes_read = self.stream.read_buf(&mut self.read_buffer).await?;
            if bytes_read == 0 {
                return Err(TcpProxyError::StreamClosed);
            }
        }

        let to_read = n.min(self.read_buffer.len());
        Ok(self.read_buffer.split_to(to_read).freeze())
    }

    pub async fn read_until(&mut self, delimiter: u8) -> Result<Bytes, TcpProxyError> {
        loop {
            if let Some(pos) = self.read_buffer.iter().position(|&b| b == delimiter) {
                return Ok(self.read_buffer.split_to(pos + 1).freeze());
            }

            if self.read_buffer.len() >= self.buffer_capacity {
                return Err(TcpProxyError::BufferOverflow {
                    size: self.read_buffer.len(),
                    max: self.buffer_capacity,
                });
            }

            let bytes_read = self.stream.read_buf(&mut self.read_buffer).await?;
            if bytes_read == 0 {
                return Err(TcpProxyError::StreamClosed);
            }
        }
    }

    pub async fn write(&mut self, data: &[u8]) -> Result<(), TcpProxyError> {
        if self.write_buffer.len() + data.len() > self.buffer_capacity {
            self.flush().await?;
        }

        if data.len() > self.buffer_capacity {
            return Err(TcpProxyError::BufferOverflow {
                size: data.len(),
                max: self.buffer_capacity,
            });
        }

        self.write_buffer.extend_from_slice(data);
        Ok(())
    }

    pub async fn write_all(&mut self, data: &[u8]) -> Result<(), TcpProxyError> {
        self.flush().await?;
        self.stream.write_all(data).await?;
        Ok(())
    }

    pub async fn flush(&mut self) -> Result<(), TcpProxyError> {
        if !self.write_buffer.is_empty() {
            self.stream.write_all(&self.write_buffer).await?;
            self.write_buffer.clear();
        }
        self.stream.flush().await?;
        Ok(())
    }

    pub async fn shutdown(&mut self) -> Result<(), TcpProxyError> {
        self.flush().await?;
        self.stream.shutdown().await?;
        Ok(())
    }

    pub fn peer_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.stream.peer_addr()
    }

    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.stream.local_addr()
    }

    pub fn set_nodelay(&self, nodelay: bool) -> Result<(), std::io::Error> {
        self.stream.set_nodelay(nodelay)
    }

    pub fn set_keepalive(&self, keepalive: Option<Duration>) -> Result<(), std::io::Error> {
        if let Some(duration) = keepalive {
            let sock_ref = socket2::SockRef::from(&self.stream);
            let keepalive = socket2::TcpKeepalive::new().with_time(duration);
            sock_ref.set_tcp_keepalive(&keepalive)?;
        }
        Ok(())
    }
}

pub struct TcpProxy {
    config: TcpProxyConfig,
    listener: Option<TcpListener>,
    active_connections: AtomicU64,
    total_connections: AtomicU64,
    bytes_transferred: AtomicU64,
}

impl TcpProxy {
    pub fn new(config: TcpProxyConfig) -> Self {
        Self {
            config,
            listener: None,
            active_connections: AtomicU64::new(0),
            total_connections: AtomicU64::new(0),
            bytes_transferred: AtomicU64::new(0),
        }
    }

    pub async fn listen(&mut self) -> Result<(), std::io::Error> {
        let listener = TcpListener::bind(self.config.listen_addr).await?;
        self.listener = Some(listener);
        Ok(())
    }

    pub async fn accept(&self) -> Result<(TcpStream, SocketAddr), TcpProxyError> {
        let listener = self
            .listener
            .as_ref()
            .ok_or_else(|| TcpProxyError::ConnectionFailed("Not listening".to_string()))?;

        let (stream, addr) = listener.accept().await?;

        if self.config.nodelay {
            stream.set_nodelay(true)?;
        }

        if let Some(keepalive) = self.config.keep_alive_interval {
            let sock_ref = socket2::SockRef::from(&stream);
            let ka = socket2::TcpKeepalive::new().with_time(keepalive);
            sock_ref.set_tcp_keepalive(&ka)?;
        }

        self.active_connections.fetch_add(1, Ordering::Relaxed);
        self.total_connections.fetch_add(1, Ordering::Relaxed);

        Ok((stream, addr))
    }

    pub async fn connect(
        target: SocketAddr,
        connect_timeout: Duration,
    ) -> Result<TcpStream, TcpProxyError> {
        let stream = timeout(connect_timeout, TcpStream::connect(target))
            .await
            .map_err(|_| TcpProxyError::Timeout(connect_timeout))?
            .map_err(|e| TcpProxyError::ConnectionFailed(e.to_string()))?;

        Ok(stream)
    }

    pub async fn proxy_bidirectional(
        client: TcpStream,
        server: TcpStream,
    ) -> Result<(u64, u64), TcpProxyError> {
        let (mut client_read, mut client_write) = client.into_split();
        let (mut server_read, mut server_write) = server.into_split();

        let client_to_server = async {
            let mut buffer = vec![0u8; 8192];
            let mut total_bytes = 0u64;
            loop {
                let n = client_read.read(&mut buffer).await?;
                if n == 0 {
                    break;
                }
                server_write.write_all(&buffer[..n]).await?;
                server_write.flush().await?;
                total_bytes += n as u64;
            }
            server_write.shutdown().await?;
            Ok::<u64, TcpProxyError>(total_bytes)
        };

        let server_to_client = async {
            let mut buffer = vec![0u8; 8192];
            let mut total_bytes = 0u64;
            loop {
                let n = server_read.read(&mut buffer).await?;
                if n == 0 {
                    break;
                }
                client_write.write_all(&buffer[..n]).await?;
                client_write.flush().await?;
                total_bytes += n as u64;
            }
            client_write.shutdown().await?;
            Ok::<u64, TcpProxyError>(total_bytes)
        };

        let (bytes_c2s, bytes_s2c) = tokio::try_join!(client_to_server, server_to_client)?;

        Ok((bytes_c2s, bytes_s2c))
    }

    pub async fn copy_stream(
        reader: &mut TcpStream,
        writer: &mut TcpStream,
    ) -> Result<u64, TcpProxyError> {
        let mut buffer = vec![0u8; 8192];
        let mut total_bytes = 0u64;

        loop {
            let n = reader.read(&mut buffer).await?;
            if n == 0 {
                break;
            }
            writer.write_all(&buffer[..n]).await?;
            writer.flush().await?;
            total_bytes += n as u64;
        }

        Ok(total_bytes)
    }

    pub fn active_connections(&self) -> u64 {
        self.active_connections.load(Ordering::Relaxed)
    }

    pub fn total_connections(&self) -> u64 {
        self.total_connections.load(Ordering::Relaxed)
    }

    pub fn bytes_transferred(&self) -> u64 {
        self.bytes_transferred.load(Ordering::Relaxed)
    }
}
