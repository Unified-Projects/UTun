use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Both,
}

impl Protocol {
    pub fn includes_tcp(&self) -> bool {
        matches!(self, Protocol::Tcp | Protocol::Both)
    }

    pub fn includes_udp(&self) -> bool {
        matches!(self, Protocol::Udp | Protocol::Both)
    }
}

pub struct ListenerConfig {
    pub bind_addr: SocketAddr,
    pub protocol: Protocol,
    pub tcp_backlog: u32,
    pub tcp_nodelay: bool,
    pub tcp_keepalive: Option<Duration>,
    pub udp_buffer_size: usize,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:8443".parse().unwrap(),
            protocol: Protocol::Tcp,
            tcp_backlog: 1024,
            tcp_nodelay: true,
            tcp_keepalive: Some(Duration::from_secs(30)),
            udp_buffer_size: 65535,
        }
    }
}

pub struct Listener {
    config: ListenerConfig,
    tcp_listener: Option<TcpListener>,
    udp_socket: Option<Arc<UdpSocket>>,
}

impl Listener {
    pub async fn bind(config: ListenerConfig) -> Result<Self, std::io::Error> {
        let tcp_listener = if config.protocol.includes_tcp() {
            let listener = TcpListener::bind(config.bind_addr).await?;
            Some(listener)
        } else {
            None
        };

        let udp_socket = if config.protocol.includes_udp() {
            let socket = UdpSocket::bind(config.bind_addr).await?;
            Some(Arc::new(socket))
        } else {
            None
        };

        Ok(Self {
            config,
            tcp_listener,
            udp_socket,
        })
    }

    pub async fn accept_tcp(&self) -> Result<(TcpStream, SocketAddr), std::io::Error> {
        let listener = self.tcp_listener.as_ref().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "TCP listener not configured",
            )
        })?;

        let (stream, addr) = listener.accept().await?;

        if self.config.tcp_nodelay {
            stream.set_nodelay(true)?;
        }

        if let Some(keepalive) = self.config.tcp_keepalive {
            let sock_ref = socket2::SockRef::from(&stream);
            let keepalive = socket2::TcpKeepalive::new().with_time(keepalive);
            sock_ref.set_tcp_keepalive(&keepalive)?;
        }

        Ok((stream, addr))
    }

    pub async fn recv_udp(&self) -> Result<(Vec<u8>, SocketAddr), std::io::Error> {
        let socket = self.udp_socket.as_ref().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "UDP socket not configured",
            )
        })?;

        let mut buf = vec![0u8; self.config.udp_buffer_size];
        let (len, addr) = socket.recv_from(&mut buf).await?;
        buf.truncate(len);
        Ok((buf, addr))
    }

    pub async fn send_udp(&self, data: &[u8], addr: SocketAddr) -> Result<(), std::io::Error> {
        let socket = self.udp_socket.as_ref().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "UDP socket not configured",
            )
        })?;

        socket.send_to(data, addr).await?;
        Ok(())
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.config.bind_addr
    }

    pub fn has_tcp(&self) -> bool {
        self.tcp_listener.is_some()
    }

    pub fn has_udp(&self) -> bool {
        self.udp_socket.is_some()
    }
}
