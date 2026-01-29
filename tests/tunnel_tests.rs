//! Unit tests for the tunnel protocol

use std::net::SocketAddr;
use utun::tunnel::{
    connection::{Connection, ConnectionState},
    frame::{Frame, FrameFlags, FrameType, Protocol, MAX_PAYLOAD_SIZE},
};

mod frame_tests {
    use super::*;

    #[test]
    fn test_frame_data_roundtrip() {
        let frame = Frame::new_data(1, 42, b"test payload").unwrap();

        let bytes = frame.to_bytes();
        let decoded = Frame::from_bytes(&bytes).unwrap();

        assert_eq!(frame.frame_type(), decoded.frame_type());
        assert_eq!(frame.sequence(), decoded.sequence());
        assert_eq!(frame.connection_id(), decoded.connection_id());
        assert_eq!(frame.payload(), decoded.payload());
    }

    #[test]
    fn test_frame_types() {
        // Test all frame type constructors
        let ping = Frame::new_ping(1);
        assert_eq!(ping.frame_type(), FrameType::Ping);

        let pong = Frame::new_pong(1);
        assert_eq!(pong.frame_type(), FrameType::Pong);

        let close = Frame::new_close(1, "goodbye");
        assert_eq!(close.frame_type(), FrameType::Close);
    }

    #[test]
    fn test_frame_flags() {
        let mut flags = FrameFlags::new();
        assert!(!flags.has(FrameFlags::FIN));
        assert!(!flags.has(FrameFlags::RST));

        flags.set(FrameFlags::FIN);
        assert!(flags.has(FrameFlags::FIN));

        flags.set(FrameFlags::RST);
        assert!(flags.has(FrameFlags::RST));

        flags.clear(FrameFlags::FIN);
        assert!(!flags.has(FrameFlags::FIN));
        assert!(flags.has(FrameFlags::RST));
    }

    #[test]
    fn test_frame_max_payload() {
        let large_payload = vec![0u8; MAX_PAYLOAD_SIZE];
        let result = Frame::new_data(1, 0, &large_payload);
        assert!(result.is_ok());

        let too_large = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        let result = Frame::new_data(1, 0, &too_large);
        assert!(result.is_err());
    }

    #[test]
    fn test_frame_version() {
        let frame = Frame::new_data(1, 0, b"test").unwrap();
        let mut bytes = frame.to_bytes();

        // Modify version
        bytes[0] = 99;

        let result = Frame::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_frame_connect() {
        let frame = Frame::new_connect(123, 8080, Protocol::Tcp);
        assert_eq!(frame.frame_type(), FrameType::Connect);
        assert_eq!(frame.connection_id(), 123);
    }

    #[test]
    fn test_frame_connect_ack() {
        let success_frame = Frame::new_connect_ack(456, true);
        assert_eq!(success_frame.frame_type(), FrameType::ConnectAck);
        assert_eq!(success_frame.connection_id(), 456);

        let fail_frame = Frame::new_connect_ack(789, false);
        assert_eq!(fail_frame.frame_type(), FrameType::ConnectAck);
    }

    #[test]
    fn test_empty_payload() {
        let frame = Frame::new_data(1, 0, b"").unwrap();
        assert_eq!(frame.payload().len(), 0);

        let bytes = frame.to_bytes();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.payload().len(), 0);
    }

    #[test]
    fn test_frame_truncated() {
        let frame = Frame::new_data(1, 0, b"test").unwrap();
        let bytes = frame.to_bytes();

        // Try to parse truncated frame
        let result = Frame::from_bytes(&bytes[..5]);
        assert!(result.is_err());
    }
}

mod connection_tests {
    use super::*;

    #[tokio::test]
    async fn test_connection_creation() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let (conn, _tx, _rx) = Connection::new(1, addr, Protocol::Tcp, 8080);

        assert_eq!(conn.id(), 1);
        assert_eq!(conn.remote_addr(), addr);
        assert_eq!(conn.state().await, ConnectionState::Connecting);
    }

    #[tokio::test]
    async fn test_connection_state_transitions() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let (conn, _tx, _rx) = Connection::new(1, addr, Protocol::Tcp, 8080);

        conn.set_state(ConnectionState::Handshaking).await;
        assert_eq!(conn.state().await, ConnectionState::Handshaking);

        conn.set_state(ConnectionState::Established).await;
        assert_eq!(conn.state().await, ConnectionState::Established);

        conn.set_state(ConnectionState::Closed).await;
        assert_eq!(conn.state().await, ConnectionState::Closed);
    }

    #[tokio::test]
    async fn test_connection_statistics() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let (conn, _tx, _rx) = Connection::new(1, addr, Protocol::Tcp, 8080);

        conn.record_send(100);
        conn.record_send(200);
        conn.record_receive(50);

        assert_eq!(conn.bytes_sent(), 300);
        assert_eq!(conn.bytes_received(), 50);
    }

    #[tokio::test]
    async fn test_connection_service_info() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let target: SocketAddr = "10.0.0.1:9000".parse().unwrap();
        let (conn, _tx, _rx) = Connection::new(1, addr, Protocol::Tcp, 8080);

        conn.set_service("web-service".to_string(), target).await;

        let service_name = conn.service_name().await;
        assert_eq!(service_name, Some("web-service".to_string()));

        let target_addr = conn.target_addr().await;
        assert_eq!(target_addr, Some(target));
    }

    #[tokio::test]
    async fn test_connection_channel_communication() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let (conn, tx_from_tunnel, mut rx_to_tunnel) =
            Connection::new(1, addr, Protocol::Tcp, 8080);

        // Send frame to tunnel
        let test_frame = Frame::new_ping(1);
        conn.send_to_tunnel(test_frame.clone()).await.unwrap();

        // Receive from tunnel side
        let received = rx_to_tunnel.recv().await.unwrap();
        assert_eq!(received.frame_type(), test_frame.frame_type());
        assert_eq!(received.sequence(), test_frame.sequence());

        // Send frame from tunnel
        let response_frame = Frame::new_pong(2);
        tx_from_tunnel.send(response_frame.clone()).await.unwrap();

        // Receive on connection side
        let received = conn.recv_from_tunnel().await.unwrap();
        assert_eq!(received.frame_type(), response_frame.frame_type());
        assert_eq!(received.sequence(), response_frame.sequence());
    }

    #[tokio::test]
    async fn test_multiple_connections() {
        let addr1: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:8081".parse().unwrap();

        let (conn1, _tx1, _rx1) = Connection::new(1, addr1, Protocol::Tcp, 8080);
        let (conn2, _tx2, _rx2) = Connection::new(2, addr2, Protocol::Tcp, 8081);

        assert_ne!(conn1.id(), conn2.id());
        assert_ne!(conn1.remote_addr(), conn2.remote_addr());
    }
}
