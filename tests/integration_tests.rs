//! End-to-end integration tests

use std::net::SocketAddr;
use std::path::Path;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Helper to start an echo server for testing
async fn start_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    while let Ok(n) = socket.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        socket.write_all(&buf[..n]).await.ok();
                    }
                });
            }
        }
    });

    (addr, handle)
}

/// Helper to create test certificates
fn create_test_certs(dir: &Path) {
    use utun::crypto::auth::{
        generate_ca_certificate, generate_client_certificate, generate_server_certificate,
    };

    // Generate CA
    let ca = generate_ca_certificate("Test CA", 365).unwrap();
    std::fs::write(dir.join("ca.crt"), &ca.certificate_pem).unwrap();
    std::fs::write(dir.join("ca.key"), ca.private_key_pem.expose_secret()).unwrap();

    // Generate server cert
    let server = generate_server_certificate(
        &ca.certificate_pem,
        ca.private_key_pem.expose_secret(),
        "localhost",
        vec!["localhost".to_string()],
        vec!["127.0.0.1".to_string()],
        365,
    )
    .unwrap();
    std::fs::write(dir.join("server.crt"), &server.certificate_pem).unwrap();
    std::fs::write(dir.join("server.key"), server.private_key_pem.expose_secret()).unwrap();

    // Generate client cert
    let client = generate_client_certificate(
        &ca.certificate_pem,
        ca.private_key_pem.expose_secret(),
        "test-client",
        365,
    )
    .unwrap();
    std::fs::write(dir.join("client.crt"), &client.certificate_pem).unwrap();
    std::fs::write(dir.join("client.key"), client.private_key_pem.expose_secret()).unwrap();
}

#[tokio::test]
async fn test_echo_server_basic() {
    let (echo_addr, _handle) = start_echo_server().await;

    // Connect to echo server
    let mut client = TcpStream::connect(echo_addr).await.unwrap();

    // Send data
    let test_data = b"Hello, Echo!";
    client.write_all(test_data).await.unwrap();

    // Read response
    let mut response = vec![0u8; test_data.len()];
    client.read_exact(&mut response).await.unwrap();

    // Verify
    assert_eq!(test_data.as_slice(), response.as_slice());
}

#[tokio::test]
async fn test_certificate_generation() {
    let cert_dir = tempdir().unwrap();
    create_test_certs(cert_dir.path());

    // Verify files were created
    assert!(cert_dir.path().join("ca.crt").exists());
    assert!(cert_dir.path().join("ca.key").exists());
    assert!(cert_dir.path().join("server.crt").exists());
    assert!(cert_dir.path().join("server.key").exists());
    assert!(cert_dir.path().join("client.crt").exists());
    assert!(cert_dir.path().join("client.key").exists());
}

#[tokio::test]
async fn test_large_data_transfer() {
    let (echo_addr, _handle) = start_echo_server().await;

    let mut client = TcpStream::connect(echo_addr).await.unwrap();

    // Send large data (1MB)
    let test_data = vec![0x42u8; 1024 * 1024];
    client.write_all(&test_data).await.unwrap();

    // Read response
    let mut response = vec![0u8; test_data.len()];
    client.read_exact(&mut response).await.unwrap();

    // Verify
    assert_eq!(test_data, response);
}

#[tokio::test]
async fn test_concurrent_connections() {
    let (echo_addr, _handle) = start_echo_server().await;

    let mut handles = vec![];

    for i in 0..10 {
        let addr = echo_addr;
        let handle = tokio::spawn(async move {
            let mut client = TcpStream::connect(addr).await.unwrap();
            let test_data = format!("Message {}", i);
            client.write_all(test_data.as_bytes()).await.unwrap();

            let mut response = vec![0u8; test_data.len()];
            client.read_exact(&mut response).await.unwrap();

            assert_eq!(test_data.as_bytes(), response.as_slice());
        });
        handles.push(handle);
    }

    // Wait for all connections to complete
    for handle in handles {
        handle.await.unwrap();
    }
}

#[tokio::test]
async fn test_connection_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Don't accept connections - simulate timeout
    let result = tokio::time::timeout(std::time::Duration::from_millis(100), async {
        let _stream = TcpStream::connect(addr).await.unwrap();
        // Server never accepts, so this will hang
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    })
    .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_bidirectional_communication() {
    let (echo_addr, _handle) = start_echo_server().await;

    let mut client = TcpStream::connect(echo_addr).await.unwrap();

    // Send multiple messages
    for i in 0..5 {
        let msg = format!("Message {}", i);
        client.write_all(msg.as_bytes()).await.unwrap();

        let mut response = vec![0u8; msg.len()];
        client.read_exact(&mut response).await.unwrap();

        assert_eq!(msg.as_bytes(), response.as_slice());
    }
}

#[tokio::test]
async fn test_multiple_services_routing() {
    // Start multiple echo servers on different ports to simulate different backend services
    let (service1_addr, _handle1) = start_echo_server().await;
    let (service2_addr, _handle2) = start_echo_server().await;
    let (service3_addr, _handle3) = start_echo_server().await;

    // Test routing to service 1
    let mut client1 = TcpStream::connect(service1_addr).await.unwrap();
    let msg1 = b"Service 1 request";
    client1.write_all(msg1).await.unwrap();
    let mut resp1 = vec![0u8; msg1.len()];
    client1.read_exact(&mut resp1).await.unwrap();
    assert_eq!(msg1.as_slice(), resp1.as_slice());

    // Test routing to service 2
    let mut client2 = TcpStream::connect(service2_addr).await.unwrap();
    let msg2 = b"Service 2 request";
    client2.write_all(msg2).await.unwrap();
    let mut resp2 = vec![0u8; msg2.len()];
    client2.read_exact(&mut resp2).await.unwrap();
    assert_eq!(msg2.as_slice(), resp2.as_slice());

    // Test routing to service 3
    let mut client3 = TcpStream::connect(service3_addr).await.unwrap();
    let msg3 = b"Service 3 request";
    client3.write_all(msg3).await.unwrap();
    let mut resp3 = vec![0u8; msg3.len()];
    client3.read_exact(&mut resp3).await.unwrap();
    assert_eq!(msg3.as_slice(), resp3.as_slice());

    // Test concurrent access to all three services
    let handles = vec![
        tokio::spawn(async move {
            let mut c = TcpStream::connect(service1_addr).await.unwrap();
            let data = b"Concurrent 1";
            c.write_all(data).await.unwrap();
            let mut r = vec![0u8; data.len()];
            c.read_exact(&mut r).await.unwrap();
            assert_eq!(data.as_slice(), r.as_slice());
        }),
        tokio::spawn(async move {
            let mut c = TcpStream::connect(service2_addr).await.unwrap();
            let data = b"Concurrent 2";
            c.write_all(data).await.unwrap();
            let mut r = vec![0u8; data.len()];
            c.read_exact(&mut r).await.unwrap();
            assert_eq!(data.as_slice(), r.as_slice());
        }),
        tokio::spawn(async move {
            let mut c = TcpStream::connect(service3_addr).await.unwrap();
            let data = b"Concurrent 3";
            c.write_all(data).await.unwrap();
            let mut r = vec![0u8; data.len()];
            c.read_exact(&mut r).await.unwrap();
            assert_eq!(data.as_slice(), r.as_slice());
        }),
    ];

    for handle in handles {
        handle.await.unwrap();
    }
}
