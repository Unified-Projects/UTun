//! End-to-end integration tests

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use utun::config::{CryptoConfig, KemMode};
use utun::crypto::KeyManager;
use utun::tunnel::HandshakeContext;

/// Helper to start an echo server for testing
async fn start_echo_server() -> Result<(SocketAddr, tokio::task::JoinHandle<()>), std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
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

    Ok((addr, handle))
}

async fn start_echo_server_or_skip(
    test_name: &str,
) -> Option<(SocketAddr, tokio::task::JoinHandle<()>)> {
    match start_echo_server().await {
        Ok(result) => Some(result),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping {test_name}: {err}");
            None
        }
        Err(err) => panic!("{test_name}: failed to start echo server: {err}"),
    }
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
    std::fs::write(
        dir.join("server.key"),
        server.private_key_pem.expose_secret(),
    )
    .unwrap();

    // Generate client cert
    let client = generate_client_certificate(
        &ca.certificate_pem,
        ca.private_key_pem.expose_secret(),
        "test-client",
        365,
    )
    .unwrap();
    std::fs::write(dir.join("client.crt"), &client.certificate_pem).unwrap();
    std::fs::write(
        dir.join("client.key"),
        client.private_key_pem.expose_secret(),
    )
    .unwrap();
}

#[tokio::test]
async fn test_echo_server_basic() {
    let (echo_addr, _handle) = match start_echo_server_or_skip("test_echo_server_basic").await {
        Some(result) => result,
        None => return,
    };

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
    let (echo_addr, _handle) = match start_echo_server_or_skip("test_large_data_transfer").await {
        Some(result) => result,
        None => return,
    };

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
    let (echo_addr, _handle) = match start_echo_server_or_skip("test_concurrent_connections").await
    {
        Some(result) => result,
        None => return,
    };

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
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping test_connection_timeout: {err}");
            return;
        }
        Err(err) => panic!("test_connection_timeout: failed to bind listener: {err}"),
    };
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
    let (echo_addr, _handle) =
        match start_echo_server_or_skip("test_bidirectional_communication").await {
            Some(result) => result,
            None => return,
        };

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
    let (service1_addr, _handle1) =
        match start_echo_server_or_skip("test_multiple_services_routing").await {
            Some(result) => result,
            None => return,
        };
    let (service2_addr, _handle2) =
        match start_echo_server_or_skip("test_multiple_services_routing").await {
            Some(result) => result,
            None => return,
        };
    let (service3_addr, _handle3) =
        match start_echo_server_or_skip("test_multiple_services_routing").await {
            Some(result) => result,
            None => return,
        };

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

/// Test that PEM certificates are properly loaded and can be used in handshake
/// This tests the fix for PEM-to-DER conversion in HandshakeContext
#[tokio::test]
async fn test_pem_certificate_handshake() {
    let cert_dir = tempdir().unwrap();
    create_test_certs(cert_dir.path());

    // Load PEM files from disk (as the real deployment does)
    let ca_pem = std::fs::read(cert_dir.path().join("ca.crt")).unwrap();
    let server_cert_pem = std::fs::read(cert_dir.path().join("server.crt")).unwrap();
    let server_key_pem = std::fs::read(cert_dir.path().join("server.key")).unwrap();
    let client_cert_pem = std::fs::read(cert_dir.path().join("client.crt")).unwrap();
    let client_key_pem = std::fs::read(cert_dir.path().join("client.key")).unwrap();

    // Verify they are PEM format (not DER)
    assert!(
        ca_pem.starts_with(b"-----BEGIN"),
        "CA cert should be PEM format"
    );
    assert!(
        server_cert_pem.starts_with(b"-----BEGIN"),
        "Server cert should be PEM format"
    );
    assert!(
        client_cert_pem.starts_with(b"-----BEGIN"),
        "Client cert should be PEM format"
    );

    // Create handshake contexts with PEM data (this should work after the fix)
    let key_manager = Arc::new(KeyManager::new(3600, 300));

    let mut client_ctx = HandshakeContext::new_client(
        key_manager.clone(),
        client_cert_pem.clone(),
        client_key_pem.clone(),
        ca_pem.clone(),
    );

    let mut server_ctx = HandshakeContext::new_server(
        key_manager.clone(),
        server_cert_pem.clone(),
        server_key_pem.clone(),
        ca_pem.clone(),
    );

    // Perform handshake - this would fail before the PEM fix
    let client_hello = client_ctx
        .create_client_hello()
        .expect("Client hello should succeed");
    let server_hello = server_ctx
        .process_client_hello(client_hello)
        .await
        .expect("Server hello should succeed");
    let client_finished = client_ctx
        .process_server_hello(server_hello)
        .await
        .expect("Client finished should succeed");
    let server_finished = server_ctx
        .process_client_finished(client_finished)
        .await
        .expect("Server finished should succeed");
    client_ctx
        .process_server_finished(server_finished)
        .await
        .expect("Client should process server finished");

    // Verify session keys were derived
    assert!(
        client_ctx.get_session_key().is_some(),
        "Client should have session key"
    );
    assert!(
        server_ctx.get_session_key().is_some(),
        "Server should have session key"
    );

    // Verify both sides derived the same key
    assert_eq!(
        client_ctx.get_session_key().unwrap(),
        server_ctx.get_session_key().unwrap(),
        "Both sides should derive the same session key"
    );
}

/// Test that max handshake size is correctly calculated for each KEM mode
#[test]
fn test_max_handshake_size_by_kem_mode() {
    // ML-KEM-768 should use smaller buffer (64KB)
    let mlkem_config = CryptoConfig {
        kem_mode: KemMode::Mlkem768,
        key_rotation_interval_seconds: 3600,
        rehandshake_before_expiry_seconds: 300,
        max_handshake_size: None,
    };
    assert_eq!(
        mlkem_config.effective_max_handshake_size(),
        64 * 1024,
        "ML-KEM-768 should use 64KB handshake buffer"
    );

    // Hybrid mode should use larger buffer (2MB) for McEliece keys
    let hybrid_config = CryptoConfig {
        kem_mode: KemMode::Hybrid,
        key_rotation_interval_seconds: 3600,
        rehandshake_before_expiry_seconds: 300,
        max_handshake_size: None,
    };
    assert_eq!(
        hybrid_config.effective_max_handshake_size(),
        2 * 1024 * 1024,
        "Hybrid mode should use 2MB handshake buffer for McEliece"
    );

    // McEliece-only mode should also use larger buffer
    let mceliece_config = CryptoConfig {
        kem_mode: KemMode::Mceliece460896,
        key_rotation_interval_seconds: 3600,
        rehandshake_before_expiry_seconds: 300,
        max_handshake_size: None,
    };
    assert_eq!(
        mceliece_config.effective_max_handshake_size(),
        2 * 1024 * 1024,
        "McEliece mode should use 2MB handshake buffer"
    );

    // Custom override should be respected
    let custom_config = CryptoConfig {
        kem_mode: KemMode::Mlkem768,
        key_rotation_interval_seconds: 3600,
        rehandshake_before_expiry_seconds: 300,
        max_handshake_size: Some(1024 * 1024), // 1MB override
    };
    assert_eq!(
        custom_config.effective_max_handshake_size(),
        1024 * 1024,
        "Custom max_handshake_size should override default"
    );
}
