//! Comprehensive full system integration tests

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use utun::config::{
    AllowedOutboundConfig, ConnectionFilterConfig, CryptoConfig, DestConfig, ExposedPortConfig,
    KemMode, Protocol as ConfigProtocol, ServiceConfig, SourceConfig, SourceMode,
};
use utun::tunnel::{DestContainer, SourceContainer};

/// Helper to create test certificates
fn create_test_certs(dir: &Path) {
    use utun::crypto::auth::{
        generate_ca_certificate, generate_client_certificate, generate_server_certificate,
    };

    let ca = generate_ca_certificate("Test CA", 365).unwrap();
    std::fs::write(dir.join("ca.crt"), &ca.certificate_pem).unwrap();
    std::fs::write(dir.join("ca.key"), ca.private_key_pem.expose_secret()).unwrap();

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

/// Start an echo server that echoes back all data
async fn start_echo_server(port: u16) -> Result<tokio::task::JoinHandle<()>, std::io::Error> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;

    let handle = tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    while let Ok(n) = socket.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        if socket.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        }
    });

    Ok(handle)
}

/// Create a default CryptoConfig for testing
fn default_crypto_config() -> CryptoConfig {
    CryptoConfig {
        kem_mode: KemMode::Mlkem768,
        key_rotation_interval_seconds: 3600,
        rehandshake_before_expiry_seconds: 300,
        max_handshake_size: Some(1024 * 1024), // 1MB to accommodate certificates + KEM data
    }
}

async fn wait_for_destination_ready() {
    tokio::time::sleep(Duration::from_secs(1)).await;
}

async fn wait_for_cleanup() {
    tokio::time::sleep(Duration::from_millis(500)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_single_port_end_to_end() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();

    let cert_dir = tempdir().unwrap();
    create_test_certs(cert_dir.path());

    // Start backend echo server
    let _echo = start_echo_server(28001).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create destination config
    let dest_config = DestConfig {
        listen_ip: "127.0.0.1".to_string(),
        tunnel_port: 28011,
        exposed_services: vec![ServiceConfig {
            name: "test-echo".to_string(),
            port: 28021,
            target_ip: "127.0.0.1".to_string(),
            target_port: 28001,
            protocol: "tcp".to_string(),
            description: Some("Test echo service".to_string()),
        }],
        max_connections_per_service: 1000,
        connection_timeout_ms: 30000,
        target_connect_timeout_ms: 5000,
        connection_channel_size: 1024,
        connection_filter: ConnectionFilterConfig::default(),
        server_cert_path: cert_dir.path().join("server.crt"),
        server_key_path: cert_dir.path().join("server.key"),
        ca_cert_path: cert_dir.path().join("ca.crt"),
    };

    let crypto_config = default_crypto_config();

    // Start destination
    let dest = Arc::new(
        DestContainer::new(dest_config, crypto_config)
            .await
            .expect("Failed to create DestContainer"),
    );
    dest.start().await.expect("Failed to start DestContainer");
    let dest_clone = dest.clone();
    let _dest_handle = tokio::spawn(async move {
        if let Err(e) = dest_clone.run().await {
            eprintln!("Destination run() failed: {}", e);
        }
    });

    // Wait for destination to be ready
    wait_for_destination_ready().await;

    // Create source config
    let source_config = SourceConfig {
        mode: SourceMode::Transparent,
        listen_ip: "127.0.0.1".to_string(),
        listen_port: 28021,
        dest_host: "127.0.0.1".to_string(),
        dest_tunnel_port: 28011,
        max_connections: 1000,
        connection_timeout_ms: 30000,
        keep_alive_interval_ms: 30000,
        heartbeat_interval_ms: 5000,
        heartbeat_timeout_ms: 10000,
        max_missed_pongs: 3,
        reconnection_enabled: false,
        max_reconnect_attempts: 0,
        initial_reconnect_delay_ms: 1000,
        max_reconnect_delay_ms: 30000,
        frame_buffer_size: 8192,
        connection_channel_size: 1024,
        circuit_breaker_window_secs: 60,
        circuit_breaker_max_restarts: 5,
        allowed_outbound: AllowedOutboundConfig::default(),
        exposed_ports: vec![ExposedPortConfig {
            port: 28021,
            protocol: ConfigProtocol::Tcp,
        }],
        client_cert_path: cert_dir.path().join("client.crt"),
        client_key_path: cert_dir.path().join("client.key"),
        ca_cert_path: cert_dir.path().join("ca.crt"),
    };

    // Start source
    let crypto_config = default_crypto_config();
    let source = Arc::new(
        SourceContainer::new(source_config, crypto_config)
            .await
            .expect("Failed to create SourceContainer"),
    );
    source
        .start()
        .await
        .expect("Failed to start SourceContainer (handshake failed)");

    let source_clone = source.clone();
    tokio::spawn(async move {
        if let Err(e) = source_clone.run().await {
            eprintln!("Source run() failed: {}", e);
        }
    });

    // Give time for listeners to bind
    tokio::time::sleep(Duration::from_secs(2)).await;

    let mut client = timeout(
        Duration::from_secs(5),
        TcpStream::connect("127.0.0.1:28021"),
    )
    .await
    .expect("Timeout connecting to source")
    .expect("Failed to connect to source");

    let test_data = b"FULL SYSTEM TEST - Single Port";
    client.write_all(test_data).await.unwrap();

    let mut response = vec![0u8; test_data.len()];
    timeout(Duration::from_secs(5), client.read_exact(&mut response))
        .await
        .expect("Timeout reading response")
        .expect("Failed to read response");

    assert_eq!(test_data, response.as_slice(), "Data mismatch!");

    // Cleanup
    source.stop().await;
    dest.stop().await;
    wait_for_cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_multiple_ports_concurrent() {
    let cert_dir = tempdir().unwrap();
    create_test_certs(cert_dir.path());

    // Start 5 backend echo servers
    let _echo1 = start_echo_server(28002).await.unwrap();
    let _echo2 = start_echo_server(28003).await.unwrap();
    let _echo3 = start_echo_server(28004).await.unwrap();
    let _echo4 = start_echo_server(28005).await.unwrap();
    let _echo5 = start_echo_server(28006).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let dest_config = DestConfig {
        listen_ip: "127.0.0.1".to_string(),
        tunnel_port: 28012,
        exposed_services: vec![
            ServiceConfig {
                name: "service1".to_string(),
                port: 28022,
                target_ip: "127.0.0.1".to_string(),
                target_port: 28002,
                protocol: "tcp".to_string(),
                description: None,
            },
            ServiceConfig {
                name: "service2".to_string(),
                port: 28023,
                target_ip: "127.0.0.1".to_string(),
                target_port: 28003,
                protocol: "tcp".to_string(),
                description: None,
            },
            ServiceConfig {
                name: "service3".to_string(),
                port: 28024,
                target_ip: "127.0.0.1".to_string(),
                target_port: 28004,
                protocol: "tcp".to_string(),
                description: None,
            },
            ServiceConfig {
                name: "service4".to_string(),
                port: 28025,
                target_ip: "127.0.0.1".to_string(),
                target_port: 28005,
                protocol: "tcp".to_string(),
                description: None,
            },
            ServiceConfig {
                name: "service5".to_string(),
                port: 28026,
                target_ip: "127.0.0.1".to_string(),
                target_port: 28006,
                protocol: "tcp".to_string(),
                description: None,
            },
        ],
        max_connections_per_service: 1000,
        connection_timeout_ms: 30000,
        target_connect_timeout_ms: 5000,
        connection_channel_size: 1024,
        connection_filter: ConnectionFilterConfig::default(),
        server_cert_path: cert_dir.path().join("server.crt"),
        server_key_path: cert_dir.path().join("server.key"),
        ca_cert_path: cert_dir.path().join("ca.crt"),
    };

    let crypto_config = default_crypto_config();
    let dest = Arc::new(
        DestContainer::new(dest_config, crypto_config)
            .await
            .unwrap(),
    );
    dest.start().await.unwrap();
    let dest_clone = dest.clone();
    tokio::spawn(async move {
        dest_clone.run().await.ok();
    });

    // Wait for destination to be ready
    wait_for_destination_ready().await;

    let source_config = SourceConfig {
        mode: SourceMode::Transparent,
        listen_ip: "127.0.0.1".to_string(),
        listen_port: 28022,
        dest_host: "127.0.0.1".to_string(),
        dest_tunnel_port: 28012,
        max_connections: 1000,
        connection_timeout_ms: 30000,
        keep_alive_interval_ms: 30000,
        heartbeat_interval_ms: 5000,
        heartbeat_timeout_ms: 10000,
        max_missed_pongs: 3,
        reconnection_enabled: false,
        max_reconnect_attempts: 0,
        initial_reconnect_delay_ms: 1000,
        max_reconnect_delay_ms: 30000,
        frame_buffer_size: 8192,
        connection_channel_size: 1024,
        circuit_breaker_window_secs: 60,
        circuit_breaker_max_restarts: 5,
        allowed_outbound: AllowedOutboundConfig::default(),
        exposed_ports: vec![
            ExposedPortConfig {
                port: 28022,
                protocol: ConfigProtocol::Tcp,
            },
            ExposedPortConfig {
                port: 28023,
                protocol: ConfigProtocol::Tcp,
            },
            ExposedPortConfig {
                port: 28024,
                protocol: ConfigProtocol::Tcp,
            },
            ExposedPortConfig {
                port: 28025,
                protocol: ConfigProtocol::Tcp,
            },
            ExposedPortConfig {
                port: 28026,
                protocol: ConfigProtocol::Tcp,
            },
        ],
        client_cert_path: cert_dir.path().join("client.crt"),
        client_key_path: cert_dir.path().join("client.key"),
        ca_cert_path: cert_dir.path().join("ca.crt"),
    };

    let crypto_config = default_crypto_config();
    let source = Arc::new(
        SourceContainer::new(source_config, crypto_config)
            .await
            .unwrap(),
    );
    source.start().await.unwrap();
    let source_clone = source.clone();
    tokio::spawn(async move {
        if let Err(e) = source_clone.run().await {
            eprintln!("Source run() failed: {}", e);
        }
    });

    // Give time for listeners to bind
    tokio::time::sleep(Duration::from_secs(1)).await;

    use tokio::task::JoinSet;
    let mut tasks = JoinSet::new();

    for port in 28022..=28026 {
        tasks.spawn(async move {
            let mut client = timeout(
                Duration::from_secs(5),
                TcpStream::connect(format!("127.0.0.1:{}", port)),
            )
            .await
            .unwrap_or_else(|_| panic!("Timeout port {}", port))
            .unwrap_or_else(|_| panic!("Connect failed port {}", port));

            let data = format!("Port {} test", port);
            client.write_all(data.as_bytes()).await.unwrap();

            let mut resp = vec![0u8; data.len()];
            timeout(Duration::from_secs(5), client.read_exact(&mut resp))
                .await
                .unwrap_or_else(|_| panic!("Read timeout port {}", port))
                .unwrap_or_else(|_| panic!("Read failed port {}", port));

            assert_eq!(data.as_bytes(), resp.as_slice());
        });
    }

    let mut count = 0;
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
        count += 1;
    }
    assert_eq!(count, 5);

    source.stop().await;
    dest.stop().await;
    wait_for_cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_chaos_massive_concurrent_connections() {
    let cert_dir = tempdir().unwrap();
    create_test_certs(cert_dir.path());

    let _echo = start_echo_server(28007).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let dest_config = DestConfig {
        listen_ip: "127.0.0.1".to_string(),
        tunnel_port: 28013,
        exposed_services: vec![ServiceConfig {
            name: "chaos-echo".to_string(),
            port: 28027,
            target_ip: "127.0.0.1".to_string(),
            target_port: 28007,
            protocol: "tcp".to_string(),
            description: None,
        }],
        max_connections_per_service: 5000,
        connection_timeout_ms: 30000,
        target_connect_timeout_ms: 5000,
        connection_channel_size: 1024,
        connection_filter: ConnectionFilterConfig::default(),
        server_cert_path: cert_dir.path().join("server.crt"),
        server_key_path: cert_dir.path().join("server.key"),
        ca_cert_path: cert_dir.path().join("ca.crt"),
    };

    let crypto_config = default_crypto_config();
    let dest = Arc::new(
        DestContainer::new(dest_config, crypto_config)
            .await
            .unwrap(),
    );
    dest.start().await.unwrap();
    let dest_clone = dest.clone();
    tokio::spawn(async move {
        dest_clone.run().await.ok();
    });

    // Wait for destination to be ready
    wait_for_destination_ready().await;

    let source_config = SourceConfig {
        mode: SourceMode::Transparent,
        listen_ip: "127.0.0.1".to_string(),
        listen_port: 28027,
        dest_host: "127.0.0.1".to_string(),
        dest_tunnel_port: 28013,
        max_connections: 5000,
        connection_timeout_ms: 30000,
        keep_alive_interval_ms: 30000,
        heartbeat_interval_ms: 5000,
        heartbeat_timeout_ms: 10000,
        max_missed_pongs: 3,
        reconnection_enabled: false,
        max_reconnect_attempts: 0,
        initial_reconnect_delay_ms: 1000,
        max_reconnect_delay_ms: 30000,
        frame_buffer_size: 8192,
        connection_channel_size: 1024,
        circuit_breaker_window_secs: 60,
        circuit_breaker_max_restarts: 5,
        allowed_outbound: AllowedOutboundConfig::default(),
        exposed_ports: vec![ExposedPortConfig {
            port: 28027,
            protocol: ConfigProtocol::Tcp,
        }],
        client_cert_path: cert_dir.path().join("client.crt"),
        client_key_path: cert_dir.path().join("client.key"),
        ca_cert_path: cert_dir.path().join("ca.crt"),
    };

    let crypto_config = default_crypto_config();
    let source = Arc::new(
        SourceContainer::new(source_config, crypto_config)
            .await
            .unwrap(),
    );
    source.start().await.unwrap();
    let source_clone = source.clone();
    tokio::spawn(async move {
        if let Err(e) = source_clone.run().await {
            eprintln!("Source run() failed: {}", e);
        }
    });

    // Give time for listeners to bind
    tokio::time::sleep(Duration::from_secs(1)).await;

    use tokio::task::JoinSet;
    let mut tasks = JoinSet::new();

    for i in 0..100 {
        tasks.spawn(async move {
            let mut client = timeout(
                Duration::from_secs(10),
                TcpStream::connect("127.0.0.1:28027"),
            )
            .await
            .unwrap_or_else(|_| panic!("Conn {} timeout", i))
            .unwrap_or_else(|_| panic!("Conn {} failed", i));

            let data = format!("Chaos connection {}", i);
            client.write_all(data.as_bytes()).await.unwrap();

            let mut resp = vec![0u8; data.len()];
            timeout(Duration::from_secs(10), client.read_exact(&mut resp))
                .await
                .unwrap_or_else(|_| panic!("Conn {} read timeout", i))
                .unwrap_or_else(|_| panic!("Conn {} read failed", i));

            assert_eq!(data.as_bytes(), resp.as_slice());
        });
    }

    let mut count = 0;
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
        count += 1;
    }
    assert_eq!(count, 100);

    source.stop().await;
    dest.stop().await;
    wait_for_cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_large_payload_transfer() {
    let cert_dir = tempdir().unwrap();
    create_test_certs(cert_dir.path());

    let _echo = start_echo_server(28008).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let dest_config = DestConfig {
        listen_ip: "127.0.0.1".to_string(),
        tunnel_port: 28014,
        exposed_services: vec![ServiceConfig {
            name: "large-payload".to_string(),
            port: 28028,
            target_ip: "127.0.0.1".to_string(),
            target_port: 28008,
            protocol: "tcp".to_string(),
            description: None,
        }],
        max_connections_per_service: 1000,
        connection_timeout_ms: 60000,
        target_connect_timeout_ms: 5000,
        connection_channel_size: 1024,
        connection_filter: ConnectionFilterConfig::default(),
        server_cert_path: cert_dir.path().join("server.crt"),
        server_key_path: cert_dir.path().join("server.key"),
        ca_cert_path: cert_dir.path().join("ca.crt"),
    };

    let crypto_config = default_crypto_config();
    let dest = Arc::new(
        DestContainer::new(dest_config, crypto_config)
            .await
            .unwrap(),
    );
    dest.start().await.unwrap();
    let dest_clone = dest.clone();
    tokio::spawn(async move {
        dest_clone.run().await.ok();
    });

    // Wait for destination to be ready
    wait_for_destination_ready().await;

    let source_config = SourceConfig {
        mode: SourceMode::Transparent,
        listen_ip: "127.0.0.1".to_string(),
        listen_port: 28028,
        dest_host: "127.0.0.1".to_string(),
        dest_tunnel_port: 28014,
        max_connections: 1000,
        connection_timeout_ms: 60000,
        keep_alive_interval_ms: 30000,
        heartbeat_interval_ms: 5000,
        heartbeat_timeout_ms: 10000,
        max_missed_pongs: 3,
        reconnection_enabled: false,
        max_reconnect_attempts: 0,
        initial_reconnect_delay_ms: 1000,
        max_reconnect_delay_ms: 30000,
        frame_buffer_size: 8192,
        connection_channel_size: 1024,
        circuit_breaker_window_secs: 60,
        circuit_breaker_max_restarts: 5,
        allowed_outbound: AllowedOutboundConfig::default(),
        exposed_ports: vec![ExposedPortConfig {
            port: 28028,
            protocol: ConfigProtocol::Tcp,
        }],
        client_cert_path: cert_dir.path().join("client.crt"),
        client_key_path: cert_dir.path().join("client.key"),
        ca_cert_path: cert_dir.path().join("ca.crt"),
    };

    let crypto_config = default_crypto_config();
    let source = Arc::new(
        SourceContainer::new(source_config, crypto_config)
            .await
            .unwrap(),
    );
    source.start().await.unwrap();
    let source_clone = source.clone();
    tokio::spawn(async move {
        if let Err(e) = source_clone.run().await {
            eprintln!("Source run() failed: {}", e);
        }
    });

    // Give time for listeners to bind
    tokio::time::sleep(Duration::from_secs(1)).await;

    let client = timeout(
        Duration::from_secs(5),
        TcpStream::connect("127.0.0.1:28028"),
    )
    .await
    .unwrap()
    .unwrap();

    let payload_size = 5 * 1024 * 1024;
    let large_payload = vec![0xAB; payload_size];

    let (mut read_half, mut write_half) = client.into_split();

    let write_payload = large_payload.clone();
    let write_handle = tokio::spawn(async move {
        write_half.write_all(&write_payload).await.unwrap();
        write_half
    });

    let mut response = vec![0u8; payload_size];
    timeout(Duration::from_secs(60), read_half.read_exact(&mut response))
        .await
        .expect("Large payload read timeout")
        .unwrap();

    let write_half = write_handle.await.unwrap();
    read_half.reunite(write_half).ok();

    assert_eq!(large_payload, response);

    source.stop().await;
    dest.stop().await;
    wait_for_cleanup().await;
}

// ============================================================================
// TEST 5: RAPID CONNECTION CHURN
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_rapid_connection_churn() {
    let cert_dir = tempdir().unwrap();
    create_test_certs(cert_dir.path());

    let _echo = start_echo_server(28009).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let dest_config = DestConfig {
        listen_ip: "127.0.0.1".to_string(),
        tunnel_port: 28015,
        exposed_services: vec![ServiceConfig {
            name: "churn-test".to_string(),
            port: 28029,
            target_ip: "127.0.0.1".to_string(),
            target_port: 28009,
            protocol: "tcp".to_string(),
            description: None,
        }],
        max_connections_per_service: 1000,
        connection_timeout_ms: 30000,
        target_connect_timeout_ms: 5000,
        connection_channel_size: 1024,
        connection_filter: ConnectionFilterConfig::default(),
        server_cert_path: cert_dir.path().join("server.crt"),
        server_key_path: cert_dir.path().join("server.key"),
        ca_cert_path: cert_dir.path().join("ca.crt"),
    };

    let crypto_config = default_crypto_config();
    let dest = Arc::new(
        DestContainer::new(dest_config, crypto_config)
            .await
            .unwrap(),
    );
    dest.start().await.unwrap();
    let dest_clone = dest.clone();
    tokio::spawn(async move {
        dest_clone.run().await.ok();
    });

    // Wait for destination to be ready
    wait_for_destination_ready().await;

    let source_config = SourceConfig {
        mode: SourceMode::Transparent,
        listen_ip: "127.0.0.1".to_string(),
        listen_port: 28029,
        dest_host: "127.0.0.1".to_string(),
        dest_tunnel_port: 28015,
        max_connections: 1000,
        connection_timeout_ms: 30000,
        keep_alive_interval_ms: 30000,
        heartbeat_interval_ms: 5000,
        heartbeat_timeout_ms: 10000,
        max_missed_pongs: 3,
        reconnection_enabled: false,
        max_reconnect_attempts: 0,
        initial_reconnect_delay_ms: 1000,
        max_reconnect_delay_ms: 30000,
        frame_buffer_size: 8192,
        connection_channel_size: 1024,
        circuit_breaker_window_secs: 60,
        circuit_breaker_max_restarts: 5,
        allowed_outbound: AllowedOutboundConfig::default(),
        exposed_ports: vec![ExposedPortConfig {
            port: 28029,
            protocol: ConfigProtocol::Tcp,
        }],
        client_cert_path: cert_dir.path().join("client.crt"),
        client_key_path: cert_dir.path().join("client.key"),
        ca_cert_path: cert_dir.path().join("ca.crt"),
    };

    let crypto_config = default_crypto_config();
    let source = Arc::new(
        SourceContainer::new(source_config, crypto_config)
            .await
            .unwrap(),
    );
    source.start().await.unwrap();
    let source_clone = source.clone();
    tokio::spawn(async move {
        if let Err(e) = source_clone.run().await {
            eprintln!("Source run() failed: {}", e);
        }
    });

    // Give time for listeners to bind
    tokio::time::sleep(Duration::from_secs(1)).await;

    // TEST: 200 rapid connect/send/close cycles
    for i in 0..200 {
        let mut client = timeout(
            Duration::from_secs(5),
            TcpStream::connect("127.0.0.1:28029"),
        )
        .await
        .unwrap()
        .unwrap();

        let data = format!("Churn {}", i);
        client.write_all(data.as_bytes()).await.unwrap();

        let mut resp = vec![0u8; data.len()];
        client.read_exact(&mut resp).await.unwrap();

        assert_eq!(data.as_bytes(), resp.as_slice());
        drop(client); // Immediate close
    }

    source.stop().await;
    dest.stop().await;
    wait_for_cleanup().await;
}

// ============================================================================
// EDGE CASE TESTS - Testing scenarios that can't be guaranteed by basic tests
// ============================================================================

// ============================================================================
// TEST 6: RACE CONDITIONS - Simultaneous Connect/Disconnect
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_race_condition_simultaneous_operations() {
    let cert_dir = tempdir().unwrap();
    create_test_certs(cert_dir.path());

    let _echo = start_echo_server(28010).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let dest_config = DestConfig {
        listen_ip: "127.0.0.1".to_string(),
        tunnel_port: 28016,
        exposed_services: vec![ServiceConfig {
            name: "race-test".to_string(),
            port: 28030,
            target_ip: "127.0.0.1".to_string(),
            target_port: 28010,
            protocol: "tcp".to_string(),
            description: None,
        }],
        max_connections_per_service: 5000,
        connection_timeout_ms: 30000,
        target_connect_timeout_ms: 5000,
        connection_channel_size: 1024,
        connection_filter: ConnectionFilterConfig::default(),
        server_cert_path: cert_dir.path().join("server.crt"),
        server_key_path: cert_dir.path().join("server.key"),
        ca_cert_path: cert_dir.path().join("ca.crt"),
    };

    let crypto_config = default_crypto_config();
    let dest = Arc::new(
        DestContainer::new(dest_config, crypto_config)
            .await
            .unwrap(),
    );
    dest.start().await.unwrap();
    let dest_clone = dest.clone();
    tokio::spawn(async move {
        dest_clone.run().await.ok();
    });

    wait_for_destination_ready().await;

    let source_config = SourceConfig {
        mode: SourceMode::Transparent,
        listen_ip: "127.0.0.1".to_string(),
        listen_port: 28030,
        dest_host: "127.0.0.1".to_string(),
        dest_tunnel_port: 28016,
        max_connections: 5000,
        connection_timeout_ms: 30000,
        keep_alive_interval_ms: 30000,
        heartbeat_interval_ms: 5000,
        heartbeat_timeout_ms: 10000,
        max_missed_pongs: 3,
        reconnection_enabled: false,
        max_reconnect_attempts: 0,
        initial_reconnect_delay_ms: 1000,
        max_reconnect_delay_ms: 30000,
        frame_buffer_size: 8192,
        connection_channel_size: 1024,
        circuit_breaker_window_secs: 60,
        circuit_breaker_max_restarts: 5,
        allowed_outbound: AllowedOutboundConfig::default(),
        exposed_ports: vec![ExposedPortConfig {
            port: 28030,
            protocol: ConfigProtocol::Tcp,
        }],
        client_cert_path: cert_dir.path().join("client.crt"),
        client_key_path: cert_dir.path().join("client.key"),
        ca_cert_path: cert_dir.path().join("ca.crt"),
    };

    let crypto_config = default_crypto_config();
    let source = Arc::new(
        SourceContainer::new(source_config, crypto_config)
            .await
            .unwrap(),
    );
    source.start().await.unwrap();
    let source_clone = source.clone();
    tokio::spawn(async move {
        source_clone.run().await.ok();
    });

    tokio::time::sleep(Duration::from_secs(1)).await;

    // TEST: 50 connections that all connect, send, receive, and disconnect simultaneously
    use tokio::task::JoinSet;
    let mut tasks = JoinSet::new();

    for i in 0..50 {
        tasks.spawn(async move {
            let mut client = TcpStream::connect("127.0.0.1:28030").await.unwrap();
            let data = format!("Race test {}", i);

            // All write simultaneously
            client.write_all(data.as_bytes()).await.unwrap();

            // All read simultaneously
            let mut resp = vec![0u8; data.len()];
            client.read_exact(&mut resp).await.unwrap();

            assert_eq!(data.as_bytes(), resp.as_slice());

            // All disconnect simultaneously (implicit via drop)
        });
    }

    let mut success_count = 0;
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
        success_count += 1;
    }
    assert_eq!(
        success_count, 50,
        "All simultaneous operations should succeed"
    );

    source.stop().await;
    dest.stop().await;
    wait_for_cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_heavy_load_1000_connections() {
    let cert_dir = tempdir().unwrap();
    create_test_certs(cert_dir.path());

    let _echo = start_echo_server(28035).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let dest_config = DestConfig {
        listen_ip: "127.0.0.1".to_string(),
        tunnel_port: 28036,
        exposed_services: vec![ServiceConfig {
            name: "heavy-load".to_string(),
            port: 28037,
            target_ip: "127.0.0.1".to_string(),
            target_port: 28035,
            protocol: "tcp".to_string(),
            description: None,
        }],
        max_connections_per_service: 10000,
        connection_timeout_ms: 60000,
        target_connect_timeout_ms: 5000,
        connection_channel_size: 1024,
        connection_filter: ConnectionFilterConfig::default(),
        server_cert_path: cert_dir.path().join("server.crt"),
        server_key_path: cert_dir.path().join("server.key"),
        ca_cert_path: cert_dir.path().join("ca.crt"),
    };

    let crypto_config = default_crypto_config();
    let dest = Arc::new(
        DestContainer::new(dest_config, crypto_config)
            .await
            .unwrap(),
    );
    dest.start().await.unwrap();
    let dest_clone = dest.clone();
    tokio::spawn(async move {
        dest_clone.run().await.ok();
    });

    wait_for_destination_ready().await;

    let source_config = SourceConfig {
        mode: SourceMode::Transparent,
        listen_ip: "127.0.0.1".to_string(),
        listen_port: 28037,
        dest_host: "127.0.0.1".to_string(),
        dest_tunnel_port: 28036,
        max_connections: 10000,
        connection_timeout_ms: 60000,
        keep_alive_interval_ms: 30000,
        heartbeat_interval_ms: 5000,
        heartbeat_timeout_ms: 10000,
        max_missed_pongs: 3,
        reconnection_enabled: false,
        max_reconnect_attempts: 0,
        initial_reconnect_delay_ms: 1000,
        max_reconnect_delay_ms: 30000,
        frame_buffer_size: 8192,
        connection_channel_size: 1024,
        circuit_breaker_window_secs: 60,
        circuit_breaker_max_restarts: 5,
        allowed_outbound: AllowedOutboundConfig::default(),
        exposed_ports: vec![ExposedPortConfig {
            port: 28037,
            protocol: ConfigProtocol::Tcp,
        }],
        client_cert_path: cert_dir.path().join("client.crt"),
        client_key_path: cert_dir.path().join("client.key"),
        ca_cert_path: cert_dir.path().join("ca.crt"),
    };

    let crypto_config = default_crypto_config();
    let source = Arc::new(
        SourceContainer::new(source_config, crypto_config)
            .await
            .unwrap(),
    );
    source.start().await.unwrap();
    let source_clone = source.clone();
    tokio::spawn(async move {
        source_clone.run().await.ok();
    });

    tokio::time::sleep(Duration::from_secs(2)).await;

    use tokio::task::JoinSet;
    let mut tasks = JoinSet::new();

    for i in 0..1000 {
        tasks.spawn(async move {
            let mut client = timeout(
                Duration::from_secs(30),
                TcpStream::connect("127.0.0.1:28037"),
            )
            .await
            .unwrap_or_else(|_| panic!("Conn {} timeout", i))
            .unwrap_or_else(|_| panic!("Conn {} failed", i));

            let data = format!("Load test {}", i);
            client.write_all(data.as_bytes()).await.unwrap();

            let mut resp = vec![0u8; data.len()];
            timeout(Duration::from_secs(30), client.read_exact(&mut resp))
                .await
                .unwrap_or_else(|_| panic!("Conn {} read timeout", i))
                .unwrap_or_else(|_| panic!("Conn {} read failed", i));

            assert_eq!(data.as_bytes(), resp.as_slice());
        });
    }

    let mut count = 0;
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
        count += 1;
        if count % 100 == 0 {
            println!("Completed {} / 1000 connections", count);
        }
    }
    assert_eq!(count, 1000, "All 1000 connections should succeed");

    source.stop().await;
    dest.stop().await;
    wait_for_cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_memory_stress_sequential_connections() {
    let cert_dir = tempdir().unwrap();
    create_test_certs(cert_dir.path());

    let _echo = start_echo_server(28038).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let dest_config = DestConfig {
        listen_ip: "127.0.0.1".to_string(),
        tunnel_port: 28039,
        exposed_services: vec![ServiceConfig {
            name: "memory-stress".to_string(),
            port: 28040,
            target_ip: "127.0.0.1".to_string(),
            target_port: 28038,
            protocol: "tcp".to_string(),
            description: None,
        }],
        max_connections_per_service: 3000,
        connection_timeout_ms: 30000,
        target_connect_timeout_ms: 5000,
        connection_channel_size: 1024,
        connection_filter: ConnectionFilterConfig::default(),
        server_cert_path: cert_dir.path().join("server.crt"),
        server_key_path: cert_dir.path().join("server.key"),
        ca_cert_path: cert_dir.path().join("ca.crt"),
    };

    let crypto_config = default_crypto_config();
    let dest = Arc::new(
        DestContainer::new(dest_config, crypto_config)
            .await
            .unwrap(),
    );
    dest.start().await.unwrap();
    let dest_clone = dest.clone();
    tokio::spawn(async move {
        dest_clone.run().await.ok();
    });

    wait_for_destination_ready().await;

    let source_config = SourceConfig {
        mode: SourceMode::Transparent,
        listen_ip: "127.0.0.1".to_string(),
        listen_port: 28040,
        dest_host: "127.0.0.1".to_string(),
        dest_tunnel_port: 28039,
        max_connections: 3000,
        connection_timeout_ms: 30000,
        keep_alive_interval_ms: 30000,
        heartbeat_interval_ms: 5000,
        heartbeat_timeout_ms: 10000,
        max_missed_pongs: 3,
        reconnection_enabled: false,
        max_reconnect_attempts: 0,
        initial_reconnect_delay_ms: 1000,
        max_reconnect_delay_ms: 30000,
        frame_buffer_size: 8192,
        connection_channel_size: 1024,
        circuit_breaker_window_secs: 60,
        circuit_breaker_max_restarts: 5,
        allowed_outbound: AllowedOutboundConfig::default(),
        exposed_ports: vec![ExposedPortConfig {
            port: 28040,
            protocol: ConfigProtocol::Tcp,
        }],
        client_cert_path: cert_dir.path().join("client.crt"),
        client_key_path: cert_dir.path().join("client.key"),
        ca_cert_path: cert_dir.path().join("ca.crt"),
    };

    let crypto_config = default_crypto_config();
    let source = Arc::new(
        SourceContainer::new(source_config, crypto_config)
            .await
            .unwrap(),
    );
    source.start().await.unwrap();
    let source_clone = source.clone();
    tokio::spawn(async move {
        source_clone.run().await.ok();
    });

    tokio::time::sleep(Duration::from_secs(1)).await;

    for i in 0..2000 {
        let mut client = TcpStream::connect("127.0.0.1:28040").await.unwrap();
        let data = format!("Memory test {}", i);
        client.write_all(data.as_bytes()).await.unwrap();

        let mut resp = vec![0u8; data.len()];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(data.as_bytes(), resp.as_slice());

        drop(client);

        if i % 200 == 0 && i > 0 {
            println!("Completed {} / 2000 sequential connections", i);
        }
    }

    source.stop().await;
    dest.stop().await;
    wait_for_cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_interleaved_data_integrity() {
    let cert_dir = tempdir().unwrap();
    create_test_certs(cert_dir.path());

    let _echo = start_echo_server(28041).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let dest_config = DestConfig {
        listen_ip: "127.0.0.1".to_string(),
        tunnel_port: 28042,
        exposed_services: vec![ServiceConfig {
            name: "interleaved".to_string(),
            port: 28043,
            target_ip: "127.0.0.1".to_string(),
            target_port: 28041,
            protocol: "tcp".to_string(),
            description: None,
        }],
        max_connections_per_service: 1000,
        connection_timeout_ms: 30000,
        target_connect_timeout_ms: 5000,
        connection_channel_size: 1024,
        connection_filter: ConnectionFilterConfig::default(),
        server_cert_path: cert_dir.path().join("server.crt"),
        server_key_path: cert_dir.path().join("server.key"),
        ca_cert_path: cert_dir.path().join("ca.crt"),
    };

    let crypto_config = default_crypto_config();
    let dest = Arc::new(
        DestContainer::new(dest_config, crypto_config)
            .await
            .unwrap(),
    );
    dest.start().await.unwrap();
    let dest_clone = dest.clone();
    tokio::spawn(async move {
        dest_clone.run().await.ok();
    });

    wait_for_destination_ready().await;

    let source_config = SourceConfig {
        mode: SourceMode::Transparent,
        listen_ip: "127.0.0.1".to_string(),
        listen_port: 28043,
        dest_host: "127.0.0.1".to_string(),
        dest_tunnel_port: 28042,
        max_connections: 1000,
        connection_timeout_ms: 30000,
        keep_alive_interval_ms: 30000,
        heartbeat_interval_ms: 5000,
        heartbeat_timeout_ms: 10000,
        max_missed_pongs: 3,
        reconnection_enabled: false,
        max_reconnect_attempts: 0,
        initial_reconnect_delay_ms: 1000,
        max_reconnect_delay_ms: 30000,
        frame_buffer_size: 8192,
        connection_channel_size: 1024,
        circuit_breaker_window_secs: 60,
        circuit_breaker_max_restarts: 5,
        allowed_outbound: AllowedOutboundConfig::default(),
        exposed_ports: vec![ExposedPortConfig {
            port: 28043,
            protocol: ConfigProtocol::Tcp,
        }],
        client_cert_path: cert_dir.path().join("client.crt"),
        client_key_path: cert_dir.path().join("client.key"),
        ca_cert_path: cert_dir.path().join("ca.crt"),
    };

    let crypto_config = default_crypto_config();
    let source = Arc::new(
        SourceContainer::new(source_config, crypto_config)
            .await
            .unwrap(),
    );
    source.start().await.unwrap();
    let source_clone = source.clone();
    tokio::spawn(async move {
        source_clone.run().await.ok();
    });

    tokio::time::sleep(Duration::from_secs(1)).await;

    use tokio::task::JoinSet;
    let mut tasks = JoinSet::new();

    for conn_id in 0..20 {
        tasks.spawn(async move {
            let mut client = TcpStream::connect("127.0.0.1:28043").await.unwrap();

            // Each connection sends 10 messages
            for msg_id in 0..10 {
                let data = format!("Conn {} Msg {}", conn_id, msg_id);
                client.write_all(data.as_bytes()).await.unwrap();

                let mut resp = vec![0u8; data.len()];
                client.read_exact(&mut resp).await.unwrap();

                assert_eq!(
                    data.as_bytes(),
                    resp.as_slice(),
                    "Data corruption detected for connection {} message {}",
                    conn_id,
                    msg_id
                );

                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
    }

    let mut success_count = 0;
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
        success_count += 1;
    }
    assert_eq!(
        success_count, 20,
        "All interleaved connections should succeed"
    );

    source.stop().await;
    dest.stop().await;
    wait_for_cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_connection_drop_resilience() {
    let cert_dir = tempdir().unwrap();
    create_test_certs(cert_dir.path());

    let _echo = start_echo_server(28044).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let dest_config = DestConfig {
        listen_ip: "127.0.0.1".to_string(),
        tunnel_port: 28045,
        exposed_services: vec![ServiceConfig {
            name: "drop-test".to_string(),
            port: 28046,
            target_ip: "127.0.0.1".to_string(),
            target_port: 28044,
            protocol: "tcp".to_string(),
            description: None,
        }],
        max_connections_per_service: 1000,
        connection_timeout_ms: 30000,
        target_connect_timeout_ms: 5000,
        connection_channel_size: 1024,
        connection_filter: ConnectionFilterConfig::default(),
        server_cert_path: cert_dir.path().join("server.crt"),
        server_key_path: cert_dir.path().join("server.key"),
        ca_cert_path: cert_dir.path().join("ca.crt"),
    };

    let crypto_config = default_crypto_config();
    let dest = Arc::new(
        DestContainer::new(dest_config, crypto_config)
            .await
            .unwrap(),
    );
    dest.start().await.unwrap();
    let dest_clone = dest.clone();
    tokio::spawn(async move {
        dest_clone.run().await.ok();
    });

    wait_for_destination_ready().await;

    let source_config = SourceConfig {
        mode: SourceMode::Transparent,
        listen_ip: "127.0.0.1".to_string(),
        listen_port: 28046,
        dest_host: "127.0.0.1".to_string(),
        dest_tunnel_port: 28045,
        max_connections: 1000,
        connection_timeout_ms: 30000,
        keep_alive_interval_ms: 30000,
        heartbeat_interval_ms: 5000,
        heartbeat_timeout_ms: 10000,
        max_missed_pongs: 3,
        reconnection_enabled: false,
        max_reconnect_attempts: 0,
        initial_reconnect_delay_ms: 1000,
        max_reconnect_delay_ms: 30000,
        frame_buffer_size: 8192,
        connection_channel_size: 1024,
        circuit_breaker_window_secs: 60,
        circuit_breaker_max_restarts: 5,
        allowed_outbound: AllowedOutboundConfig::default(),
        exposed_ports: vec![ExposedPortConfig {
            port: 28046,
            protocol: ConfigProtocol::Tcp,
        }],
        client_cert_path: cert_dir.path().join("client.crt"),
        client_key_path: cert_dir.path().join("client.key"),
        ca_cert_path: cert_dir.path().join("ca.crt"),
    };

    let crypto_config = default_crypto_config();
    let source = Arc::new(
        SourceContainer::new(source_config, crypto_config)
            .await
            .unwrap(),
    );
    source.start().await.unwrap();
    let source_clone = source.clone();
    tokio::spawn(async move {
        source_clone.run().await.ok();
    });

    tokio::time::sleep(Duration::from_secs(1)).await;

    for i in 0..50 {
        let client = TcpStream::connect("127.0.0.1:28046").await.unwrap();

        if i % 2 == 0 {
            drop(client);
        } else {
            let mut client = client;
            let data = format!("Drop test {}", i);
            client.write_all(data.as_bytes()).await.unwrap();
            drop(client);
        }
    }

    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut client = TcpStream::connect("127.0.0.1:28046").await.unwrap();
    let data = b"System still works";
    client.write_all(data).await.unwrap();
    let mut resp = vec![0u8; data.len()];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(
        data,
        resp.as_slice(),
        "System should recover from dropped connections"
    );

    source.stop().await;
    dest.stop().await;
    wait_for_cleanup().await;
}
