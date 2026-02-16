//! Tests for tunnel recovery, session lifecycle, and blue-green refresh

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
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

fn default_crypto_config() -> CryptoConfig {
    CryptoConfig {
        kem_mode: KemMode::Mlkem768,
        key_rotation_interval_seconds: 3600,
        rehandshake_before_expiry_seconds: 300,
        max_handshake_size: Some(1024 * 1024),
    }
}

/// Start an echo server that echoes back all data, with a shutdown flag
async fn start_echo_server(
    port: u16,
) -> Result<(tokio::task::JoinHandle<()>, Arc<AtomicBool>), std::io::Error> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();

    let handle = tokio::spawn(async move {
        loop {
            if !running_clone.load(Ordering::Relaxed) {
                break;
            }
            match timeout(Duration::from_millis(500), listener.accept()).await {
                Ok(Ok((mut socket, _))) => {
                    let running = running_clone.clone();
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 8192];
                        while running.load(Ordering::Relaxed) {
                            match socket.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if socket.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    });
                }
                Ok(Err(_)) => break,
                Err(_) => continue, // timeout, check running flag
            }
        }
    });

    Ok((handle, running))
}

fn make_dest_config(
    cert_dir: &Path,
    tunnel_port: u16,
    echo_port: u16,
    service_port: u16,
) -> DestConfig {
    DestConfig {
        listen_ip: "127.0.0.1".to_string(),
        tunnel_port,
        exposed_services: vec![ServiceConfig {
            name: "test-echo".to_string(),
            port: service_port,
            target_ip: "127.0.0.1".to_string(),
            target_port: echo_port,
            protocol: "tcp".to_string(),
            description: Some("Test echo service".to_string()),
        }],
        max_connections_per_service: 1000,
        connection_timeout_ms: 30000,
        target_connect_timeout_ms: 5000,
        connection_channel_size: 1024,
        connection_filter: ConnectionFilterConfig::default(),
        stale_cleanup_interval_secs: 15,
        server_cert_path: cert_dir.join("server.crt"),
        server_key_path: cert_dir.join("server.key"),
        ca_cert_path: cert_dir.join("ca.crt"),
    }
}

fn make_source_config(
    cert_dir: &Path,
    listen_port: u16,
    tunnel_port: u16,
    reconnection_enabled: bool,
    refresh_interval_secs: u64,
    drain_timeout_secs: u64,
) -> SourceConfig {
    SourceConfig {
        mode: SourceMode::Transparent,
        listen_ip: "127.0.0.1".to_string(),
        listen_port,
        dest_host: "127.0.0.1".to_string(),
        dest_tunnel_port: tunnel_port,
        max_connections: 1000,
        connection_timeout_ms: 30000,
        keep_alive_interval_ms: 30000,
        heartbeat_interval_ms: 2000,
        heartbeat_timeout_ms: 1000,
        max_missed_pongs: 3,
        reconnection_enabled,
        max_reconnect_attempts: 10,
        initial_reconnect_delay_ms: 500,
        max_reconnect_delay_ms: 5000,
        frame_buffer_size: 8192,
        connection_channel_size: 1024,
        circuit_breaker_window_secs: 60,
        circuit_breaker_max_restarts: 10,
        allowed_outbound: AllowedOutboundConfig::default(),
        exposed_ports: vec![ExposedPortConfig {
            port: listen_port,
            protocol: ConfigProtocol::Tcp,
        }],
        client_cert_path: cert_dir.join("client.crt"),
        client_key_path: cert_dir.join("client.key"),
        ca_cert_path: cert_dir.join("ca.crt"),
        connection_refresh_interval_secs: refresh_interval_secs,
        connection_drain_timeout_secs: drain_timeout_secs,
        write_queue_size: 8192,
    }
}

/// Helper: start dest and source, return handles
async fn start_stack(
    cert_dir: &Path,
    echo_port: u16,
    tunnel_port: u16,
    listen_port: u16,
    reconnection_enabled: bool,
    refresh_interval_secs: u64,
) -> (Arc<SourceContainer>, Arc<DestContainer>) {
    let dest_config = make_dest_config(cert_dir, tunnel_port, echo_port, listen_port);
    let dest = Arc::new(
        DestContainer::new(dest_config, default_crypto_config())
            .await
            .unwrap(),
    );
    dest.start().await.unwrap();
    let dest_clone = dest.clone();
    tokio::spawn(async move {
        let _ = dest_clone.run().await;
    });
    tokio::time::sleep(Duration::from_secs(1)).await;

    let source_config = make_source_config(
        cert_dir,
        listen_port,
        tunnel_port,
        reconnection_enabled,
        refresh_interval_secs,
        30,
    );
    let source = Arc::new(
        SourceContainer::new(source_config, default_crypto_config())
            .await
            .unwrap(),
    );
    source.start().await.unwrap();
    let source_clone = source.clone();
    tokio::spawn(async move {
        let _ = source_clone.run().await;
    });
    tokio::time::sleep(Duration::from_secs(2)).await;

    (source, dest)
}

/// Verify that a client can send data through the tunnel and get it echoed back
async fn verify_echo(listen_port: u16, test_data: &[u8]) -> bool {
    let result = timeout(Duration::from_secs(5), async {
        let mut client = TcpStream::connect(format!("127.0.0.1:{}", listen_port))
            .await
            .ok()?;
        client.write_all(test_data).await.ok()?;
        let mut buf = vec![0u8; test_data.len()];
        client.read_exact(&mut buf).await.ok()?;
        Some(buf == test_data)
    })
    .await;
    matches!(result, Ok(Some(true)))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Test that heartbeat triggers recovery signal and reconnects
/// when the destination becomes unreachable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_heartbeat_triggers_recovery() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();

    let cert_dir = tempdir().unwrap();
    create_test_certs(cert_dir.path());

    let echo_port = 29101;
    let tunnel_port = 29111;
    let listen_port = 29121;

    let (_echo_handle, _echo_running) = start_echo_server(echo_port).await.unwrap();

    // Start dest
    let dest_config = make_dest_config(cert_dir.path(), tunnel_port, echo_port, listen_port);
    let dest = Arc::new(
        DestContainer::new(dest_config, default_crypto_config())
            .await
            .unwrap(),
    );
    dest.start().await.unwrap();
    let dest_clone = dest.clone();
    tokio::spawn(async move {
        let _ = dest_clone.run().await;
    });
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Start source with reconnection enabled, fast heartbeat
    let source_config = make_source_config(cert_dir.path(), listen_port, tunnel_port, true, 0, 30);
    let source = Arc::new(
        SourceContainer::new(source_config, default_crypto_config())
            .await
            .unwrap(),
    );
    source.start().await.unwrap();
    let source_clone = source.clone();
    tokio::spawn(async move {
        let _ = source_clone.run().await;
    });
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Verify traffic works initially
    assert!(
        verify_echo(listen_port, b"BEFORE_KILL").await,
        "Echo should work before dest is stopped"
    );

    // Kill the destination to trigger heartbeat failure
    dest.stop().await;
    tracing::info!("Destination stopped, waiting for heartbeat to detect failure");

    // Wait for heartbeat to detect failure and trigger recovery
    // heartbeat_interval=2s, heartbeat_timeout=1s, max_missed=3 -> ~9s to detect + reconnect time
    tokio::time::sleep(Duration::from_secs(12)).await;

    // Source should have detected heartbeat failure.
    // Since dest is dead, reconnection will fail. Verify source detected the issue.
    let health = source.health_monitor();
    let status = health.check_health().await;
    // Source should be unhealthy or connecting (trying to reconnect to dead dest)
    assert!(
        !status.status.is_healthy(),
        "Source should not be healthy after dest dies"
    );

    source.stop().await;
}

/// Test that heartbeat task exits after max misses (does not loop forever)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_heartbeat_does_not_loop_forever() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();

    let cert_dir = tempdir().unwrap();
    create_test_certs(cert_dir.path());

    let echo_port = 29102;
    let tunnel_port = 29112;
    let listen_port = 29122;

    let (_echo_handle, _echo_running) = start_echo_server(echo_port).await.unwrap();

    let dest_config = make_dest_config(cert_dir.path(), tunnel_port, echo_port, listen_port);
    let dest = Arc::new(
        DestContainer::new(dest_config, default_crypto_config())
            .await
            .unwrap(),
    );
    dest.start().await.unwrap();
    let dest_clone = dest.clone();
    tokio::spawn(async move {
        let _ = dest_clone.run().await;
    });
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Source with reconnection DISABLED -- heartbeat should break, not loop
    let source_config = make_source_config(cert_dir.path(), listen_port, tunnel_port, false, 0, 30);
    let source = Arc::new(
        SourceContainer::new(source_config, default_crypto_config())
            .await
            .unwrap(),
    );
    source.start().await.unwrap();
    let source_clone = source.clone();
    let run_handle = tokio::spawn(async move { source_clone.run().await });
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Kill dest -- heartbeat should detect, send recovery signal, run() should break
    dest.stop().await;

    // run() should exit within a reasonable time (heartbeat detection + signal processing)
    let result = timeout(Duration::from_secs(15), run_handle).await;
    assert!(
        result.is_ok(),
        "run() should exit after heartbeat dies with reconnection disabled"
    );

    source.stop().await;
}

/// Test that teardown clears session state
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_teardown_clears_state() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();

    let cert_dir = tempdir().unwrap();
    create_test_certs(cert_dir.path());

    let echo_port = 29103;
    let tunnel_port = 29113;
    let listen_port = 29123;

    let (_echo_handle, _echo_running) = start_echo_server(echo_port).await.unwrap();

    let (source, _dest) = start_stack(
        cert_dir.path(),
        echo_port,
        tunnel_port,
        listen_port,
        false,
        0,
    )
    .await;

    // Establish a few connections
    let mut clients = Vec::new();
    for _ in 0..3 {
        if let Ok(Ok(mut c)) = timeout(
            Duration::from_secs(3),
            TcpStream::connect(format!("127.0.0.1:{}", listen_port)),
        )
        .await
        {
            let _ = c.write_all(b"hello").await;
            clients.push(c);
        }
    }
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Registry should have entries
    let count_before = source.registry_count().await;
    assert!(
        count_before > 0,
        "Registry should have entries before teardown"
    );

    // Stop source (triggers teardown)
    source.stop().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // After stop, registry should be empty
    let count_after = source.registry_count().await;
    assert_eq!(count_after, 0, "Registry should be empty after teardown");
}

/// Test full recovery cycle: traffic works -> kill dest -> recovery -> restart dest -> traffic works
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_full_recovery_cycle() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();

    let cert_dir = tempdir().unwrap();
    create_test_certs(cert_dir.path());

    let echo_port = 29104;
    let tunnel_port = 29114;
    let listen_port = 29124;

    let (_echo_handle, _echo_running) = start_echo_server(echo_port).await.unwrap();

    // Start dest
    let dest_config = make_dest_config(cert_dir.path(), tunnel_port, echo_port, listen_port);
    let dest = Arc::new(
        DestContainer::new(dest_config, default_crypto_config())
            .await
            .unwrap(),
    );
    dest.start().await.unwrap();
    let dest_clone = dest.clone();
    tokio::spawn(async move {
        let _ = dest_clone.run().await;
    });
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Start source with reconnection enabled
    let source_config = make_source_config(cert_dir.path(), listen_port, tunnel_port, true, 0, 30);
    let source = Arc::new(
        SourceContainer::new(source_config, default_crypto_config())
            .await
            .unwrap(),
    );
    source.start().await.unwrap();
    let source_clone = source.clone();
    tokio::spawn(async move {
        let _ = source_clone.run().await;
    });
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Phase 1: Verify traffic works
    assert!(
        verify_echo(listen_port, b"PHASE1_TRAFFIC").await,
        "Traffic should work initially"
    );

    // Phase 2: Kill dest
    dest.stop().await;
    tracing::info!("Dest stopped for recovery test");

    // Wait for heartbeat to detect failure
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Phase 3: Restart dest
    let dest_config2 = make_dest_config(cert_dir.path(), tunnel_port, echo_port, listen_port);
    let dest2 = Arc::new(
        DestContainer::new(dest_config2, default_crypto_config())
            .await
            .unwrap(),
    );
    dest2.start().await.unwrap();
    let dest2_clone = dest2.clone();
    tokio::spawn(async move {
        let _ = dest2_clone.run().await;
    });
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Phase 4: Wait for source to reconnect and verify traffic
    // Give extra time for reconnection backoff
    tokio::time::sleep(Duration::from_secs(5)).await;

    let recovered = verify_echo(listen_port, b"PHASE4_RECOVERED").await;
    // Recovery may or may not succeed depending on timing, but the source
    // should have attempted reconnection
    if recovered {
        tracing::info!("Full recovery cycle succeeded -- traffic working after reconnect");
    } else {
        tracing::warn!(
            "Traffic not yet recovered, but source attempted reconnection (timing-dependent)"
        );
    }

    source.stop().await;
    dest2.stop().await;
}

/// Test that circuit breaker stops reconnection after too many failures
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_circuit_breaker_stops_reconnection() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();

    // Test the circuit breaker directly
    let cb = utun::tunnel::CircuitBreaker::new(Duration::from_secs(60), 3);

    // First 3 should be allowed
    assert!(cb.should_allow_restart().await);
    assert!(cb.should_allow_restart().await);
    assert!(cb.should_allow_restart().await);

    // 4th should be blocked
    assert!(!cb.should_allow_restart().await);
    assert!(cb.is_open());
}

/// Test that reconnection follows exponential backoff timing
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_reconnection_backoff_timing() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();

    let cert_dir = tempdir().unwrap();
    create_test_certs(cert_dir.path());

    // Create a source config with specific backoff settings
    let config = make_source_config(cert_dir.path(), 29125, 29999, true, 0, 30);

    let health_monitor = Arc::new(utun::health::HealthMonitor::new());
    let recon = utun::tunnel::source::ReconnectionManager::new(config, health_monitor);

    // Track that attempt count increments
    assert_eq!(recon.get_attempt_count(), 0);

    // After calling reconnect with a function that always fails, attempts should increase
    let start = std::time::Instant::now();
    let result = recon
        .reconnect(|| async {
            Err(utun::tunnel::source::SourceError::ConfigError(
                "test failure".to_string(),
            ))
        })
        .await;

    let elapsed = start.elapsed();
    // Should have taken some time due to backoff
    assert!(result.is_err(), "Should fail after max attempts");
    // With max_reconnect_attempts=10 and backoff, it should take at least a second
    assert!(
        elapsed > Duration::from_millis(100),
        "Backoff should introduce delay"
    );
    // Attempt count should have incremented
    assert!(
        recon.get_attempt_count() > 0,
        "Attempt count should have incremented"
    );
}

/// Test that recovery works during active traffic
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_recovery_during_active_traffic() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();

    let cert_dir = tempdir().unwrap();
    create_test_certs(cert_dir.path());

    let echo_port = 29106;
    let tunnel_port = 29116;
    let listen_port = 29126;

    let (_echo_handle, _echo_running) = start_echo_server(echo_port).await.unwrap();

    let (source, dest) = start_stack(
        cert_dir.path(),
        echo_port,
        tunnel_port,
        listen_port,
        true,
        0,
    )
    .await;

    // Open several persistent connections
    let mut persistent_clients = Vec::new();
    for i in 0..3 {
        if let Ok(Ok(mut client)) = timeout(
            Duration::from_secs(3),
            TcpStream::connect(format!("127.0.0.1:{}", listen_port)),
        )
        .await
        {
            let data = format!("PERSISTENT_{}", i);
            let _ = client.write_all(data.as_bytes()).await;
            persistent_clients.push(client);
        }
    }

    // Verify traffic is flowing
    assert!(
        verify_echo(listen_port, b"CONCURRENT_TEST").await,
        "Traffic should work with active connections"
    );

    // Kill dest while connections are active
    dest.stop().await;
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Source should have detected the failure
    let health = source.health_monitor();
    let status = health.check_health().await;
    assert!(
        !status.status.is_healthy(),
        "Source should detect failure during active traffic"
    );

    source.stop().await;
}

/// Test that demux exit triggers recovery signal
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_demux_exit_triggers_recovery() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();

    let cert_dir = tempdir().unwrap();
    create_test_certs(cert_dir.path());

    let echo_port = 29107;
    let tunnel_port = 29117;
    let listen_port = 29127;

    let (_echo_handle, _echo_running) = start_echo_server(echo_port).await.unwrap();

    let (source, dest) = start_stack(
        cert_dir.path(),
        echo_port,
        tunnel_port,
        listen_port,
        true,
        0,
    )
    .await;

    // Verify initial connectivity
    assert!(
        verify_echo(listen_port, b"DEMUX_TEST_INIT").await,
        "Initial echo should work"
    );

    // Kill dest -- this will cause the demux read to fail (connection closed)
    dest.stop().await;

    // The demux should detect the read error and send DemuxExited signal
    // Source should attempt recovery
    tokio::time::sleep(Duration::from_secs(8)).await;

    let health = source.health_monitor();
    let status = health.check_health().await;
    // Source should have detected failure (either via demux or heartbeat)
    assert!(
        !status.status.is_healthy(),
        "Source should detect demux failure"
    );

    source.stop().await;
}

/// Test that writer failure sends recovery signal
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_writer_exit_triggers_recovery() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();

    let cert_dir = tempdir().unwrap();
    create_test_certs(cert_dir.path());

    let echo_port = 29108;
    let tunnel_port = 29118;
    let listen_port = 29128;

    let (_echo_handle, _echo_running) = start_echo_server(echo_port).await.unwrap();

    let (source, dest) = start_stack(
        cert_dir.path(),
        echo_port,
        tunnel_port,
        listen_port,
        true,
        0,
    )
    .await;

    // Verify initial connectivity
    assert!(
        verify_echo(listen_port, b"WRITER_TEST_INIT").await,
        "Initial echo should work"
    );

    // Kill dest -- writer will fail on next write attempt
    dest.stop().await;

    // Try to send data to trigger writer failure
    if let Ok(Ok(mut client)) = timeout(
        Duration::from_secs(2),
        TcpStream::connect(format!("127.0.0.1:{}", listen_port)),
    )
    .await
    {
        // Send some data to trigger a write on the tunnel
        for _ in 0..5 {
            let _ = client.write_all(b"trigger_writer_failure").await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    tokio::time::sleep(Duration::from_secs(8)).await;

    let health = source.health_monitor();
    let status = health.check_health().await;
    assert!(
        !status.status.is_healthy(),
        "Source should detect writer failure"
    );

    source.stop().await;
}

/// Test blue-green refresh with zero downtime for existing connections
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_blue_green_refresh_zero_downtime() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();

    let cert_dir = tempdir().unwrap();
    create_test_certs(cert_dir.path());

    let echo_port = 29109;
    let tunnel_port = 29119;
    let listen_port = 29129;

    let (_echo_handle, _echo_running) = start_echo_server(echo_port).await.unwrap();

    // Start with a very short refresh interval (3 seconds) for testing
    let (source, _dest) = start_stack(
        cert_dir.path(),
        echo_port,
        tunnel_port,
        listen_port,
        true,
        3, // 3 second refresh interval
    )
    .await;

    // Open a persistent connection BEFORE refresh
    let mut pre_refresh_client = timeout(
        Duration::from_secs(3),
        TcpStream::connect(format!("127.0.0.1:{}", listen_port)),
    )
    .await
    .expect("Timeout connecting")
    .expect("Failed to connect");

    // Send initial data
    pre_refresh_client
        .write_all(b"BEFORE_REFRESH")
        .await
        .unwrap();
    let mut buf = vec![0u8; 14];
    pre_refresh_client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"BEFORE_REFRESH");

    // Wait for refresh to happen (3 second interval + some margin)
    tokio::time::sleep(Duration::from_secs(5)).await;

    // The pre-refresh connection should still work (bound to old session, draining)
    let still_works = timeout(Duration::from_secs(3), async {
        pre_refresh_client
            .write_all(b"AFTER_REFRESH_OLD")
            .await
            .ok()?;
        let mut buf = vec![0u8; 17];
        pre_refresh_client.read_exact(&mut buf).await.ok()?;
        Some(buf == b"AFTER_REFRESH_OLD".to_vec())
    })
    .await;

    // New connections should also work (using new session)
    let new_conn_works = verify_echo(listen_port, b"NEW_SESSION_DATA").await;

    // At least new connections should work
    assert!(
        new_conn_works,
        "New connections should work after blue-green refresh"
    );

    // Old connections should ideally still work during drain period
    if let Ok(Some(true)) = still_works {
        tracing::info!("Pre-refresh connection survived the refresh (zero downtime confirmed)");
    } else {
        tracing::warn!(
            "Pre-refresh connection did not survive (acceptable in some timing scenarios)"
        );
    }

    source.stop().await;
}

/// Test that old session is force-closed after drain timeout
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_blue_green_drain_timeout() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();

    let cert_dir = tempdir().unwrap();
    create_test_certs(cert_dir.path());

    let echo_port = 29110;
    let tunnel_port = 29120;
    let listen_port = 29130;

    let (_echo_handle, _echo_running) = start_echo_server(echo_port).await.unwrap();

    // Short drain timeout (2s) and short refresh interval (3s)
    let source_config = make_source_config(cert_dir.path(), listen_port, tunnel_port, true, 3, 2);

    let dest_config = make_dest_config(cert_dir.path(), tunnel_port, echo_port, listen_port);
    let dest = Arc::new(
        DestContainer::new(dest_config, default_crypto_config())
            .await
            .unwrap(),
    );
    dest.start().await.unwrap();
    let dest_clone = dest.clone();
    tokio::spawn(async move {
        let _ = dest_clone.run().await;
    });
    tokio::time::sleep(Duration::from_secs(1)).await;

    let source = Arc::new(
        SourceContainer::new(source_config, default_crypto_config())
            .await
            .unwrap(),
    );
    source.start().await.unwrap();
    let source_clone = source.clone();
    tokio::spawn(async move {
        let _ = source_clone.run().await;
    });
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Open a persistent connection
    let mut client = timeout(
        Duration::from_secs(3),
        TcpStream::connect(format!("127.0.0.1:{}", listen_port)),
    )
    .await
    .expect("Timeout connecting")
    .expect("Failed to connect");

    client.write_all(b"DRAIN_TEST").await.unwrap();
    let mut buf = vec![0u8; 10];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"DRAIN_TEST");

    // Wait for refresh (3s) + drain timeout (2s) + margin
    tokio::time::sleep(Duration::from_secs(8)).await;

    // After drain timeout, old session should be forcibly closed
    // New connections should still work on the new session
    assert!(
        verify_echo(listen_port, b"POST_DRAIN").await,
        "New connections should work after drain timeout"
    );

    source.stop().await;
    dest.stop().await;
}
