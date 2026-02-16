//! Duration and stress tests for UTun tunnel stability.
//!
//! These tests run for several minutes each. Run with:
//! ```
//! cargo test --test duration_tests -- --test-threads=1 --nocapture
//! ```

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use utun::config::{
    AllowedOutboundConfig, ConnectionFilterConfig, CryptoConfig, DestConfig, ExposedPortConfig,
    KemMode, Protocol as ConfigProtocol, ServiceConfig, SourceConfig, SourceMode,
};
use utun::tunnel::{DestContainer, SourceContainer};

// ============================================================================
// SHARED HELPERS
// ============================================================================

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

fn default_crypto_config() -> CryptoConfig {
    CryptoConfig {
        kem_mode: KemMode::Mlkem768,
        key_rotation_interval_seconds: 3600,
        rehandshake_before_expiry_seconds: 300,
        max_handshake_size: Some(1024 * 1024),
    }
}

/// Sets up the full tunnel stack (dest + source) and spawns their `.run()` tasks.
/// Returns `(Arc<SourceContainer>, Arc<DestContainer>)` for cleanup.
async fn setup_full_stack(
    backend_port: u16,
    tunnel_port: u16,
    listen_port: u16,
    cert_dir: &Path,
    max_conns: usize,
) -> (Arc<SourceContainer>, Arc<DestContainer>) {
    let dest_config = DestConfig {
        listen_ip: "127.0.0.1".to_string(),
        tunnel_port,
        exposed_services: vec![ServiceConfig {
            name: format!("duration-test-{}", listen_port),
            port: listen_port,
            target_ip: "127.0.0.1".to_string(),
            target_port: backend_port,
            protocol: "tcp".to_string(),
            description: Some("Duration test service".to_string()),
        }],
        max_connections_per_service: max_conns,
        connection_timeout_ms: 60000,
        target_connect_timeout_ms: 5000,
        connection_channel_size: 1024,
        connection_filter: ConnectionFilterConfig::default(),
        stale_cleanup_interval_secs: 15,
        server_cert_path: cert_dir.join("server.crt"),
        server_key_path: cert_dir.join("server.key"),
        ca_cert_path: cert_dir.join("ca.crt"),
    };

    let crypto_config = default_crypto_config();
    let dest = Arc::new(
        DestContainer::new(dest_config, crypto_config)
            .await
            .expect("Failed to create DestContainer"),
    );
    dest.start().await.expect("Failed to start DestContainer");
    let dest_clone = dest.clone();
    tokio::spawn(async move {
        if let Err(e) = dest_clone.run().await {
            eprintln!("[DEST] run() failed: {}", e);
        }
    });

    // Wait for destination to be ready
    tokio::time::sleep(Duration::from_secs(1)).await;

    let source_config = SourceConfig {
        mode: SourceMode::Transparent,
        listen_ip: "127.0.0.1".to_string(),
        listen_port,
        dest_host: "127.0.0.1".to_string(),
        dest_tunnel_port: tunnel_port,
        max_connections: max_conns,
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
            port: listen_port,
            protocol: ConfigProtocol::Tcp,
        }],
        client_cert_path: cert_dir.join("client.crt"),
        client_key_path: cert_dir.join("client.key"),
        ca_cert_path: cert_dir.join("ca.crt"),
        connection_refresh_interval_secs: 0,
        connection_drain_timeout_secs: 60,
        write_queue_size: 8192,
    };

    let crypto_config = default_crypto_config();
    let source = Arc::new(
        SourceContainer::new(source_config, crypto_config)
            .await
            .expect("Failed to create SourceContainer"),
    );
    source
        .start()
        .await
        .expect("Failed to start SourceContainer");
    let source_clone = source.clone();
    tokio::spawn(async move {
        if let Err(e) = source_clone.run().await {
            eprintln!("[SOURCE] run() failed: {}", e);
        }
    });

    // Wait for listeners to bind
    tokio::time::sleep(Duration::from_secs(2)).await;

    (source, dest)
}

// ============================================================================
// TEST 1: SUSTAINED TRAFFIC FOR 5 MINUTES
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_sustained_traffic_5min() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let cert_dir = tempdir().unwrap();
    create_test_certs(cert_dir.path());

    let _echo = start_echo_server(29001).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let (source, dest) = setup_full_stack(29001, 29011, 29021, cert_dir.path(), 1000).await;

    let test_duration = Duration::from_secs(5 * 60);
    let num_clients = 10;
    let stop_flag = Arc::new(AtomicBool::new(false));
    let total_messages = Arc::new(AtomicU64::new(0));
    let total_errors = Arc::new(AtomicU64::new(0));
    let total_bytes = Arc::new(AtomicU64::new(0));
    let active_clients = Arc::new(AtomicU64::new(0));

    let start = Instant::now();

    // Spawn progress reporter
    let progress_stop = stop_flag.clone();
    let progress_msgs = total_messages.clone();
    let progress_errs = total_errors.clone();
    let progress_bytes = total_bytes.clone();
    let progress_active = active_clients.clone();
    let progress_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        interval.tick().await; // skip immediate tick
        loop {
            interval.tick().await;
            if progress_stop.load(Ordering::Relaxed) {
                break;
            }
            let elapsed = start.elapsed();
            eprintln!(
                "[SUSTAINED] {:>3}s elapsed | active: {} | messages: {} | bytes: {} | errors: {}",
                elapsed.as_secs(),
                progress_active.load(Ordering::Relaxed),
                progress_msgs.load(Ordering::Relaxed),
                progress_bytes.load(Ordering::Relaxed),
                progress_errs.load(Ordering::Relaxed),
            );
        }
    });

    // Spawn client tasks
    let mut client_handles = Vec::new();
    for client_id in 0..num_clients {
        let stop = stop_flag.clone();
        let msgs = total_messages.clone();
        let errs = total_errors.clone();
        let bytes = total_bytes.clone();
        let active = active_clients.clone();

        let handle = tokio::spawn(async move {
            let connect_result = timeout(
                Duration::from_secs(10),
                TcpStream::connect("127.0.0.1:29021"),
            )
            .await;

            let mut client = match connect_result {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => {
                    eprintln!("[SUSTAINED] Client {} connect failed: {}", client_id, e);
                    errs.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                Err(_) => {
                    eprintln!("[SUSTAINED] Client {} connect timed out", client_id);
                    errs.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };

            active.fetch_add(1, Ordering::Relaxed);

            let payload: Vec<u8> = (0..100)
                .map(|i| (client_id as u8).wrapping_add(i))
                .collect();

            while !stop.load(Ordering::Relaxed) {
                // Write
                if let Err(e) = client.write_all(&payload).await {
                    eprintln!("[SUSTAINED] Client {} write error: {}", client_id, e);
                    errs.fetch_add(1, Ordering::Relaxed);
                    break;
                }

                // Read
                let mut response = vec![0u8; 100];
                match timeout(Duration::from_secs(10), client.read_exact(&mut response)).await {
                    Ok(Ok(_)) => {
                        if response != payload {
                            eprintln!(
                                "[SUSTAINED] Client {} data mismatch at message {}",
                                client_id,
                                msgs.load(Ordering::Relaxed)
                            );
                            errs.fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                        msgs.fetch_add(1, Ordering::Relaxed);
                        bytes.fetch_add(200, Ordering::Relaxed); // 100 sent + 100 received
                    }
                    Ok(Err(e)) => {
                        eprintln!("[SUSTAINED] Client {} read error: {}", client_id, e);
                        errs.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                    Err(_) => {
                        eprintln!("[SUSTAINED] Client {} read timed out", client_id);
                        errs.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                }

                tokio::time::sleep(Duration::from_millis(100)).await;
            }

            active.fetch_sub(1, Ordering::Relaxed);
        });

        client_handles.push(handle);
    }

    // Wait for test duration
    tokio::time::sleep(test_duration).await;
    stop_flag.store(true, Ordering::Relaxed);

    // Join all clients
    for (i, handle) in client_handles.into_iter().enumerate() {
        match timeout(Duration::from_secs(15), handle).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => eprintln!("[SUSTAINED] Client {} task panicked: {}", i, e),
            Err(_) => eprintln!("[SUSTAINED] Client {} did not stop in time", i),
        }
    }

    progress_handle.abort();

    let final_messages = total_messages.load(Ordering::Relaxed);
    let final_errors = total_errors.load(Ordering::Relaxed);
    let final_bytes = total_bytes.load(Ordering::Relaxed);

    eprintln!("=== SUSTAINED TRAFFIC TEST RESULTS ===");
    eprintln!("  Duration:       {} seconds", start.elapsed().as_secs());
    eprintln!("  Total messages:  {}", final_messages);
    eprintln!("  Total bytes:     {}", final_bytes);
    eprintln!("  Total errors:    {}", final_errors);
    eprintln!("======================================");

    // Final verification: fresh connection still works
    let mut verify_client = timeout(
        Duration::from_secs(10),
        TcpStream::connect("127.0.0.1:29021"),
    )
    .await
    .expect("Final verification connect timed out")
    .expect("Final verification connect failed");

    let verify_data = b"POST-TEST VERIFICATION";
    verify_client.write_all(verify_data).await.unwrap();
    let mut verify_resp = vec![0u8; verify_data.len()];
    timeout(
        Duration::from_secs(10),
        verify_client.read_exact(&mut verify_resp),
    )
    .await
    .expect("Final verification read timed out")
    .expect("Final verification read failed");
    assert_eq!(
        verify_data,
        verify_resp.as_slice(),
        "Final verification data mismatch - tunnel is dead"
    );

    assert_eq!(
        final_errors, 0,
        "Sustained traffic test had {} errors",
        final_errors
    );
    assert!(
        final_messages > 0,
        "No messages were sent during the sustained traffic test"
    );

    source.stop().await;
    dest.stop().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
}

// ============================================================================
// TEST 2: IDLE RESILIENCE FOR 5 MINUTES
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_idle_resilience_5min() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let cert_dir = tempdir().unwrap();
    create_test_certs(cert_dir.path());

    let _echo = start_echo_server(29002).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let (source, dest) = setup_full_stack(29002, 29012, 29022, cert_dir.path(), 1000).await;

    let test_duration = Duration::from_secs(5 * 60);
    let check_interval = Duration::from_secs(30);
    let start = Instant::now();
    let mut checks_passed = 0u32;
    let mut checks_total = 0u32;

    while start.elapsed() < test_duration {
        // Idle for 30 seconds
        tokio::time::sleep(check_interval).await;
        checks_total += 1;

        let elapsed = start.elapsed();

        // Probe: connect, send, verify, disconnect
        let probe_result: Result<(), String> = async {
            let mut client = timeout(
                Duration::from_secs(10),
                TcpStream::connect("127.0.0.1:29022"),
            )
            .await
            .map_err(|_| "connect timed out".to_string())?
            .map_err(|e| format!("connect failed: {}", e))?;

            let data = format!("idle-check-{}", checks_total);
            client
                .write_all(data.as_bytes())
                .await
                .map_err(|e| format!("write failed: {}", e))?;

            let mut resp = vec![0u8; data.len()];
            timeout(Duration::from_secs(10), client.read_exact(&mut resp))
                .await
                .map_err(|_| "read timed out".to_string())?
                .map_err(|e| format!("read failed: {}", e))?;

            if data.as_bytes() != resp.as_slice() {
                return Err("data mismatch".to_string());
            }
            Ok(())
        }
        .await;

        match probe_result {
            Ok(()) => {
                checks_passed += 1;
                eprintln!(
                    "[IDLE] {:>3}s | check {}/{} PASSED",
                    elapsed.as_secs(),
                    checks_passed,
                    checks_total,
                );
            }
            Err(e) => {
                eprintln!(
                    "[IDLE] {:>3}s | check {} FAILED: {}",
                    elapsed.as_secs(),
                    checks_total,
                    e,
                );
            }
        }
    }

    eprintln!("=== IDLE RESILIENCE TEST RESULTS ===");
    eprintln!("  Duration:       {} seconds", start.elapsed().as_secs());
    eprintln!("  Checks passed:  {}/{}", checks_passed, checks_total);
    eprintln!("====================================");

    assert_eq!(
        checks_passed, checks_total,
        "Idle resilience test: {}/{} checks passed - tunnel died during idle period",
        checks_passed, checks_total
    );

    source.stop().await;
    dest.stop().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
}

// ============================================================================
// TEST 3: STRESS SUSTAINED LOAD FOR 3 MINUTES
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_stress_sustained_load() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let cert_dir = tempdir().unwrap();
    create_test_certs(cert_dir.path());

    let _echo = start_echo_server(29003).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let (source, dest) = setup_full_stack(29003, 29013, 29023, cert_dir.path(), 5000).await;

    let test_duration = Duration::from_secs(3 * 60);
    let wave_interval = Duration::from_secs(5);
    let clients_per_wave = 50;
    let messages_per_client = 10;
    let message_size = 256;

    let stop_flag = Arc::new(AtomicBool::new(false));
    let success_count = Arc::new(AtomicU64::new(0));
    let failure_count = Arc::new(AtomicU64::new(0));
    let active_connections = Arc::new(AtomicU64::new(0));

    let start = Instant::now();

    // Spawn progress reporter
    let progress_stop = stop_flag.clone();
    let progress_success = success_count.clone();
    let progress_failure = failure_count.clone();
    let progress_active = active_connections.clone();
    let progress_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        interval.tick().await; // skip immediate tick
        loop {
            interval.tick().await;
            if progress_stop.load(Ordering::Relaxed) {
                break;
            }
            let elapsed = start.elapsed();
            eprintln!(
                "[STRESS] {:>3}s elapsed | active: {} | successes: {} | failures: {}",
                elapsed.as_secs(),
                progress_active.load(Ordering::Relaxed),
                progress_success.load(Ordering::Relaxed),
                progress_failure.load(Ordering::Relaxed),
            );
        }
    });

    // Collect all wave task handles so we can drain them
    let mut all_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    // Spawn waves until duration expires
    while start.elapsed() < test_duration {
        for client_id in 0..clients_per_wave {
            let success = success_count.clone();
            let failure = failure_count.clone();
            let active = active_connections.clone();
            let wave_time = start.elapsed().as_secs();

            let handle = tokio::spawn(async move {
                let connect_result = timeout(
                    Duration::from_secs(15),
                    TcpStream::connect("127.0.0.1:29023"),
                )
                .await;

                let mut client = match connect_result {
                    Ok(Ok(c)) => c,
                    Ok(Err(e)) => {
                        eprintln!(
                            "[STRESS] wave@{}s client {} connect failed: {}",
                            wave_time, client_id, e
                        );
                        failure.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    Err(_) => {
                        eprintln!(
                            "[STRESS] wave@{}s client {} connect timed out",
                            wave_time, client_id
                        );
                        failure.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                };

                active.fetch_add(1, Ordering::Relaxed);

                let payload: Vec<u8> = (0..message_size)
                    .map(|i| (client_id as u8).wrapping_add(i as u8))
                    .collect();

                let mut client_ok = true;
                for msg_idx in 0..messages_per_client {
                    // Write
                    if let Err(e) = client.write_all(&payload).await {
                        eprintln!(
                            "[STRESS] wave@{}s client {} msg {} write error: {}",
                            wave_time, client_id, msg_idx, e
                        );
                        failure.fetch_add(1, Ordering::Relaxed);
                        client_ok = false;
                        break;
                    }

                    // Read
                    let mut response = vec![0u8; message_size];
                    match timeout(Duration::from_secs(15), client.read_exact(&mut response)).await {
                        Ok(Ok(_)) => {
                            if response != payload {
                                eprintln!(
                                    "[STRESS] wave@{}s client {} msg {} data mismatch",
                                    wave_time, client_id, msg_idx
                                );
                                failure.fetch_add(1, Ordering::Relaxed);
                                client_ok = false;
                                break;
                            }
                        }
                        Ok(Err(e)) => {
                            eprintln!(
                                "[STRESS] wave@{}s client {} msg {} read error: {}",
                                wave_time, client_id, msg_idx, e
                            );
                            failure.fetch_add(1, Ordering::Relaxed);
                            client_ok = false;
                            break;
                        }
                        Err(_) => {
                            eprintln!(
                                "[STRESS] wave@{}s client {} msg {} read timed out",
                                wave_time, client_id, msg_idx
                            );
                            failure.fetch_add(1, Ordering::Relaxed);
                            client_ok = false;
                            break;
                        }
                    }
                }

                if client_ok {
                    success.fetch_add(1, Ordering::Relaxed);
                }

                active.fetch_sub(1, Ordering::Relaxed);
                // client drops here, connection closes
            });

            all_handles.push(handle);
        }

        tokio::time::sleep(wave_interval).await;
    }

    // Stop spawning, drain remaining clients
    eprintln!(
        "[STRESS] Spawning complete after {}s, draining {} remaining handles...",
        start.elapsed().as_secs(),
        all_handles.len()
    );

    for handle in all_handles {
        match timeout(Duration::from_secs(30), handle).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => eprintln!("[STRESS] Client task panicked: {}", e),
            Err(_) => eprintln!("[STRESS] Client task did not finish in drain window"),
        }
    }

    stop_flag.store(true, Ordering::Relaxed);
    progress_handle.abort();

    let final_successes = success_count.load(Ordering::Relaxed);
    let final_failures = failure_count.load(Ordering::Relaxed);
    let total = final_successes + final_failures;
    let failure_rate = if total > 0 {
        (final_failures as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    eprintln!("=== STRESS SUSTAINED LOAD TEST RESULTS ===");
    eprintln!("  Duration:       {} seconds", start.elapsed().as_secs());
    eprintln!("  Total clients:  {}", total);
    eprintln!("  Successes:      {}", final_successes);
    eprintln!("  Failures:       {}", final_failures);
    eprintln!("  Failure rate:   {:.2}%", failure_rate);
    eprintln!("==========================================");

    // Final verification: tunnel still responsive
    let mut verify_client = timeout(
        Duration::from_secs(10),
        TcpStream::connect("127.0.0.1:29023"),
    )
    .await
    .expect("Final verification connect timed out - tunnel is dead")
    .expect("Final verification connect failed - tunnel is dead");

    let verify_data = b"POST-STRESS VERIFICATION";
    verify_client.write_all(verify_data).await.unwrap();
    let mut verify_resp = vec![0u8; verify_data.len()];
    timeout(
        Duration::from_secs(10),
        verify_client.read_exact(&mut verify_resp),
    )
    .await
    .expect("Final verification read timed out - tunnel is dead")
    .expect("Final verification read failed - tunnel is dead");
    assert_eq!(
        verify_data,
        verify_resp.as_slice(),
        "Final verification data mismatch - tunnel is corrupted"
    );

    assert!(
        failure_rate < 1.0,
        "Failure rate {:.2}% exceeds 1% threshold ({} failures out of {} total)",
        failure_rate,
        final_failures,
        total
    );
    assert!(
        final_successes > 0,
        "No successful clients during stress test"
    );

    source.stop().await;
    dest.stop().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
}

// ============================================================================
// EXTENDED 30-MINUTE VARIANTS (ignored, run manually)
//
// cargo test --test duration_tests -- --ignored --test-threads=1 --nocapture
// ============================================================================

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_sustained_traffic_30min() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let cert_dir = tempdir().unwrap();
    create_test_certs(cert_dir.path());

    let _echo = start_echo_server(29101).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let (source, dest) = setup_full_stack(29101, 29111, 29121, cert_dir.path(), 1000).await;

    let test_duration = Duration::from_secs(30 * 60);
    let num_clients = 10;
    let stop_flag = Arc::new(AtomicBool::new(false));
    let total_messages = Arc::new(AtomicU64::new(0));
    let total_errors = Arc::new(AtomicU64::new(0));
    let total_bytes = Arc::new(AtomicU64::new(0));
    let active_clients = Arc::new(AtomicU64::new(0));

    let start = Instant::now();

    let progress_stop = stop_flag.clone();
    let progress_msgs = total_messages.clone();
    let progress_errs = total_errors.clone();
    let progress_bytes = total_bytes.clone();
    let progress_active = active_clients.clone();
    let progress_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.tick().await;
        loop {
            interval.tick().await;
            if progress_stop.load(Ordering::Relaxed) {
                break;
            }
            let elapsed = start.elapsed();
            eprintln!(
                "[SUSTAINED-30m] {:>4}s elapsed | active: {} | messages: {} | bytes: {} | errors: {}",
                elapsed.as_secs(),
                progress_active.load(Ordering::Relaxed),
                progress_msgs.load(Ordering::Relaxed),
                progress_bytes.load(Ordering::Relaxed),
                progress_errs.load(Ordering::Relaxed),
            );
        }
    });

    let mut client_handles = Vec::new();
    for client_id in 0..num_clients {
        let stop = stop_flag.clone();
        let msgs = total_messages.clone();
        let errs = total_errors.clone();
        let bytes = total_bytes.clone();
        let active = active_clients.clone();

        let handle = tokio::spawn(async move {
            let connect_result = timeout(
                Duration::from_secs(10),
                TcpStream::connect("127.0.0.1:29121"),
            )
            .await;

            let mut client = match connect_result {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => {
                    eprintln!("[SUSTAINED-30m] Client {} connect failed: {}", client_id, e);
                    errs.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                Err(_) => {
                    eprintln!("[SUSTAINED-30m] Client {} connect timed out", client_id);
                    errs.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };

            active.fetch_add(1, Ordering::Relaxed);

            let payload: Vec<u8> = (0..100)
                .map(|i| (client_id as u8).wrapping_add(i))
                .collect();

            while !stop.load(Ordering::Relaxed) {
                if let Err(e) = client.write_all(&payload).await {
                    eprintln!("[SUSTAINED-30m] Client {} write error: {}", client_id, e);
                    errs.fetch_add(1, Ordering::Relaxed);
                    break;
                }

                let mut response = vec![0u8; 100];
                match timeout(Duration::from_secs(10), client.read_exact(&mut response)).await {
                    Ok(Ok(_)) => {
                        if response != payload {
                            eprintln!(
                                "[SUSTAINED-30m] Client {} data mismatch at message {}",
                                client_id,
                                msgs.load(Ordering::Relaxed)
                            );
                            errs.fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                        msgs.fetch_add(1, Ordering::Relaxed);
                        bytes.fetch_add(200, Ordering::Relaxed);
                    }
                    Ok(Err(e)) => {
                        eprintln!("[SUSTAINED-30m] Client {} read error: {}", client_id, e);
                        errs.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                    Err(_) => {
                        eprintln!("[SUSTAINED-30m] Client {} read timed out", client_id);
                        errs.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                }

                tokio::time::sleep(Duration::from_millis(100)).await;
            }

            active.fetch_sub(1, Ordering::Relaxed);
        });

        client_handles.push(handle);
    }

    tokio::time::sleep(test_duration).await;
    stop_flag.store(true, Ordering::Relaxed);

    for (i, handle) in client_handles.into_iter().enumerate() {
        match timeout(Duration::from_secs(15), handle).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => eprintln!("[SUSTAINED-30m] Client {} task panicked: {}", i, e),
            Err(_) => eprintln!("[SUSTAINED-30m] Client {} did not stop in time", i),
        }
    }

    progress_handle.abort();

    let final_messages = total_messages.load(Ordering::Relaxed);
    let final_errors = total_errors.load(Ordering::Relaxed);
    let final_bytes = total_bytes.load(Ordering::Relaxed);

    eprintln!("=== SUSTAINED TRAFFIC 30min TEST RESULTS ===");
    eprintln!("  Duration:       {} seconds", start.elapsed().as_secs());
    eprintln!("  Total messages:  {}", final_messages);
    eprintln!("  Total bytes:     {}", final_bytes);
    eprintln!("  Total errors:    {}", final_errors);
    eprintln!("=============================================");

    let mut verify_client = timeout(
        Duration::from_secs(10),
        TcpStream::connect("127.0.0.1:29121"),
    )
    .await
    .expect("Final verification connect timed out")
    .expect("Final verification connect failed");

    let verify_data = b"POST-TEST VERIFICATION 30m";
    verify_client.write_all(verify_data).await.unwrap();
    let mut verify_resp = vec![0u8; verify_data.len()];
    timeout(
        Duration::from_secs(10),
        verify_client.read_exact(&mut verify_resp),
    )
    .await
    .expect("Final verification read timed out")
    .expect("Final verification read failed");
    assert_eq!(verify_data, verify_resp.as_slice());

    assert_eq!(
        final_errors, 0,
        "30min sustained traffic test had {} errors",
        final_errors
    );
    assert!(
        final_messages > 0,
        "No messages sent during 30min sustained traffic test"
    );

    source.stop().await;
    dest.stop().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
}

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_idle_resilience_30min() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let cert_dir = tempdir().unwrap();
    create_test_certs(cert_dir.path());

    let _echo = start_echo_server(29102).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let (source, dest) = setup_full_stack(29102, 29112, 29122, cert_dir.path(), 1000).await;

    let test_duration = Duration::from_secs(30 * 60);
    let check_interval = Duration::from_secs(30);
    let start = Instant::now();
    let mut checks_passed = 0u32;
    let mut checks_total = 0u32;

    while start.elapsed() < test_duration {
        tokio::time::sleep(check_interval).await;
        checks_total += 1;

        let elapsed = start.elapsed();

        let probe_result: Result<(), String> = async {
            let mut client = timeout(
                Duration::from_secs(10),
                TcpStream::connect("127.0.0.1:29122"),
            )
            .await
            .map_err(|_| "connect timed out".to_string())?
            .map_err(|e| format!("connect failed: {}", e))?;

            let data = format!("idle-check-30m-{}", checks_total);
            client
                .write_all(data.as_bytes())
                .await
                .map_err(|e| format!("write failed: {}", e))?;

            let mut resp = vec![0u8; data.len()];
            timeout(Duration::from_secs(10), client.read_exact(&mut resp))
                .await
                .map_err(|_| "read timed out".to_string())?
                .map_err(|e| format!("read failed: {}", e))?;

            if data.as_bytes() != resp.as_slice() {
                return Err("data mismatch".to_string());
            }
            Ok(())
        }
        .await;

        match probe_result {
            Ok(()) => {
                checks_passed += 1;
                eprintln!(
                    "[IDLE-30m] {:>4}s | check {}/{} PASSED",
                    elapsed.as_secs(),
                    checks_passed,
                    checks_total,
                );
            }
            Err(e) => {
                eprintln!(
                    "[IDLE-30m] {:>4}s | check {} FAILED: {}",
                    elapsed.as_secs(),
                    checks_total,
                    e,
                );
            }
        }
    }

    eprintln!("=== IDLE RESILIENCE 30min TEST RESULTS ===");
    eprintln!("  Duration:       {} seconds", start.elapsed().as_secs());
    eprintln!("  Checks passed:  {}/{}", checks_passed, checks_total);
    eprintln!("==========================================");

    assert_eq!(
        checks_passed, checks_total,
        "30min idle resilience test: {}/{} checks passed - tunnel died during idle period",
        checks_passed, checks_total
    );

    source.stop().await;
    dest.stop().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
}

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_stress_sustained_load_30min() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let cert_dir = tempdir().unwrap();
    create_test_certs(cert_dir.path());

    let _echo = start_echo_server(29103).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let (source, dest) = setup_full_stack(29103, 29113, 29123, cert_dir.path(), 10000).await;

    let test_duration = Duration::from_secs(30 * 60);
    let wave_interval = Duration::from_secs(5);
    let clients_per_wave = 25;
    let messages_per_client = 10;
    let message_size = 256;

    let stop_flag = Arc::new(AtomicBool::new(false));
    let success_count = Arc::new(AtomicU64::new(0));
    let failure_count = Arc::new(AtomicU64::new(0));
    let active_connections = Arc::new(AtomicU64::new(0));

    let start = Instant::now();

    let progress_stop = stop_flag.clone();
    let progress_success = success_count.clone();
    let progress_failure = failure_count.clone();
    let progress_active = active_connections.clone();
    let progress_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        interval.tick().await;
        loop {
            interval.tick().await;
            if progress_stop.load(Ordering::Relaxed) {
                break;
            }
            let elapsed = start.elapsed();
            eprintln!(
                "[STRESS-30m] {:>4}s elapsed | active: {} | successes: {} | failures: {}",
                elapsed.as_secs(),
                progress_active.load(Ordering::Relaxed),
                progress_success.load(Ordering::Relaxed),
                progress_failure.load(Ordering::Relaxed),
            );
        }
    });

    let mut all_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    while start.elapsed() < test_duration {
        for client_id in 0..clients_per_wave {
            let success = success_count.clone();
            let failure = failure_count.clone();
            let active = active_connections.clone();
            let wave_time = start.elapsed().as_secs();

            let handle = tokio::spawn(async move {
                let connect_result = timeout(
                    Duration::from_secs(15),
                    TcpStream::connect("127.0.0.1:29123"),
                )
                .await;

                let mut client = match connect_result {
                    Ok(Ok(c)) => c,
                    Ok(Err(e)) => {
                        eprintln!(
                            "[STRESS-30m] wave@{}s client {} connect failed: {}",
                            wave_time, client_id, e
                        );
                        failure.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    Err(_) => {
                        eprintln!(
                            "[STRESS-30m] wave@{}s client {} connect timed out",
                            wave_time, client_id
                        );
                        failure.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                };

                active.fetch_add(1, Ordering::Relaxed);

                let payload: Vec<u8> = (0..message_size)
                    .map(|i| (client_id as u8).wrapping_add(i as u8))
                    .collect();

                let mut client_ok = true;
                for msg_idx in 0..messages_per_client {
                    if let Err(e) = client.write_all(&payload).await {
                        eprintln!(
                            "[STRESS-30m] wave@{}s client {} msg {} write error: {}",
                            wave_time, client_id, msg_idx, e
                        );
                        failure.fetch_add(1, Ordering::Relaxed);
                        client_ok = false;
                        break;
                    }

                    let mut response = vec![0u8; message_size];
                    match timeout(Duration::from_secs(15), client.read_exact(&mut response)).await {
                        Ok(Ok(_)) => {
                            if response != payload {
                                eprintln!(
                                    "[STRESS-30m] wave@{}s client {} msg {} data mismatch",
                                    wave_time, client_id, msg_idx
                                );
                                failure.fetch_add(1, Ordering::Relaxed);
                                client_ok = false;
                                break;
                            }
                        }
                        Ok(Err(e)) => {
                            eprintln!(
                                "[STRESS-30m] wave@{}s client {} msg {} read error: {}",
                                wave_time, client_id, msg_idx, e
                            );
                            failure.fetch_add(1, Ordering::Relaxed);
                            client_ok = false;
                            break;
                        }
                        Err(_) => {
                            eprintln!(
                                "[STRESS-30m] wave@{}s client {} msg {} read timed out",
                                wave_time, client_id, msg_idx
                            );
                            failure.fetch_add(1, Ordering::Relaxed);
                            client_ok = false;
                            break;
                        }
                    }
                }

                if client_ok {
                    success.fetch_add(1, Ordering::Relaxed);
                }

                active.fetch_sub(1, Ordering::Relaxed);
            });

            all_handles.push(handle);
        }

        tokio::time::sleep(wave_interval).await;
    }

    eprintln!(
        "[STRESS-30m] Spawning complete after {}s, draining {} remaining handles...",
        start.elapsed().as_secs(),
        all_handles.len()
    );

    for handle in all_handles {
        match timeout(Duration::from_secs(30), handle).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => eprintln!("[STRESS-30m] Client task panicked: {}", e),
            Err(_) => eprintln!("[STRESS-30m] Client task did not finish in drain window"),
        }
    }

    stop_flag.store(true, Ordering::Relaxed);
    progress_handle.abort();

    let final_successes = success_count.load(Ordering::Relaxed);
    let final_failures = failure_count.load(Ordering::Relaxed);
    let total = final_successes + final_failures;
    let failure_rate = if total > 0 {
        (final_failures as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    eprintln!("=== STRESS SUSTAINED LOAD 30min TEST RESULTS ===");
    eprintln!("  Duration:       {} seconds", start.elapsed().as_secs());
    eprintln!("  Total clients:  {}", total);
    eprintln!("  Successes:      {}", final_successes);
    eprintln!("  Failures:       {}", final_failures);
    eprintln!("  Failure rate:   {:.2}%", failure_rate);
    eprintln!("==================================================");

    let mut verify_client = timeout(
        Duration::from_secs(10),
        TcpStream::connect("127.0.0.1:29123"),
    )
    .await
    .expect("Final verification connect timed out - tunnel is dead")
    .expect("Final verification connect failed - tunnel is dead");

    let verify_data = b"POST-STRESS VERIFICATION 30m";
    verify_client.write_all(verify_data).await.unwrap();
    let mut verify_resp = vec![0u8; verify_data.len()];
    timeout(
        Duration::from_secs(10),
        verify_client.read_exact(&mut verify_resp),
    )
    .await
    .expect("Final verification read timed out - tunnel is dead")
    .expect("Final verification read failed - tunnel is dead");
    assert_eq!(verify_data, verify_resp.as_slice());

    assert!(
        failure_rate < 1.0,
        "Failure rate {:.2}% exceeds 1% threshold ({} failures out of {} total)",
        failure_rate,
        final_failures,
        total
    );
    assert!(
        final_successes > 0,
        "No successful clients during 30min stress test"
    );

    source.stop().await;
    dest.stop().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
}
