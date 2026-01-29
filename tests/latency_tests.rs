//! Latency measurement tests

use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn start_echo_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
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

#[tokio::test]
async fn measure_baseline_latency() {
    let (addr, _handle) = start_echo_server().await;
    let mut client = TcpStream::connect(addr).await.unwrap();

    // Warm up
    for _ in 0..10 {
        let payload = b"warmup";
        client.write_all(payload).await.unwrap();
        let mut response = vec![0u8; payload.len()];
        client.read_exact(&mut response).await.unwrap();
    }

    // Measure 100 round trips
    let mut latencies = Vec::new();
    for _ in 0..100 {
        let payload = b"test";
        let start = Instant::now();
        client.write_all(payload).await.unwrap();
        let mut response = vec![0u8; payload.len()];
        client.read_exact(&mut response).await.unwrap();
        let duration = start.elapsed();
        latencies.push(duration.as_micros());
    }

    latencies.sort();
    let median = latencies[latencies.len() / 2];
    let p99 = latencies[(latencies.len() * 99) / 100];
    let avg: u128 = latencies.iter().sum::<u128>() / latencies.len() as u128;

    println!("\nBaseline TCP Latency (localhost):");
    println!("  Average: {}µs", avg);
    println!("  Median:  {}µs", median);
    println!("  P99:     {}µs", p99);
}

#[tokio::test]
async fn measure_crypto_overhead() {
    use utun::crypto::symmetric::SymmetricCrypto;

    let key = [0u8; 32];
    let crypto = SymmetricCrypto::new(&key);
    let payload_sizes = [64, 256, 1024, 4096];

    println!("\nCrypto Overhead (encrypt + decrypt round-trip):");
    for size in payload_sizes {
        let payload = vec![0u8; size];
        let mut latencies = Vec::new();

        // Warm up
        for _ in 0..10 {
            let ct = crypto.encrypt(&payload).unwrap();
            let _pt = crypto.decrypt(&ct).unwrap();
        }

        // Measure
        for _ in 0..100 {
            let start = Instant::now();
            let ciphertext = crypto.encrypt(&payload).unwrap();
            let _decrypted = crypto.decrypt(&ciphertext).unwrap();
            let duration = start.elapsed();
            latencies.push(duration.as_nanos());
        }

        latencies.sort();
        let median = latencies[latencies.len() / 2];
        let avg: u128 = latencies.iter().sum::<u128>() / latencies.len() as u128;

        println!("  {} bytes: avg={}ns, median={}ns", size, avg, median);
    }
}

#[tokio::test]
async fn measure_frame_overhead() {
    use utun::tunnel::Frame;

    let payload_sizes = [64, 256, 1024, 4096];

    println!("\nFrame Processing Overhead (serialize + deserialize):");
    for size in payload_sizes {
        let payload = vec![0u8; size];
        let mut latencies = Vec::new();

        // Warm up
        for _ in 0..10 {
            let frame = Frame::new_data(1, 0, &payload).unwrap();
            let bytes = frame.to_bytes();
            let _decoded = Frame::from_bytes(&bytes).unwrap();
        }

        // Measure
        for _ in 0..100 {
            let start = Instant::now();
            let frame = Frame::new_data(1, 0, &payload).unwrap();
            let bytes = frame.to_bytes();
            let _decoded = Frame::from_bytes(&bytes).unwrap();
            let duration = start.elapsed();
            latencies.push(duration.as_nanos());
        }

        latencies.sort();
        let median = latencies[latencies.len() / 2];
        let avg: u128 = latencies.iter().sum::<u128>() / latencies.len() as u128;

        println!("  {} bytes: avg={}ns, median={}ns", size, avg, median);
    }
}

#[tokio::test]
async fn measure_total_overhead() {
    use utun::crypto::symmetric::SymmetricCrypto;
    use utun::tunnel::Frame;

    let key = [0u8; 32];
    let crypto = SymmetricCrypto::new(&key);
    let payload_sizes = [64, 256, 1024, 4096];

    println!("\nTotal Tunnel Overhead per packet (frame + encrypt + decrypt + parse):");
    for size in payload_sizes {
        let payload = vec![0u8; size];
        let mut latencies = Vec::new();

        // Warm up
        for _ in 0..10 {
            let frame = Frame::new_data(1, 0, &payload).unwrap();
            let frame_bytes = frame.to_bytes();
            let encrypted = crypto.encrypt(&frame_bytes).unwrap();
            let decrypted = crypto.decrypt(&encrypted).unwrap();
            let _parsed = Frame::from_bytes(&decrypted).unwrap();
        }

        // Measure
        for _ in 0..100 {
            let start = Instant::now();

            // Outbound: Frame + Encrypt
            let frame = Frame::new_data(1, 0, &payload).unwrap();
            let frame_bytes = frame.to_bytes();
            let encrypted = crypto.encrypt(&frame_bytes).unwrap();

            // Inbound: Decrypt + Parse
            let decrypted = crypto.decrypt(&encrypted).unwrap();
            let _parsed = Frame::from_bytes(&decrypted).unwrap();

            let duration = start.elapsed();
            latencies.push(duration.as_micros());
        }

        latencies.sort();
        let median = latencies[latencies.len() / 2];
        let avg: u128 = latencies.iter().sum::<u128>() / latencies.len() as u128;

        println!("  {} bytes: avg={}µs, median={}µs", size, avg, median);
    }
}

#[test]
fn measure_handshake_time() {
    use utun::crypto::hybrid_kem::HybridKeyPair;

    println!("\nHandshake Time (full bidirectional key exchange):");

    // Warm up
    for _ in 0..2 {
        let client = HybridKeyPair::generate();
        let server = HybridKeyPair::generate();
        let (_s1, ct1) = HybridKeyPair::encapsulate(server.public_key()).unwrap();
        let _s2 = server.decapsulate(&ct1).unwrap();
        let (_s3, ct2) = HybridKeyPair::encapsulate(client.public_key()).unwrap();
        let _s4 = client.decapsulate(&ct2).unwrap();
    }

    // Measure
    let mut times = Vec::new();
    for _ in 0..10 {
        let start = Instant::now();

        let client = HybridKeyPair::generate();
        let server = HybridKeyPair::generate();

        let (_client_shared, client_ct) = HybridKeyPair::encapsulate(server.public_key()).unwrap();
        let _server_shared = server.decapsulate(&client_ct).unwrap();
        let (_server_shared2, server_ct) = HybridKeyPair::encapsulate(client.public_key()).unwrap();
        let _client_shared2 = client.decapsulate(&server_ct).unwrap();

        let duration = start.elapsed();
        times.push(duration.as_millis());
    }

    times.sort();
    let median = times[times.len() / 2];
    let avg: u128 = times.iter().sum::<u128>() / times.len() as u128;

    println!("  Average: {}ms", avg);
    println!("  Median:  {}ms", median);
    println!("  Note: One-time cost per connection establishment");
}
