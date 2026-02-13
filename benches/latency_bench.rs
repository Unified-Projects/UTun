//! Latency benchmarks for measuring tunnel overhead

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;

/// Measure baseline latency without tunnel (direct TCP connection)
async fn measure_baseline_rtt() -> u128 {
    // Start echo server
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        loop {
            let n = socket.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            socket.write_all(&buf[..n]).await.unwrap();
        }
    });

    // Connect and measure RTT
    let mut client = TcpStream::connect(addr).await.unwrap();
    let payload = b"test";

    let start = Instant::now();
    client.write_all(payload).await.unwrap();
    let mut response = [0u8; 4];
    client.read_exact(&mut response).await.unwrap();
    let duration = start.elapsed();

    duration.as_nanos()
}

/// Measure encryption/decryption latency for a single frame
async fn measure_crypto_latency(payload_size: usize) -> u128 {
    use utun::crypto::symmetric::SymmetricCrypto;

    let key = [0u8; 32];
    let crypto = SymmetricCrypto::new(&key);
    let payload = vec![0u8; payload_size];

    let start = Instant::now();
    let ciphertext = crypto.encrypt(&payload).unwrap();
    let _decrypted = crypto.decrypt(&ciphertext).unwrap();
    let duration = start.elapsed();

    duration.as_nanos()
}

fn benchmark_baseline_latency(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("baseline_tcp_rtt", |b| {
        b.iter(|| rt.block_on(measure_baseline_rtt()))
    });
}

fn benchmark_crypto_overhead(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let sizes = [64, 256, 1024, 4096];

    let mut group = c.benchmark_group("crypto_latency_overhead");
    for size in sizes {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter(|| rt.block_on(measure_crypto_latency(size)))
        });
    }
    group.finish();
}

fn benchmark_handshake_latency(c: &mut Criterion) {
    use utun::crypto::hybrid_kem::HybridKeyPair;

    c.bench_function("handshake_latency", |b| {
        b.iter(|| {
            let start = Instant::now();

            let client = HybridKeyPair::generate();
            let server = HybridKeyPair::generate();

            // Client -> Server encapsulation
            let (_client_shared, client_ct) =
                HybridKeyPair::encapsulate(server.public_key()).unwrap();

            // Server decapsulation
            let _server_shared = server.decapsulate(&client_ct).unwrap();

            // Server -> Client encapsulation
            let (_server_shared, server_ct) =
                HybridKeyPair::encapsulate(client.public_key()).unwrap();

            // Client decapsulation
            let _client_shared2 = client.decapsulate(&server_ct).unwrap();

            start.elapsed()
        })
    });
}

fn benchmark_frame_processing_latency(c: &mut Criterion) {
    use utun::tunnel::Frame;

    let sizes = [64, 256, 1024, 4096];

    let mut group = c.benchmark_group("frame_processing_latency");
    for size in sizes {
        let payload = vec![0u8; size];
        group.bench_with_input(BenchmarkId::from_parameter(size), &payload, |b, payload| {
            b.iter(|| {
                let start = Instant::now();

                // Create frame
                let frame = Frame::new_data(1, 0, payload).unwrap();

                // Serialize
                let bytes = frame.to_bytes();

                // Deserialize
                let _decoded = Frame::from_bytes(&bytes).unwrap();

                start.elapsed()
            })
        });
    }
    group.finish();
}

fn benchmark_end_to_end_latency(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let sizes = [64, 256, 1024];

    let mut group = c.benchmark_group("e2e_latency");
    for size in sizes {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter(|| {
                rt.block_on(async {
                    let start = Instant::now();

                    // Simulate full round trip with crypto
                    use utun::crypto::symmetric::SymmetricCrypto;
                    use utun::tunnel::Frame;

                    let key = [0u8; 32];
                    let crypto = SymmetricCrypto::new(&key);
                    let payload = vec![0u8; size];

                    // Outbound: Frame + Encrypt
                    let frame = Frame::new_data(1, 0, &payload).unwrap();
                    let frame_bytes = frame.to_bytes();
                    let encrypted = crypto.encrypt(&frame_bytes).unwrap();

                    // Inbound: Decrypt + Parse
                    let decrypted = crypto.decrypt(&encrypted).unwrap();
                    let _parsed_frame = Frame::from_bytes(&decrypted).unwrap();

                    start.elapsed()
                })
            })
        });
    }
    group.finish();
}

criterion_group!(
    latency_benches,
    benchmark_baseline_latency,
    benchmark_crypto_overhead,
    benchmark_handshake_latency,
    benchmark_frame_processing_latency,
    benchmark_end_to_end_latency,
);

criterion_main!(latency_benches);
