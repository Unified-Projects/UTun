//! Performance benchmarks for crypto operations

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use utun::crypto::{hybrid_kem::HybridKeyPair, symmetric::SymmetricCrypto};

fn benchmark_key_generation(c: &mut Criterion) {
    c.bench_function("hybrid_keypair_generate", |b| {
        b.iter(|| HybridKeyPair::generate())
    });
}

fn benchmark_encapsulation(c: &mut Criterion) {
    let bob = HybridKeyPair::generate();

    c.bench_function("hybrid_encapsulate", |b| {
        b.iter(|| HybridKeyPair::encapsulate(bob.public_key()))
    });
}

fn benchmark_decapsulation(c: &mut Criterion) {
    let bob = HybridKeyPair::generate();
    let (_shared, ciphertext) = HybridKeyPair::encapsulate(bob.public_key()).unwrap();

    c.bench_function("hybrid_decapsulate", |b| {
        b.iter(|| bob.decapsulate(&ciphertext))
    });
}

fn benchmark_aes_gcm(c: &mut Criterion) {
    let key = [0u8; 32];
    let crypto = SymmetricCrypto::new(&key);

    let sizes = [64, 256, 1024, 4096, 16384, 65536];

    let mut group = c.benchmark_group("aes_gcm_encrypt");
    for size in sizes {
        let plaintext = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, data| {
            b.iter(|| crypto.encrypt(data))
        });
    }
    group.finish();

    let mut group = c.benchmark_group("aes_gcm_decrypt");
    for size in sizes {
        let plaintext = vec![0u8; size];
        let ciphertext = crypto.encrypt(&plaintext).unwrap();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &ciphertext, |b, data| {
            b.iter(|| crypto.decrypt(data))
        });
    }
    group.finish();
}

fn benchmark_full_handshake(c: &mut Criterion) {
    c.bench_function("full_handshake", |b| {
        b.iter(|| {
            let client = HybridKeyPair::generate();
            let server = HybridKeyPair::generate();

            // Client -> Server
            let (_client_shared, client_ct) =
                HybridKeyPair::encapsulate(server.public_key()).unwrap();

            // Server decapsulates and responds
            let _server_shared = server.decapsulate(&client_ct).unwrap();
            let (_server_shared, server_ct) =
                HybridKeyPair::encapsulate(client.public_key()).unwrap();

            // Client decapsulates server response
            let _client_shared2 = client.decapsulate(&server_ct).unwrap();
        })
    });
}

fn benchmark_public_key_serialization(c: &mut Criterion) {
    let kp = HybridKeyPair::generate();

    c.bench_function("public_key_serialize", |b| {
        b.iter(|| kp.serialize_public_key())
    });

    let pk_bytes = kp.serialize_public_key();
    c.bench_function("public_key_deserialize", |b| {
        b.iter(|| HybridKeyPair::deserialize_public_key(&pk_bytes))
    });
}

fn benchmark_counter_mode_encryption(c: &mut Criterion) {
    let key = [0u8; 32];
    let crypto = SymmetricCrypto::new(&key);
    let plaintext = vec![0u8; 1024];

    c.bench_function("aes_gcm_counter_mode", |b| {
        b.iter(|| crypto.encrypt_with_counter(&plaintext, 0))
    });
}

fn benchmark_large_payload(c: &mut Criterion) {
    let key = [0u8; 32];
    let crypto = SymmetricCrypto::new(&key);

    let mut group = c.benchmark_group("large_payload");

    // 1MB payload
    let plaintext_1mb = vec![0u8; 1024 * 1024];
    group.throughput(Throughput::Bytes(1024 * 1024));
    group.bench_function("encrypt_1mb", |b| b.iter(|| crypto.encrypt(&plaintext_1mb)));

    let ciphertext_1mb = crypto.encrypt(&plaintext_1mb).unwrap();
    group.bench_function("decrypt_1mb", |b| {
        b.iter(|| crypto.decrypt(&ciphertext_1mb))
    });

    // 10MB payload
    let plaintext_10mb = vec![0u8; 10 * 1024 * 1024];
    group.throughput(Throughput::Bytes(10 * 1024 * 1024));
    group.bench_function("encrypt_10mb", |b| {
        b.iter(|| crypto.encrypt(&plaintext_10mb))
    });

    let ciphertext_10mb = crypto.encrypt(&plaintext_10mb).unwrap();
    group.bench_function("decrypt_10mb", |b| {
        b.iter(|| crypto.decrypt(&ciphertext_10mb))
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_key_generation,
    benchmark_encapsulation,
    benchmark_decapsulation,
    benchmark_aes_gcm,
    benchmark_full_handshake,
    benchmark_public_key_serialization,
    benchmark_counter_mode_encryption,
    benchmark_large_payload,
);

criterion_main!(benches);
