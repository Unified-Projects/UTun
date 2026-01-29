# UTun

High-performance quantum-resistant tunneling system built in Rust. Provides secure, encrypted tunnels using post-quantum cryptography with mTLS authentication and automated key rotation.

## Features

- **Post-Quantum Cryptography**: Hybrid KEM using Kyber-768 and Classic McEliece-460896
- **Strong Encryption**: AES-256-GCM symmetric encryption with HKDF key derivation
- **Mutual TLS**: Certificate-based authentication with custom CA support
- **Key Rotation**: Automatic cryptographic key rotation and session rekeying
- **TCP/UDP Support**: Tunneling for both TCP and UDP protocols
- **Connection Pooling**: Efficient connection reuse and management
- **Metrics & Monitoring**: Prometheus-compatible metrics endpoint
- **Health Checks**: Built-in health check endpoint for container orchestration
- **Docker Support**: Complete containerization with Docker Compose orchestration

## Architecture

UTun operates with two container types:

1. **Source Container**: Acts as a forward proxy, accepting client connections and tunneling them through a quantum-safe encrypted channel
2. **Destination Container**: Receives tunneled connections and forwards them to target services

```
[Client] -> [Source Container] --[Quantum-Safe Tunnel]--> [Dest Container] -> [Target Service]
```

## Quick Start

### Prerequisites

- Rust 1.75 or later
- Docker and Docker Compose (for containerized deployment)

### Building from Source

```bash
# Clone the repository
cd UTun

# Build the project
cargo build --release

# The binary will be at target/release/utun
```

### Generate Certificates

Before running UTun, generate the required certificates:

```bash
# Build first if you haven't
cargo build --release

# Generate CA, server, and client certificates
./scripts/generate-certs.sh
```

This creates:
- `certs/ca.crt` and `certs/ca.key` - Certificate Authority
- `certs/dest/server.crt` and `certs/dest/server.key` - Destination server certificate
- `certs/source/client.crt` and `certs/source/client.key` - Source client certificate

### Running with Docker Compose

```bash
# Build and start both containers
docker-compose up -d

# View logs
docker-compose logs -f

# Check health status
docker ps

# Stop containers
docker-compose down
```

### Running Manually

#### Start Destination Container

```bash
./target/release/utun dest --config examples/config-dest.toml
```

#### Start Source Container

```bash
./target/release/utun source --config examples/config-source.toml
```

## Configuration

Configuration is done via TOML files. See `examples/` directory for complete examples.

### Source Configuration

```toml
[source]
listen_ip = "0.0.0.0"
listen_port = 8443
dest_host = "utun-dest"
dest_tunnel_port = 9443
max_connections = 10000

[auth]
use_mtls = true
ca_cert_path = "/certs/ca.crt"
client_cert_path = "/certs/client.crt"
client_key_path = "/certs/client.key"

[crypto]
kem_mode = "hybrid"
key_rotation_interval_seconds = 3600

[metrics]
enabled = true
metrics_port = 9090
```

### Destination Configuration

```toml
[dest]
listen_ip = "0.0.0.0"
tunnel_port = 9443

[[dest.exposed_services]]
name = "ssh"
port = 22
target_ip = "127.0.0.1"
target_port = 22
protocol = "tcp"

[auth]
use_mtls = true
ca_cert_path = "/certs/ca.crt"
server_cert_path = "/certs/server.crt"
server_key_path = "/certs/server.key"

[crypto]
kem_mode = "hybrid"
key_rotation_interval_seconds = 3600

[metrics]
enabled = true
metrics_port = 9091
```

## CLI Usage

### Certificate Management

```bash
# Generate CA certificate
utun cert ca --common-name "My CA" --out-cert ca.crt --out-key ca.key

# Generate server certificate
utun cert server \
  --common-name "server.example.com" \
  --dns-names "server.example.com,localhost" \
  --ip-addresses "127.0.0.1,192.168.1.10" \
  --ca-cert ca.crt --ca-key ca.key \
  --out-cert server.crt --out-key server.key

# Generate client certificate
utun cert client \
  --common-name "client1" \
  --ca-cert ca.crt --ca-key ca.key \
  --out-cert client.crt --out-key client.key

# Show certificate details
utun cert show server.crt

# Verify certificate
utun cert verify --cert server.crt --ca-cert ca.crt --hostname server.example.com
```

### Running Containers

```bash
# Run source container
utun source --config config.toml

# Run with custom log level
utun --log-level debug source --config config.toml

# Run with CLI overrides
utun source --config config.toml --listen-port 9000 --metrics-port 9999

# Run destination container
utun dest --config config.toml

# Show version
utun version
```

## Monitoring

### Metrics Endpoint

Access Prometheus-compatible metrics:

```bash
# Source container metrics
curl http://localhost:9090/metrics

# Destination container metrics
curl http://localhost:9091/metrics
```

### Health Check Endpoint

```bash
# Source container health
curl http://localhost:9090/health

# Destination container health
curl http://localhost:9091/health
```

## Security Considerations

1. **Certificate Management**: Keep private keys secure with appropriate file permissions (0600)
2. **Key Rotation**: Configure appropriate key rotation intervals based on your security requirements
3. **Network Isolation**: Use Docker networks or firewalls to restrict access to tunnel ports
4. **Monitoring**: Regularly monitor metrics for anomalies
5. **Updates**: Keep dependencies up to date for security patches

## Development

### Project Structure

```
UTun/
├── src/
│   ├── main.rs           # CLI entry point and command routing
│   ├── cli.rs            # CLI argument parsing
│   ├── config.rs         # Configuration management
│   ├── cert.rs           # Certificate operations
│   ├── crypto/           # Cryptographic implementations
│   │   ├── hybrid_kem.rs # Post-quantum KEM
│   │   ├── symmetric.rs  # Symmetric encryption
│   │   ├── key_manager.rs# Key rotation
│   │   └── auth.rs       # mTLS authentication
│   ├── tunnel/           # Tunnel protocol
│   │   ├── frame.rs      # Protocol frames and codec
│   │   ├── handshake.rs  # Handshake protocol
│   │   ├── connection.rs # Connection state
│   │   ├── source.rs     # Source container
│   │   └── dest.rs       # Destination container
│   └── network/          # Network layer
│       ├── tcp.rs        # TCP proxying
│       ├── udp.rs        # UDP proxying
│       └── pool.rs       # Connection pooling
├── examples/             # Example configurations
├── scripts/              # Utility scripts
├── Dockerfile            # Container build
└── docker-compose.yml    # Orchestration
```

### Testing

```bash
# Run tests
cargo test

# Run with logging
RUST_LOG=debug cargo test

# Check code
cargo check

# Lint
cargo clippy
```

### Building for Production

```bash
# Optimized release build
cargo build --release

# Build Docker image
docker build -t utun:latest .
```

## Performance Tuning

### Connection Limits

Adjust `max_connections` in the source config and `max_connections_per_service` in the destination config based on your system resources.

### Key Rotation

Balance security and performance by tuning `key_rotation_interval_seconds`. Shorter intervals are more secure but increase CPU usage.

### KEM Mode

- `hybrid`: Maximum security with both Kyber-768 and McEliece (default)
- `mlkem768`: Faster, uses only Kyber-768
- `mceliece460896`: Uses only Classic McEliece

## Troubleshooting

### Certificate Errors

If you see certificate validation errors:
1. Ensure certificates are generated with correct hostnames/IPs
2. Check certificate validity periods
3. Verify CA certificate is trusted by both source and destination

### Connection Issues

If containers can't connect:
1. Check network connectivity between containers
2. Verify firewall rules allow traffic on tunnel ports
3. Check logs for TLS handshake errors
4. Ensure certificates are properly mounted in Docker

### Performance Issues

If experiencing slow performance:
1. Increase connection pool sizes
2. Adjust key rotation intervals
3. Consider switching to `mlkem768` KEM mode
4. Check system resources (CPU, memory, network)

## Cryptographic Details

### Hybrid Key Encapsulation Mechanism (KEM)

The hybrid KEM combines two post-quantum algorithms:
- **Kyber768** (CRYSTALS-Kyber): Lattice-based KEM, NIST Level 3 security
- **Classic McEliece 460896**: Code-based KEM, conservative PQ security

Key sizes:
- Public key: 525,344 bytes (1,184 + 524,160)
- Secret key: 16,008 bytes (2,400 + 13,608)
- Ciphertext: 1,276 bytes (1,088 + 188)

The two shared secrets are combined using HKDF-SHA384 with the concatenated ciphertexts as salt.

### Session Cryptography

- **Encryption**: AES-256-GCM with 12-byte nonces and 16-byte authentication tags
- **Key Material**: 64 bytes derived from hybrid KEM, split into encryption and MAC keys
- **Session Keys**: Separate keys for each direction to prevent reflection attacks

## License

GNU AGPL-v3.0

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and contribution guidelines.
