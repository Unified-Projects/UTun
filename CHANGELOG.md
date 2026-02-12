# Changelog

All notable changes to UTun will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.3] - 2026-02-12

### Added
- Transparent multi-port forwarding mode for source containers. Each port in
  `exposed_ports` now gets its own listener that automatically forwards
  connections to the same port on the destination server. This replaces the
  previous single-port limitation where all traffic went through one port.
- New `mode` configuration option for source containers with three modes:
  `transparent` (default, multi-port), `protocol` (single entry point), and
  `hybrid` (both modes).
- Port validation to prevent duplicate ports in `exposed_ports` configuration.
- Example configuration file `examples/config-source-transparent.toml` showing
  multi-port setup.

### Fixed
- Source mode now uses actual target port in CONNECT frames instead of
  hardcoded port 22. Each connection now correctly specifies which destination
  port to connect to.
- Updated `bytes` dependency from 1.11.0 to 1.11.1 to fix integer overflow
  vulnerability (RUSTSEC-2026-0007).
- Updated `time` dependency from 0.3.46 to 0.3.47 to fix denial of service
  vulnerability via stack exhaustion (RUSTSEC-2026-0009).
- Improved error messages for certificate file access issues with better
  diagnostics and fix suggestions.

### Changed
- Source container now spawns separate listener tasks for each exposed port,
  using channel-based communication for centralized connection handling.
- Added graceful shutdown for all listener tasks.

## [0.1.2] - 2026-02-02

### Fixed
- Added safe config reload with blue/green swap so invalid configs no longer
  crash the running container.

## [0.1.1] - 2026-01-29

### Fixed
- Dynamic handshake buffer size based on KEM mode. Hybrid and McEliece modes now
  use 2MB buffers to accommodate ~500KB Classic McEliece public keys. ML-KEM-768
  mode uses 64KB buffers. This fixes "Frame size exceeds maximum" errors when
  using hybrid KEM mode.
- Increased handshake timeout from 3-10 seconds to 30 seconds per message to
  allow time for large key exchanges.
- Fixed PEM certificate handling in handshake. Certificates are now properly
  converted from PEM to DER format before verification. This fixes "Certificate
  verification failed" errors when using PEM-encoded certificate files.
- Fixed keypair storage in handshake. Both client and server now properly store
  their ephemeral keypairs and reuse them for decapsulation. Previously, new
  keypairs were incorrectly generated during decapsulation, causing key exchange
  failures.
- Fixed shared secret ordering in verify_data and session key derivation. Both
  client and server now use canonical ordering (client-to-server, server-to-client)
  regardless of which side is computing. This ensures both sides derive identical
  verify_data hashes and session keys.
- Fixed handshake transcript ordering. Verify_data is now computed before adding
  the finished message to the transcript, ensuring both sides compute the same
  hash over the same transcript state.
- Added graceful shutdown handling for Docker containers. The process now properly
  handles SIGTERM and SIGINT signals, triggering a clean shutdown with a 30-second
  timeout. This fixes containers that would not stop or disconnect cleanly.

### Added
- New `max_handshake_size` option in `[crypto]` config section to manually
  override the handshake buffer size if needed.

## [0.1.0] - 2026-01-29

### Added
- Post-quantum cryptography with hybrid KEM (ML-KEM-768 + Classic McEliece-460896)
- AES-256-GCM symmetric encryption with HKDF key derivation
- Mutual TLS authentication with custom CA support
- Automatic key rotation and session rekeying
- TCP and UDP protocol tunneling
- Connection pooling and efficient connection management
- Prometheus metrics endpoint
- Health check endpoint for container orchestration
- Docker and Docker Compose support
- Certificate generation and management CLI
- Source and destination container modes
- Configuration via TOML files
- Initial implementation of quantum-safe tunnel system
- Core cryptographic primitives
- Network layer with TCP/UDP support
- Certificate management utilities
- Example configurations
- Build scripts and Docker support

### Changed
- Switched the hybrid KEM from Kyber-768 to ML-KEM-768 (pqcrypto-mlkem)
- Certificate CLI now requires `--out-cert`/`--out-key` and will not print PEM material to stdout
