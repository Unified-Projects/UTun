# Changelog

All notable changes to UTun will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.6] - 2026-02-14

### Fixed
- Frame read timeout increased from 30s to 60s to prevent heartbeat timeout during idle periods
- Heartbeat task now respects reconnection_enabled setting
- Connection cleanup now properly removes from both demux registry and connection manager
- GitHub Actions release workflow artifact download configuration

## [0.1.5] - 2026-02-14

### Added
- Resilience module with circuit breaker to prevent infinite demux restart loops
- Demux task watchdog for automatic recovery from task failures
- Tunnel metrics tracking for observability (demux restarts, channel full events, frames dropped, lock wait times, heartbeat timeouts)
- Configurable channel sizes for connection management (`connection_channel_size` in source and dest configs)
- Circuit breaker configuration options (`circuit_breaker_window_secs`, `circuit_breaker_max_restarts`)
- Dedicated writer task for lock-free frame sending via unbounded write queue

### Fixed
- Heartbeat race condition where pong could arrive after timeout check began, now uses atomic flag checked atomically before timeout
- Potential deadlock in destination response channel by switching to unbounded channel (monitored via metrics for backpressure)
- Lock contention during frame writes by implementing dedicated writer task that minimizes critical section to just write/flush operations
- Clippy dead_code warnings by adding appropriate allow attributes to config fields and public API methods not yet used

### Changed
- Source demux task now takes ownership of tunnel read half for lock-free operation (no mutex on read path)
- Connection channels now use configurable size (default 1024) instead of hardcoded 100
- Heartbeat pong detection now atomic (flag cleared before ping sent, checked atomically after timeout)
- Frame sending now uses unbounded write queue instead of direct writes (eliminates per-frame lock acquisition)

## [0.1.4] - 2026-02-13

### Added
- Frame demultiplexing system in source container to route incoming frames to correct connection handlers via connection registry
- Comprehensive session crypto tests including nonce format validation, replay protection, high-volume unique nonces, bidirectional communication, and out-of-order delivery
- Three new test suites: demux_tests.rs, end_to_end_tests.rs, and full_system_tests.rs for integration testing
- Port reuse support with SO_REUSEADDR and SO_REUSEPORT for better socket management
- Port fallback logic that tries up to 5 additional ports if the configured port is in use

### Fixed
- Session crypto now uses proper session-prefixed nonces (4-byte session prefix + 8-byte counter) instead of counter-only nonces to prevent nonce collisions across sessions
- Timing attack vulnerability by always incrementing sequence counter regardless of decryption success/failure
- Bidirectional crypto key ordering in destination container (swapped enc_key and mac_key for proper symmetric communication)
- Connection state handling by making rx_from_tunnel public for demux access

### Changed
- Split tunnel stream into separate read/write halves to avoid lock contention
- Refactored frame reception to use dedicated demux task instead of direct receive_frame calls
- Simplified handshake flow by removing excessive logging throughout codebase
- Improved connection handling with better timeout management and cleanup

### Removed
- Unused counter-mode encryption methods (encrypt_with_counter, decrypt_with_counter, nonce_from_counter)
- Counter-mode tests and benchmarks that are no longer relevant
- Excessive/over-the-top log messages across source and destination containers

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
