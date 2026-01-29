# Changelog

All notable changes to UTun will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-01-27

### Added
- Post-quantum cryptography with hybrid KEM (Kyber-768 + Classic McEliece-460896)
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
