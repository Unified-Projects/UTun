# Contributing to UTun

Thanks for your interest in contributing to UTun. This document covers the basics of getting set up and submitting changes.

## Development Setup

### Requirements

- Rust 1.75 or later
- Docker and Docker Compose (for containerized testing)
- OpenSSL development libraries

### Building

```bash
git clone <repository-url>
cd UTun
cargo build
```

The first build will take a while as it downloads and compiles dependencies, especially the post-quantum crypto libraries.

### Running Tests

```bash
cargo test
```

For verbose output:
```bash
cargo test -- --nocapture
```

### Code Quality

Before submitting a PR:

```bash
# Check for compilation errors
cargo check

# Run clippy for lints
cargo clippy -- -D warnings

# Format code
cargo fmt

# Run all tests
cargo test
```

## Making Changes

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Add tests if you're adding functionality
4. Ensure all tests pass and code is formatted
5. Submit a pull request

### Commit Messages

Write clear commit messages that describe what changed and why. No specific format required, just be descriptive.

### Pull Requests

- Target the `main` branch
- Include a description of what changed and why
- Reference any related issues
- Ensure CI passes

## Project Structure

- `src/crypto/` - Cryptographic implementations (KEM, symmetric encryption, key rotation)
- `src/tunnel/` - Tunnel protocol (handshake, framing, connection management)
- `src/network/` - Network layer (TCP/UDP proxying, connection pooling)
- `src/cert.rs` - Certificate generation and management
- `src/config.rs` - Configuration parsing and validation
- `src/cli.rs` - CLI argument parsing
- `tests/` - Integration tests
- `benches/` - Performance benchmarks
- `examples/` - Example configurations

## Testing

Integration tests are in the `tests/` directory. Unit tests live alongside the code they test.

To run specific tests:
```bash
cargo test test_name
```

To run benchmarks:
```bash
cargo bench
```

## Certificate Testing

The `scripts/generate-certs.sh` script generates test certificates. For development, you can run:

```bash
./scripts/generate-certs.sh
```

This creates a local CA and generates certificates for testing.

## Docker Testing

To test the full containerized setup:

```bash
docker-compose up --build
```

This builds the image and starts both source and destination containers.

## Reporting Issues

When reporting bugs, include:
- Steps to reproduce
- Expected vs actual behavior
- Rust version (`rustc --version`)
- OS and architecture
- Relevant logs or error messages

## Security

Don't open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md) for reporting instructions.

## License

By contributing, you agree that your contributions will be licensed under [GNU Affero General Public License v3.0 (AGPL-3.0)](LICENSE).
