# Build stage
# Builder and runtime use the same Debian release so the binary links against a matching glibc
FROM rust:1.99.1-trixie AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create a new empty project for caching dependencies
RUN cargo new --bin utun
WORKDIR /app/utun

# Copy dependency files
COPY Cargo.toml Cargo.lock ./
COPY benches/ ./benches/

# Build dependencies only (cached)
RUN cargo build --release && rm src/*.rs && rm target/release/deps/utun*

# Copy source code
COPY src/ ./src/

# Set build timestamp
ARG BUILD_TIMESTAMP
ENV BUILD_TIMESTAMP=${BUILD_TIMESTAMP:-unknown}

# Build the actual binary
RUN cargo build --release

# Runtime stage
FROM debian:trixie-20261020-slim

# Apply pending security updates to the base image, then install runtime dependencies
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends \
    ca-certificates \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash utun

# Create directories
RUN mkdir -p /etc/utun /certs && chown -R utun:utun /etc/utun /certs

# Copy the binary
COPY --from=builder /app/utun/target/release/utun /usr/local/bin/utun
RUN chmod +x /usr/local/bin/utun

# Switch to non-root user
USER utun

# Expose ports
EXPOSE 8443 9443 9090

# Health check
# start-period is 30s to account for the quantum-safe handshake (10-13s)
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD /usr/local/bin/utun health --endpoint http://localhost:9090/health --timeout 5 || exit 1

# Default entrypoint
ENTRYPOINT ["utun"]

# Default command (can be overridden)
CMD ["--help"]
