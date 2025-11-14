# Multi-stage build for minimal image size
FROM rust:1.75-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY build.rs ./

# Copy source tree
COPY src ./src
COPY proto ./proto

# Build for release
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -m -u 1000 uploader

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/uploader /usr/local/bin/uploader

# Copy example config
COPY config.example.toml /app/config.toml

# Create directories
RUN mkdir -p /app/storage /app/certs && \
    chown -R uploader:uploader /app

# Switch to app user
USER uploader

# Expose ports
# 50051 - gRPC service
# 9000 - P2P network
EXPOSE 50051 9000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD uploader ping --server 127.0.0.1:50051 || exit 1

# Default command
CMD ["uploader", "server"]
