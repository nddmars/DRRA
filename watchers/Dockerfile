# Build stage for Rust file watcher
FROM rust:latest AS builder

WORKDIR /app

# Copy Cargo files
COPY Cargo.toml ./

# Create dummy source to cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

# Copy actual source
COPY src ./src

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /app/target/release/watcher /app/watcher

# Set environment defaults
ENV BACKEND_URL=http://backend:8000
ENV WATCH_PATH=/tmp/honeypot

# Run the watcher
CMD ["/app/watcher"]
