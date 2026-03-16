# Rust-Based File Watchers for Resilience Forge

High-performance, asynchronous file system monitoring for entropy analysis and behavior tracking.

## Features

- Real-time file access monitoring
- Shannon entropy calculation on file modifications
- Process correlation (which process modified files)
- Bulk import/export of monitoring configs
- Minimal CPU overhead (<2%)
- Async I/O with tokio runtime

## Project Structure

```
watchers/
├── Cargo.toml                  # Rust project manifest
├── src/
│   ├── main.rs              # Entry point
│   ├── monitor.rs           # File system monitoring
│   ├── entropy.rs           # Entropy calculations
│   └── api_client.rs        # Communication with FastAPI backend
└── README.md
```

## Building

```bash
cd watchers
cargo build --release
```

## Running

```bash
./target/release/resilience-watcher \
  --watch-path C:\Users \
  --api-endpoint http://localhost:8000 \
  --entropy-threshold 0.85
```

## Configuration

```toml
[watcher]
watch_paths = ["C:\\Users", "C:\\ProgramData"]
entropy_threshold = 0.85
mass_modification_threshold = 0.15
report_interval_secs = 5
api_endpoint = "http://localhost:8000"
```

## Integration with Sentinel

File watcher streams events to Sentinel ML engine via:
1. REST API polling
2. Kafka topics (preferred)
3. Direct in-process callbacks

## Performance

- **Latency**: <50ms event detection
- **CPU**: <2% baseline
- **Memory**: ~50MB per watched directory
- **Throughput**: 10,000+ events/second

See [../docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) for full integration details.
