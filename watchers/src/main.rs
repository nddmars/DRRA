mod lib;

use lib::{FileSystemWatcher, WatcherConfig};
use tracing::{info, error};

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    info!("🔥 Resilience Forge File Watcher starting...");

    let config = WatcherConfig {
        watch_paths: vec![
            "/tmp/honeypot".to_string(),
            "/home".to_string(),
            "/var/lib".to_string(),
        ],
        backend_url: "http://localhost:8000".to_string(),
        batch_size: 100,
        batch_timeout_ms: 5000,
    };

    let watcher = FileSystemWatcher::new(config);

    match watcher.start().await {
        Ok(_) => info!("Watcher started successfully"),
        Err(e) => error!("Failed to start watcher: {}", e),
    }
}
