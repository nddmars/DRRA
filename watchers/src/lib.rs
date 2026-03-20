use notify::{Watcher, RecursiveMode, Result as NotifyResult, watcher};
use std::sync::{Arc, Mutex};
use std::path::Path;
use std::collections::HashMap;
use chrono::Utc;
use serde::{Serialize, Deserialize};
use tokio::sync::mpsc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileModificationEvent {
    pub event_id: String,
    pub timestamp: String,
    pub file_path: String,
    pub event_type: String, // "create", "modify", "remove", "rename"
    pub file_size: Option<u64>,
    pub entropy_score: Option<f64>,
    pub source: String,
}

#[derive(Debug, Clone)]
pub struct WatcherConfig {
    pub watch_paths: Vec<String>,
    pub backend_url: String,
    pub batch_size: usize,
    pub batch_timeout_ms: u64,
}

pub struct FileSystemWatcher {
    config: WatcherConfig,
    events: Arc<Mutex<Vec<FileModificationEvent>>>,
    event_count: Arc<Mutex<usize>>,
}

impl FileSystemWatcher {
    pub fn new(config: WatcherConfig) -> Self {
        FileSystemWatcher {
            config,
            events: Arc::new(Mutex::new(Vec::new())),
            event_count: Arc::new(Mutex::new(0)),
        }
    }

    pub async fn start(&self) -> NotifyResult<()> {
        let (tx, mut rx) = mpsc::unbounded_channel();
        
        // Create watcher
        let mut watcher = watcher(
            move |res| {
                if let Ok(_event) = res {
                    let _ = tx.send(());
                }
            },
            Default::default(),
        )?;

        // Watch all configured paths
        for path in &self.config.watch_paths {
            watcher.watch(Path::new(path), RecursiveMode::Recursive)?;
            println!("🔍 Watching: {}", path);
        }

        // Process events
        let events = self.events.clone();
        let event_count = self.event_count.clone();

        tokio::spawn(async move {
            let mut batch = Vec::new();
            let mut interval = tokio::time::interval(
                tokio::time::Duration::from_millis(1000)
            );

            loop {
                tokio::select! {
                    _ = rx.recv() => {
                        // File system event received
                        if let Ok(mut e) = events.lock() {
                            if !e.is_empty() {
                                batch.extend(e.drain(..));
                            }
                        }
                    }
                    _ = interval.tick() => {
                        // Flush if batch has events
                        if !batch.is_empty() {
                            if let Ok(count) = event_count.lock() {
                                println!("📊 Detected {} file events", count);
                            }
                            batch.clear();
                        }
                    }
                }
            }
        });

        // Keep watcher alive
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }

    pub fn record_event(
        &self,
        file_path: String,
        event_type: String,
        file_size: Option<u64>,
    ) -> String {
        let event_id = uuid::Uuid::new_v4().to_string();
        
        let event = FileModificationEvent {
            event_id: event_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            file_path,
            event_type,
            file_size,
            entropy_score: None,
            source: "file_watcher".to_string(),
        };

        if let Ok(mut events) = self.events.lock() {
            events.push(event);
            
            if let Ok(mut count) = self.event_count.lock() {
                *count += 1;
            }
        }

        event_id
    }

    pub async fn send_to_backend(&self, events: Vec<FileModificationEvent>) -> Result<(), Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();
        
        for event in events {
            client
                .post(&format!("{}/api/v1/vigil/events", self.config.backend_url))
                .json(&event)
                .send()
                .await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watcher_config_creation() {
        let config = WatcherConfig {
            watch_paths: vec!["/tmp".to_string()],
            backend_url: "http://localhost:8000".to_string(),
            batch_size: 100,
            batch_timeout_ms: 1000,
        };
        assert_eq!(config.watch_paths.len(), 1);
    }

    #[test]
    fn test_event_creation() {
        let event = FileModificationEvent {
            event_id: "test-id".to_string(),
            timestamp: Utc::now().to_rfc3339(),
            file_path: "/tmp/test.txt".to_string(),
            event_type: "create".to_string(),
            file_size: Some(1024),
            entropy_score: None,
            source: "file_watcher".to_string(),
        };
        
        assert_eq!(event.file_path, "/tmp/test.txt");
        assert_eq!(event.event_type, "create");
    }
}
