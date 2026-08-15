use notify::event::{EventKind, ModifyKind, RenameMode};
use notify::{
    Config as NotifyConfig, RecommendedWatcher, RecursiveMode, Result as NotifyResult, Watcher,
};
use serde::{Deserialize, Serialize};
use std::path::Path;
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
}

/// Map a notify EventKind to the compact event-type string the backend expects.
fn classify(kind: &EventKind) -> Option<&'static str> {
    match kind {
        EventKind::Create(_) => Some("create"),
        EventKind::Remove(_) => Some("remove"),
        EventKind::Modify(ModifyKind::Name(RenameMode::Any))
        | EventKind::Modify(ModifyKind::Name(RenameMode::To))
        | EventKind::Modify(ModifyKind::Name(RenameMode::From))
        | EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => Some("rename"),
        EventKind::Modify(_) => Some("modify"),
        _ => None,
    }
}

/// Shannon entropy of a file's leading bytes, normalised to [0, 1].
/// High entropy (~1.0) is a strong signal of encryption.
fn file_entropy(path: &Path) -> Option<f64> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    let mut buf = [0u8; 8192];
    let n = file.read(&mut buf).ok()?;
    if n == 0 {
        return None;
    }
    let mut counts = [0u64; 256];
    for &b in &buf[..n] {
        counts[b as usize] += 1;
    }
    let len = n as f64;
    let mut entropy = 0.0f64;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / len;
            entropy -= p * p.log2();
        }
    }
    Some((entropy / 8.0).min(1.0))
}

fn build_event(path: &Path, event_type: &str) -> FileModificationEvent {
    let metadata = std::fs::metadata(path).ok();
    let file_size = metadata.as_ref().map(|m| m.len());
    // Only compute entropy for modify/create on regular files (cheap guard).
    let entropy_score = if matches!(event_type, "modify" | "create")
        && metadata.as_ref().map(|m| m.is_file()).unwrap_or(false)
    {
        file_entropy(path)
    } else {
        None
    };

    FileModificationEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        file_path: path.to_string_lossy().to_string(),
        event_type: event_type.to_string(),
        file_size,
        entropy_score,
        source: "file_watcher".to_string(),
    }
}

impl FileSystemWatcher {
    pub fn new(config: WatcherConfig) -> Self {
        FileSystemWatcher { config }
    }

    pub async fn start(&self) -> NotifyResult<()> {
        // Channel now carries the actual events (previously it sent unit `()`
        // and the event payload was discarded, so nothing was ever forwarded).
        let (tx, mut rx) = mpsc::unbounded_channel::<FileModificationEvent>();

        let mut watcher: RecommendedWatcher = RecommendedWatcher::new(
            move |res: NotifyResult<notify::Event>| {
                if let Ok(event) = res {
                    if let Some(event_type) = classify(&event.kind) {
                        for path in event.paths {
                            let built = build_event(&path, event_type);
                            let _ = tx.send(built);
                        }
                    }
                }
            },
            NotifyConfig::default(),
        )?;

        for path in &self.config.watch_paths {
            if Path::new(path).exists() {
                watcher.watch(Path::new(path), RecursiveMode::Recursive)?;
                println!("🔍 Watching: {}", path);
            } else {
                eprintln!("⚠️  Skipping non-existent watch path: {}", path);
            }
        }

        let backend_url = self.config.backend_url.clone();
        let batch_size = self.config.batch_size.max(1);
        let batch_timeout =
            tokio::time::Duration::from_millis(self.config.batch_timeout_ms.max(100));
        let client = reqwest::Client::new();

        let mut batch: Vec<FileModificationEvent> = Vec::new();
        let mut interval = tokio::time::interval(batch_timeout);

        loop {
            tokio::select! {
                maybe_event = rx.recv() => {
                    match maybe_event {
                        Some(event) => {
                            batch.push(event);
                            if batch.len() >= batch_size {
                                flush(&client, &backend_url, &mut batch).await;
                            }
                        }
                        None => break, // channel closed
                    }
                }
                _ = interval.tick() => {
                    if !batch.is_empty() {
                        flush(&client, &backend_url, &mut batch).await;
                    }
                }
            }
        }
        Ok(())
    }
}

/// POST a batch of events to the backend detection endpoint, draining the batch.
async fn flush(
    client: &reqwest::Client,
    backend_url: &str,
    batch: &mut Vec<FileModificationEvent>,
) {
    let count = batch.len();
    let url = format!("{}/api/v1/vigil/events", backend_url);
    for event in batch.drain(..) {
        if let Err(e) = client.post(&url).json(&event).send().await {
            eprintln!("❌ Failed to forward event to backend: {}", e);
        }
    }
    println!("📤 Forwarded {} file event(s) to {}", count, backend_url);
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
    fn test_classify_event_kinds() {
        use notify::event::{CreateKind, RemoveKind};
        assert_eq!(
            classify(&EventKind::Create(CreateKind::File)),
            Some("create")
        );
        assert_eq!(
            classify(&EventKind::Remove(RemoveKind::File)),
            Some("remove")
        );
        assert_eq!(
            classify(&EventKind::Modify(ModifyKind::Name(RenameMode::Both))),
            Some("rename")
        );
    }

    #[test]
    fn test_entropy_of_uniform_data_is_low() {
        // A temp file of all-identical bytes has ~zero entropy.
        use std::io::Write;
        let dir = std::env::temp_dir();
        let path = dir.join(format!("drra_entropy_test_{}.bin", uuid::Uuid::new_v4()));
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(&[0u8; 4096]).unwrap();
        }
        let e = file_entropy(&path).unwrap();
        std::fs::remove_file(&path).ok();
        assert!(
            e < 0.01,
            "uniform data should have near-zero entropy, got {}",
            e
        );
    }

    #[test]
    fn test_build_event_fields() {
        let event = build_event(Path::new("/tmp/test.txt"), "create");
        assert_eq!(event.event_type, "create");
        assert_eq!(event.source, "file_watcher");
        assert!(!event.event_id.is_empty());
    }
}
