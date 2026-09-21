//! F7.1: protokol veltrix-dist-v2 (framing JSON-lines, kompatibel dengan v1 transport).
//! Beda dari v1: run_id global, chunk deterministik (chunk_id/checksum/resume_offset),
//! token per-run + expiry, heartbeat berisi counters, dedup berbasis task_id stabil.

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: &str = "veltrix-dist-v2";

/// Chunk deterministik: range [start_idx, end_idx) dari ruang task global.
/// chunk_id dan checksum dapat dihitung ulang kedua belah pihak.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkSpec {
    pub chunk_id: String,
    pub run_id: String,
    pub start_idx: usize,
    pub end_idx: usize,
    pub checksum: String,
}

impl ChunkSpec {
    pub fn new(run_id: &str, start_idx: usize, end_idx: usize, task_ids: &[String]) -> Self {
        let chunk_id = chunk_id_for(run_id, start_idx, end_idx);
        let checksum = chunk_checksum(run_id, &chunk_id, task_ids);
        ChunkSpec { chunk_id, run_id: run_id.to_string(), start_idx, end_idx, checksum }
    }

    /// Offset resume: index global task pertama chunk ini.
    pub fn resume_offset(&self) -> usize {
        self.start_idx
    }
}

/// chunk_id deterministik dari (run_id, start, end).
pub fn chunk_id_for(run_id: &str, start_idx: usize, end_idx: usize) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"veltrix-chunk-v2:");
    h.update(run_id.as_bytes());
    h.update(b":");
    h.update(start_idx.to_string().as_bytes());
    h.update(b":");
    h.update(end_idx.to_string().as_bytes());
    hex12(&h.finalize())
}

/// Checksum isi chunk dari daftar task_id (urutan signifikan).
pub fn chunk_checksum(run_id: &str, chunk_id: &str, task_ids: &[String]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"veltrix-chunk-sum-v2:");
    h.update(run_id.as_bytes());
    h.update(b":");
    h.update(chunk_id.as_bytes());
    for id in task_ids {
        h.update(b":");
        h.update(id.as_bytes());
    }
    hex12(&h.finalize())
}

fn hex12(bytes: &[u8]) -> String {
    bytes.iter().take(6).map(|b| format!("{:02x}", b)).collect()
}

/// task_id stabil dan deterministik: "{run_short}:{index:08}".
pub fn task_id_for(run_id: &str, idx: usize) -> String {
    let short: String = run_id.chars().filter(|c| *c != '-').take(8).collect();
    format!("{}-{:08}", short, idx)
}

#[derive(Debug, Serialize, Deserialize)]
pub enum DistributedMessage {
    Hello {
        version: String,
        /// Token per-run (F7.4). Coordinator menolak token salah/kadaluarsa.
        run_token: String,
        hostname: String,
        max_concurrent: usize,
        /// Checkpoint lokal worker: task_id yang sudah di-ack di run ini (cap 10k).
        completed_hint: Vec<String>,
    },
    HelloAck {
        accepted: bool,
        message: String,
        worker_id: String,
        run_id: String,
        heartbeat_interval_secs: u64,
    },
    TaskRequest {
        worker_id: String,
        batch_size: usize,
    },
    TaskBatch {
        chunk: ChunkSpec,
        tasks: Vec<SerializedTask>,
    },
    NoMoreWork {
        reason: String,
    },
    ResultReport {
        worker_id: String,
        run_id: String,
        chunk_id: String,
        results: Vec<SerializedResult>,
    },
    ResultAck {
        chunk_id: String,
        accepted: bool,
        duplicate_count: usize,
    },
    Heartbeat {
        worker_id: String,
        run_id: String,
        tasks_done: u64,
        tasks_failed: u64,
        cpu_percent: f32,
        mem_mb: u64,
    },
    HeartbeatAck {
        ok: bool,
    },
    Error {
        worker_id: String,
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedTask {
    pub task_id: String,
    pub target_host: String,
    pub target_port: u16,
    pub protocol: String,
    pub username: String,
    pub password: String,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedResult {
    pub task_id: String,
    pub success: bool,
    pub duration_ms: u64,
    pub error: Option<String>,
    pub target_host: String,
    pub target_port: u16,
    pub protocol: String,
    pub username: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_ids_deterministic() {
        let a = ChunkSpec::new("run-1", 0, 100, &["a".into(), "b".into()]);
        let b = ChunkSpec::new("run-1", 0, 100, &["a".into(), "b".into()]);
        assert_eq!(a.chunk_id, b.chunk_id);
        assert_eq!(a.checksum, b.checksum);
        assert_eq!(a.resume_offset(), 0);
        let c = ChunkSpec::new("run-1", 100, 200, &["a".into(), "b".into()]);
        assert_ne!(a.chunk_id, c.chunk_id);
    }

    #[test]
    fn checksum_detects_reorder() {
        let a = ChunkSpec::new("run-1", 0, 2, &["x".into(), "y".into()]);
        let b = ChunkSpec::new("run-1", 0, 2, &["y".into(), "x".into()]);
        assert_eq!(a.chunk_id, b.chunk_id, "same range => same id");
        assert_ne!(a.checksum, b.checksum, "order matters for checksum");
    }

    #[test]
    fn task_ids_stable_and_unique() {
        assert_eq!(task_id_for("run-1", 5), task_id_for("run-1", 5));
        assert_ne!(task_id_for("run-1", 5), task_id_for("run-1", 6));
        assert_ne!(task_id_for("run-1", 5), task_id_for("run-2", 5));
    }

    #[test]
    fn messages_roundtrip_json_lines() {
        let m = DistributedMessage::Hello {
            version: PROTOCOL_VERSION.into(),
            run_token: "tok".into(),
            hostname: "h".into(),
            max_concurrent: 4,
            completed_hint: vec![],
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(!s.contains('\n'));
        let back: DistributedMessage = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, DistributedMessage::Hello { .. }));
    }
}
