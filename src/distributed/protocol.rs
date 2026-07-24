use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: &str = "veltrix-dist-v1";

#[derive(Debug, Serialize, Deserialize)]
pub enum DistributedMessage {
    Hello {
        version: String,
        token: String,
        hostname: String,
        max_concurrent: usize,
    },
    HelloAck {
        accepted: bool,
        message: String,
        worker_id: String,
        heartbeat_interval_secs: u64,
    },
    TaskRequest {
        worker_id: String,
        batch_size: usize,
    },
    TaskBatch {
        tasks: Vec<SerializedTask>,
        batch_id: String,
    },
    NoMoreWork {
        reason: String,
    },
    ResultReport {
        worker_id: String,
        batch_id: String,
        results: Vec<SerializedResult>,
    },
    ResultAck {
        batch_id: String,
        accepted: bool,
    },
    Heartbeat {
        worker_id: String,
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
