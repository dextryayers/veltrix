//! F6.4/F6.6: state server API v2 - job queue non-blocking,
//! audit log ring buffer, dan rate limiter sederhana per IP.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{broadcast, Mutex, RwLock};

use crate::core::result::AuthResult;

pub const AUDIT_CAP: usize = 1000;
pub const JOB_LOG_CAP: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Stopped,
}

impl JobStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            JobStatus::Queued => "queued",
            JobStatus::Running => "running",
            JobStatus::Completed => "completed",
            JobStatus::Failed => "failed",
            JobStatus::Stopped => "stopped",
        }
    }
}

/// Spesifikasi attack dari API (password hanya di memori, tak pernah di-list).
#[derive(Debug, Clone)]
pub struct AttackSpec {
    pub target: String,
    pub port: u16,
    pub protocol: String,
    pub usernames: Vec<String>,
    pub passwords: Vec<String>,
    pub threads: usize,
    pub timeout_secs: u64,
    pub show_secrets: bool,
}

#[derive(Debug, Clone)]
pub struct JobV2 {
    pub id: String,
    pub run_id: String,
    pub target: String,
    pub port: u16,
    pub protocol: String,
    pub status: JobStatus,
    pub progress: f64,
    pub attempts: u64,
    pub successes: u64,
    pub failures: u64,
    pub errors: u64,
    pub total_targets_est: usize,
    pub total_credentials_est: usize,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub error: Option<String>,
    pub submitted_by: String,
    pub spec: AttackSpec,
    pub results: Vec<AuthResult>,
    pub log: VecDeque<String>,
    pub cancel: Arc<std::sync::atomic::AtomicBool>,
}

impl JobV2 {
    /// Proyeksi aman untuk list/detail: password selalu masked di sini.
    /// Hasil penuh hanya lewat /results dan /report dengan show_secrets eksplisit.
    pub fn masked_summary(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "run_id": self.run_id,
            "target": self.target,
            "port": self.port,
            "protocol": self.protocol,
            "status": self.status.as_str(),
            "progress": (self.progress * 100.0).round() / 100.0,
            "attempts": self.attempts,
            "successes": self.successes,
            "failures": self.failures,
            "errors": self.errors,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "submitted_by": self.submitted_by,
        })
    }

    pub fn push_log(&mut self, line: String) {
        if self.log.len() >= JOB_LOG_CAP {
            self.log.pop_front();
        }
        self.log.push_back(line);
    }
}

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub ts: String,
    pub actor: String,
    pub action: String,
    pub job_id: Option<String>,
    pub detail: String,
}

/// Event live untuk websocket /api/v2/jobs/:id/events.
#[derive(Debug, Clone)]
pub struct JobEvent {
    pub job_id: String,
    pub status: String,
    pub progress: f64,
    pub attempts: u64,
    pub successes: u64,
    pub msg: String,
}

/// Rate limiter sederhana: max N request per 60 detik per IP.
pub struct ApiRateLimiter {
    max_per_min: u32,
    hits: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
}

impl ApiRateLimiter {
    pub fn new(max_per_min: u32) -> Self {
        Self { max_per_min: max_per_min.max(1), hits: Mutex::new(HashMap::new()) }
    }

    pub async fn allow(&self, ip: IpAddr) -> bool {
        let mut hits = self.hits.lock().await;
        let now = Instant::now();
        let window = std::time::Duration::from_secs(60);
        let q = hits.entry(ip).or_insert_with(VecDeque::new);
        while q.front().map(|t| now.duration_since(*t) > window).unwrap_or(false) {
            q.pop_front();
        }
        if q.len() >= self.max_per_min as usize {
            return false;
        }
        q.push_back(now);
        true
    }
}

#[derive(Clone)]
pub struct AppState {
    pub jobs: Arc<RwLock<HashMap<String, JobV2>>>,
    pub audit: Arc<Mutex<VecDeque<AuditEntry>>>,
    pub auth: super::auth::ApiAuth,
    pub running: Arc<std::sync::atomic::AtomicBool>,
    pub rate_limiter: Arc<ApiRateLimiter>,
    pub events: broadcast::Sender<JobEvent>,
}

impl AppState {
    pub fn new(
        auth: super::auth::ApiAuth,
        running: Arc<std::sync::atomic::AtomicBool>,
        rate_per_min: u32,
    ) -> Self {
        let (tx, _) = broadcast::channel(256);
        Self {
            jobs: Arc::new(RwLock::new(HashMap::new())),
            audit: Arc::new(Mutex::new(VecDeque::new())),
            auth,
            running,
            rate_limiter: Arc::new(ApiRateLimiter::new(rate_per_min)),
            events: tx,
        }
    }

    pub async fn audit(&self, actor: &str, action: &str, job_id: Option<&str>, detail: &str) {
        let mut log = self.audit.lock().await;
        if log.len() >= AUDIT_CAP {
            log.pop_front();
        }
        log.push_back(AuditEntry {
            ts: chrono::Utc::now().to_rfc3339(),
            actor: actor.to_string(),
            action: action.to_string(),
            job_id: job_id.map(|s| s.to_string()),
            detail: detail.chars().take(300).collect(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[tokio::test]
    async fn rate_limiter_blocks_over_quota() {
        let rl = ApiRateLimiter::new(3);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(rl.allow(ip).await);
        assert!(rl.allow(ip).await);
        assert!(rl.allow(ip).await);
        assert!(!rl.allow(ip).await);
        // IP lain tidak terpengaruh.
        let other: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(rl.allow(other).await);
    }

    #[tokio::test]
    async fn audit_ring_buffer_caps() {
        let (auth, _) = super::super::auth::ApiAuth::new(Some("t".into()));
        let st = AppState::new(auth, Arc::new(std::sync::atomic::AtomicBool::new(true)), 60);
        for i in 0..(AUDIT_CAP + 10) {
            st.audit("tester", "test", None, &format!("entry {}", i)).await;
        }
        let log = st.audit.lock().await;
        assert_eq!(log.len(), AUDIT_CAP);
        assert!(log.back().unwrap().detail.contains(&format!("entry {}", AUDIT_CAP + 9)));
    }
}
