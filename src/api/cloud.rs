use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::core::attack::AttackOrchestrator;
use crate::core::config::AttackConfig;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CloudJob {
    pub id: String,
    pub status: String,
    pub created_at: String,
    pub finished_at: Option<String>,
    pub total_attempts: usize,
    pub successes: usize,
    pub error: Option<String>,
}

pub struct CloudScheduler {
    jobs: Arc<Mutex<HashMap<String, CloudJob>>>,
}

impl Clone for CloudScheduler {
    fn clone(&self) -> Self {
        Self { jobs: Arc::clone(&self.jobs) }
    }
}

impl CloudScheduler {
    pub fn new() -> Self {
        Self {
            jobs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn submit(&self, config: AttackConfig, running: std::sync::Arc<std::sync::atomic::AtomicBool>) -> String {
        let job_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();

        {
            let mut jobs = self.jobs.lock().unwrap();
            jobs.insert(job_id.clone(), CloudJob {
                id: job_id.clone(),
                status: "running".into(),
                created_at: now.clone(),
                finished_at: None,
                total_attempts: 0,
                successes: 0,
                error: None,
            });
        }

        let jobs = self.jobs.clone();
        let jid = job_id.clone();

        tokio::spawn(async move {
            let mut orchestrator = match AttackOrchestrator::new(config, running).await {
                Ok(o) => o,
                Err(e) => {
                    let mut j = jobs.lock().unwrap();
                    if let Some(job) = j.get_mut(&jid) {
                        job.status = "failed".into();
                        job.error = Some(e.to_string());
                        job.finished_at = Some(chrono::Utc::now().to_rfc3339());
                    }
                    return;
                }
            };

            let summary = orchestrator.run().await;

            let mut j = jobs.lock().unwrap();
            if let Some(job) = j.get_mut(&jid) {
                job.status = "completed".into();
                job.total_attempts = summary.attempts as usize;
                job.successes = summary.successes as usize;
                job.finished_at = Some(chrono::Utc::now().to_rfc3339());
            }
        });

        job_id
    }

    pub fn get_job(&self, id: &str) -> Option<CloudJob> {
        let jobs = self.jobs.lock().unwrap();
        jobs.get(id).cloned()
    }

    pub fn list_jobs(&self) -> Vec<CloudJob> {
        let jobs = self.jobs.lock().unwrap();
        let mut list: Vec<CloudJob> = jobs.values().cloned().collect();
        list.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        list
    }
}
