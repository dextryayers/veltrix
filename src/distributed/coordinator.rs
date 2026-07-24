use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use chrono::Utc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use uuid::Uuid;

use super::protocol::*;
use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;

#[allow(dead_code)]
struct WorkerHandle {
    id: String,
    hostname: String,
    max_concurrent: usize,
    addr: SocketAddr,
    connected_at: chrono::DateTime<Utc>,
    tasks_done: u64,
    tasks_failed: u64,
    current_batch: Option<String>,
}

#[allow(dead_code)]
pub struct Coordinator {
    bind: String,
    token: String,
    targets: Vec<Target>,
    credentials: Vec<Credential>,
    target_idx: usize,
    cred_idx: usize,
    workers: HashMap<String, WorkerHandle>,
    results: Vec<AuthResult>,
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl Coordinator {
    pub fn new(
        bind: String,
        token: String,
        targets: Vec<Target>,
        credentials: Vec<Credential>,
        running: Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Coordinator {
            bind,
            token,
            targets,
            credentials,
            target_idx: 0,
            cred_idx: 0,
            workers: HashMap::new(),
            results: Vec::new(),
            running,
        }
    }

    pub async fn run(&mut self) -> Vec<AuthResult> {
        let listener = TcpListener::bind(&self.bind).await.unwrap_or_else(|e| {
            panic!("Failed to bind coordinator to {}: {}", self.bind, e);
        });
        log::info!("Coordinator listening on {}", self.bind);

        let workers = Arc::new(Mutex::new(HashMap::<String, WorkerHandle>::new()));
        let results = Arc::new(Mutex::new(Vec::<AuthResult>::new()));
        let state = Arc::new(Mutex::new(CoordinatorState {
            targets: self.targets.clone(),
            credentials: self.credentials.clone(),
            target_idx: 0,
            cred_idx: 0,
            total_tasks: self.targets.len() * self.credentials.len(),
        }));

        let running = Arc::clone(&self.running);
        let token = self.token.clone();

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    let (stream, addr) = match accept_result {
                        Ok(v) => v,
                        Err(e) => {
                            log::error!("Accept error: {}", e);
                            continue;
                        }
                    };
                    let workers = Arc::clone(&workers);
                    let results = Arc::clone(&results);
                    let state = Arc::clone(&state);
                    let running = Arc::clone(&running);
                    let token = token.clone();

                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_worker(stream, addr, token, workers, results, state, running).await {
                            log::error!("Worker {} error: {}", addr, e);
                        }
                    });
                }
                _ = async {
                    while running.load(std::sync::atomic::Ordering::SeqCst) {
                        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    }
                } => {
                    break;
                }
            }
            if !self.running.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
        }

        let final_results = results.lock().await.clone();
        log::info!(
            "Coordinator finished: {} workers, {} results",
            workers.lock().await.len(),
            final_results.len()
        );
        final_results
    }

    async fn handle_worker(
        stream: TcpStream,
        addr: SocketAddr,
        token: String,
        workers: Arc<Mutex<HashMap<String, WorkerHandle>>>,
        results: Arc<Mutex<Vec<AuthResult>>>,
        state: Arc<Mutex<CoordinatorState>>,
        running: Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();

        reader.read_line(&mut line).await?;
        let msg: DistributedMessage = serde_json::from_str(line.trim())?;

        let worker_id = Uuid::new_v4().to_string();
        match msg {
            DistributedMessage::Hello { version, token: t, hostname, max_concurrent } => {
                if version != PROTOCOL_VERSION {
                    let response = DistributedMessage::HelloAck {
                        accepted: false,
                        message: format!("Unsupported version: {}", version),
                        worker_id: String::new(),
                        heartbeat_interval_secs: 0,
                    };
                    let mut resp = serde_json::to_string(&response)?;
                    resp.push('\n');
                    writer.write_all(resp.as_bytes()).await?;
                    return Ok(());
                }
                if t != token {
                    let response = DistributedMessage::HelloAck {
                        accepted: false,
                        message: "Invalid auth token".into(),
                        worker_id: String::new(),
                        heartbeat_interval_secs: 0,
                    };
                    let mut resp = serde_json::to_string(&response)?;
                    resp.push('\n');
                    writer.write_all(resp.as_bytes()).await?;
                    return Ok(());
                }

                let handle = WorkerHandle {
                    id: worker_id.clone(),
                    hostname,
                    max_concurrent,
                    addr,
                    connected_at: Utc::now(),
                    tasks_done: 0,
                    tasks_failed: 0,
                    current_batch: None,
                };
                workers.lock().await.insert(worker_id.clone(), handle);

                let response = DistributedMessage::HelloAck {
                    accepted: true,
                    message: "Welcome to Veltrix distributed coordinator".into(),
                    worker_id: worker_id.clone(),
                    heartbeat_interval_secs: 10,
                };
                let mut resp = serde_json::to_string(&response)?;
                resp.push('\n');
                writer.write_all(resp.as_bytes()).await?;
            }
            _ => {
                let response = DistributedMessage::Error {
                    worker_id: String::new(),
                    message: "Expected Hello first".into(),
                };
                let mut resp = serde_json::to_string(&response)?;
                resp.push('\n');
                writer.write_all(resp.as_bytes()).await?;
                return Ok(());
            }
        }

        loop {
            line.clear();
            let n = reader.read_line(&mut line).await?;
            if n == 0 {
                log::info!("Worker {} disconnected", worker_id);
                break;
            }
            let msg: DistributedMessage = serde_json::from_str(line.trim())?;

            match msg {
                DistributedMessage::TaskRequest { worker_id: wid, batch_size } => {
                    let batch = {
                        let mut s = state.lock().await;
                        s.next_batch(batch_size)
                    };

                    match batch {
                        Some(tasks) => {
                            let batch_id = Uuid::new_v4().to_string();
                            {
                                let mut w = workers.lock().await;
                                if let Some(h) = w.get_mut(&wid) {
                                    h.current_batch = Some(batch_id.clone());
                                }
                            }

                            let response = DistributedMessage::TaskBatch {
                                tasks,
                                batch_id,
                            };
                            let mut resp = serde_json::to_string(&response)?;
                            resp.push('\n');
                            writer.write_all(resp.as_bytes()).await?;
                        }
                        None => {
                            let response = DistributedMessage::NoMoreWork {
                                reason: "All tasks completed".into(),
                            };
                            let mut resp = serde_json::to_string(&response)?;
                            resp.push('\n');
                            writer.write_all(resp.as_bytes()).await?;
                            break;
                        }
                    }
                }
                DistributedMessage::ResultReport { worker_id: wid, batch_id, results: batch_results } => {
                    let mut r = results.lock().await;
                    for sr in &batch_results {
                        r.push(AuthResult {
                            success: sr.success,
                            target_host: sr.target_host.clone(),
                            target_port: sr.target_port,
                            protocol: sr.protocol.clone(),
                            username: sr.username.clone(),
                            password: String::new(),
                            duration_ms: sr.duration_ms,
                            error: sr.error.clone(),
                            timestamp: Utc::now(),
                            r#type: "password".into(),
                        });
                    }

                    {
                        let mut w = workers.lock().await;
                        if let Some(h) = w.get_mut(&wid) {
                            h.tasks_done += batch_results.iter().filter(|r| r.success).count() as u64;
                            h.tasks_failed += batch_results.iter().filter(|r| !r.success && r.error.is_some()).count() as u64;
                            h.current_batch = None;
                        }
                    }

                    let response = DistributedMessage::ResultAck {
                        batch_id,
                        accepted: true,
                    };
                    let mut resp = serde_json::to_string(&response)?;
                    resp.push('\n');
                    writer.write_all(resp.as_bytes()).await?;
                }
                DistributedMessage::Heartbeat { worker_id: wid, .. } => {
                    if let Some(h) = workers.lock().await.get_mut(&wid) {
                        h.tasks_done = wid.parse().unwrap_or(0);
                    }
                    let response = DistributedMessage::HeartbeatAck { ok: true };
                    let mut resp = serde_json::to_string(&response)?;
                    resp.push('\n');
                    writer.write_all(resp.as_bytes()).await?;
                }
                _ => {}
            }

            if !running.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
        }

        workers.lock().await.remove(&worker_id);
        log::info!("Worker {} removed from pool", worker_id);
        Ok(())
    }
}

#[allow(dead_code)]
struct CoordinatorState {
    targets: Vec<Target>,
    credentials: Vec<Credential>,
    target_idx: usize,
    cred_idx: usize,
    total_tasks: usize,
}

impl CoordinatorState {
    fn next_batch(&mut self, batch_size: usize) -> Option<Vec<SerializedTask>> {
        let mut tasks = Vec::new();
        for _ in 0..batch_size {
            if self.target_idx >= self.targets.len() {
                break;
            }
            let target = &self.targets[self.target_idx];
            let credential = &self.credentials[self.cred_idx];
            tasks.push(SerializedTask {
                task_id: Uuid::new_v4().to_string(),
                target_host: target.host.clone(),
                target_port: target.port,
                protocol: target.protocol.clone(),
                username: credential.username.clone(),
                password: credential.password.clone(),
                timeout_secs: 10,
            });

            self.cred_idx += 1;
            if self.cred_idx >= self.credentials.len() {
                self.cred_idx = 0;
                self.target_idx += 1;
            }
        }
        if tasks.is_empty() {
            None
        } else {
            Some(tasks)
        }
    }
}
