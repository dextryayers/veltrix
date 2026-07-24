use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use super::protocol::*;
use crate::core::result::AuthResult;
use crate::protocols::get_protocol;
use crate::proxy::ProxyConfig;

pub struct DistributedWorker {
    coordinator_addr: String,
    token: String,
    hostname: String,
    max_concurrent: usize,
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl DistributedWorker {
    pub fn new(
        coordinator_addr: String,
        token: String,
        hostname: String,
        max_concurrent: usize,
        running: Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        DistributedWorker {
            coordinator_addr,
            token,
            hostname,
            max_concurrent,
            running,
        }
    }

    pub async fn run(&self) -> Vec<AuthResult> {
        let stream = match TcpStream::connect(&self.coordinator_addr).await {
            Ok(s) => s,
            Err(e) => {
                log::error!("Cannot connect to coordinator {}: {}", self.coordinator_addr, e);
                return Vec::new();
            }
        };

        log::info!("Connected to coordinator at {}", self.coordinator_addr);
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();

        // Send Hello
        let hello = DistributedMessage::Hello {
            version: PROTOCOL_VERSION.to_string(),
            token: self.token.clone(),
            hostname: self.hostname.clone(),
            max_concurrent: self.max_concurrent,
        };
        {
            let mut msg = serde_json::to_string(&hello).unwrap();
            msg.push('\n');
            writer.write_all(msg.as_bytes()).await.unwrap();
        }

        // Read HelloAck
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        let ack: DistributedMessage = serde_json::from_str(line.trim()).unwrap();
        let (worker_id, _heartbeat_interval) = match ack {
            DistributedMessage::HelloAck { accepted: true, worker_id, heartbeat_interval_secs, .. } => {
                log::info!("Authenticated as worker {}", worker_id);
                (worker_id, heartbeat_interval_secs)
            }
            DistributedMessage::HelloAck { accepted: false, message, .. } => {
                log::error!("Coordinator rejected: {}", message);
                return Vec::new();
            }
            _ => {
                log::error!("Unexpected response to Hello");
                return Vec::new();
            }
        };

        let semaphore = Arc::new(Semaphore::new(self.max_concurrent));
        let running = Arc::clone(&self.running);
        let mut tasks_done = 0u64;
        let mut tasks_failed = 0u64;
        let mut all_results = Vec::new();

        // Main work loop: request tasks, execute them, report results
        loop {
            if !running.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }

            // Request next batch
            let req = DistributedMessage::TaskRequest {
                worker_id: worker_id.clone(),
                batch_size: self.max_concurrent,
            };
            {
                let mut msg = serde_json::to_string(&req).unwrap();
                msg.push('\n');
                writer.write_all(msg.as_bytes()).await.unwrap();
            }

            // Read response
            line.clear();
            let n = reader.read_line(&mut line).await.unwrap();
            if n == 0 {
                log::info!("Coordinator closed connection");
                break;
            }

            let response: DistributedMessage = serde_json::from_str(line.trim()).unwrap();
            match response {
                DistributedMessage::TaskBatch { tasks, batch_id } => {
                    let batch_size = tasks.len();
                    log::debug!("Received batch {} with {} tasks", batch_id, batch_size);

                    let mut handles = Vec::new();
                    for task in tasks {
                        let sem = Arc::clone(&semaphore);
                        let running = Arc::clone(&running);

                        let handle = tokio::spawn(async move {
                            let _permit = sem.acquire().await.unwrap();
                            if !running.load(std::sync::atomic::Ordering::SeqCst) {
                                return SerializedResult {
                                    task_id: task.task_id,
                                    success: false,
                                    duration_ms: 0,
                                    error: Some("Cancelled".into()),
                                    target_host: task.target_host,
                                    target_port: task.target_port,
                                    protocol: task.protocol,
                                    username: task.username,
                                };
                            }

                            let start = std::time::Instant::now();
                            let proxy: Option<ProxyConfig> = None;
                            let timeout = std::time::Duration::from_secs(task.timeout_secs);

                            let handler = match get_protocol(&task.protocol) {
                                Some(h) => h,
                                None => {
                                    return SerializedResult {
                                        task_id: task.task_id,
                                        success: false,
                                        duration_ms: start.elapsed().as_millis() as u64,
                                        error: Some(format!("Unsupported protocol: {}", task.protocol)),
                                        target_host: task.target_host,
                                        target_port: task.target_port,
                                        protocol: task.protocol,
                                        username: task.username,
                                    };
                                }
                            };

                            let target = crate::core::target::Target::new(
                                task.target_host.clone(),
                                task.target_port,
                                &task.protocol,
                            );
                            let credential = crate::core::credential::Credential {
                                username: task.username.clone(),
                                password: task.password.clone(),
                            };

                            let result = handler
                                .authenticate(&target, &credential, timeout, &proxy)
                                .await;

                            SerializedResult {
                                task_id: task.task_id,
                                success: result.success,
                                duration_ms: start.elapsed().as_millis() as u64,
                                error: result.error,
                                target_host: task.target_host,
                                target_port: task.target_port,
                                protocol: task.protocol,
                                username: task.username,
                            }
                        });
                        handles.push(handle);
                    }

                    let mut batch_results = Vec::new();
                    for h in handles {
                        if let Ok(r) = h.await {
                            if r.success {
                                tasks_done += 1;
                            } else if r.error.is_some() {
                                tasks_failed += 1;
                            }
                            all_results.push(AuthResult {
                                success: r.success,
                                target_host: r.target_host.clone(),
                                target_port: r.target_port,
                                protocol: r.protocol.clone(),
                                username: r.username.clone(),
                                password: String::new(),
                                duration_ms: r.duration_ms,
                                error: r.error.clone(),
                                timestamp: chrono::Utc::now(),
                                r#type: "password".into(),
                            });
                            batch_results.push(r);
                        }
                    }

                    // Report results
                    let report = DistributedMessage::ResultReport {
                        worker_id: worker_id.clone(),
                        batch_id: batch_id.clone(),
                        results: batch_results,
                    };
                    {
                        let mut msg = serde_json::to_string(&report).unwrap();
                        msg.push('\n');
                        writer.write_all(msg.as_bytes()).await.unwrap();
                    }

                    // Read ack
                    line.clear();
                    reader.read_line(&mut line).await.unwrap();
                    if let Ok(DistributedMessage::ResultAck { accepted, .. }) =
                        serde_json::from_str::<DistributedMessage>(line.trim())
                    {
                        if !accepted {
                            log::warn!("Batch {} rejected by coordinator", batch_id);
                        }
                    }
                }
                DistributedMessage::NoMoreWork { reason } => {
                    log::info!("Coordinator: {} — {} tasks done, {} failed", reason, tasks_done, tasks_failed);
                    break;
                }
                DistributedMessage::Error { message, .. } => {
                    log::error!("Coordinator error: {}", message);
                    break;
                }
                _ => {
                    log::warn!("Unexpected message from coordinator");
                }
            }
        }

        all_results
    }
}
