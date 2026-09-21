//! F7.3: worker veltrix-dist-v2.
//! - Heartbeat periodik di task terpisah (shared writer).
//! - Checkpoint file JSON: task_id yang sudah di-ack, untuk forensik dan
//!   seed dedup coordinator saat reconnect (lihat Hello.completed_hint).
//! - Graceful drain: saat running=false, batch aktif diselesaikan + dilaporkan
//!   dulu sebelum keluar.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore};

use super::protocol::*;
use crate::core::result::AuthResult;
use crate::protocols::get_protocol;
use crate::proxy::ProxyConfig;

pub struct DistributedWorker {
    coordinator_addr: String,
    run_token: String,
    hostname: String,
    max_concurrent: usize,
    running: Arc<AtomicBool>,
    /// Path checkpoint opsional (JSON {run_id, task_ids}).
    pub checkpoint_path: Option<PathBuf>,
    /// Hook test/chaos: berhenti meminta batch setelah N batch (None = normal).
    pub stop_after_batches: Option<usize>,
}

impl DistributedWorker {
    pub fn new(
        coordinator_addr: String,
        run_token: String,
        hostname: String,
        max_concurrent: usize,
        running: Arc<AtomicBool>,
    ) -> Self {
        DistributedWorker {
            coordinator_addr,
            run_token,
            hostname,
            max_concurrent: max_concurrent.max(1),
            running,
            checkpoint_path: None,
            stop_after_batches: None,
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
        let (reader, writer) = stream.into_split();
        let writer = Arc::new(Mutex::new(writer));
        let mut reader = BufReader::new(reader);
        let mut line = String::new();

        // Checkpoint lokal: seed Hello agar coordinator bisa dedup hasil lama.
        let completed_hint = self.load_checkpoint();
        if !completed_hint.is_empty() {
            log::info!("Loaded {} completed task_ids from checkpoint", completed_hint.len());
        }

        // Send Hello (v2)
        {
            let hello = DistributedMessage::Hello {
                version: PROTOCOL_VERSION.to_string(),
                run_token: self.run_token.clone(),
                hostname: self.hostname.clone(),
                max_concurrent: self.max_concurrent,
                completed_hint: completed_hint.into_iter().take(10_000).collect(),
            };
            let mut w = writer.lock().await;
            if send(&mut w, &hello).await.is_err() {
                return Vec::new();
            }
        }

        // Read HelloAck
        line.clear();
        if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
            log::error!("Coordinator closed connection during handshake");
            return Vec::new();
        }
        let ack: DistributedMessage = match serde_json::from_str(line.trim()) {
            Ok(m) => m,
            Err(e) => {
                log::error!("Invalid HelloAck: {}", e);
                return Vec::new();
            }
        };
        let (worker_id, run_id, heartbeat_interval) = match ack {
            DistributedMessage::HelloAck { accepted: true, worker_id, run_id, heartbeat_interval_secs, .. } => {
                log::info!("Authenticated as worker {} in run {}", &worker_id[..8.min(worker_id.len())], &run_id[..8.min(run_id.len())]);
                (worker_id, run_id, heartbeat_interval_secs.max(2))
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

        // Heartbeat task (F7.3).
        let tasks_done = Arc::new(AtomicU64::new(0));
        let tasks_failed = Arc::new(AtomicU64::new(0));
        let hb_done = Arc::clone(&tasks_done);
        let hb_failed = Arc::clone(&tasks_failed);
        let hb_writer = Arc::clone(&writer);
        let hb_running = Arc::clone(&self.running);
        let hb_wid = worker_id.clone();
        let hb_run = run_id.clone();
        let hb_handle = tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(heartbeat_interval));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                if !hb_running.load(Ordering::SeqCst) {
                    break;
                }
                let hb = DistributedMessage::Heartbeat {
                    worker_id: hb_wid.clone(),
                    run_id: hb_run.clone(),
                    tasks_done: hb_done.load(Ordering::Relaxed),
                    tasks_failed: hb_failed.load(Ordering::Relaxed),
                    cpu_percent: 0.0,
                    mem_mb: 0,
                };
                let mut w = hb_writer.lock().await;
                if send(&mut w, &hb).await.is_err() {
                    break;
                }
                // Konsumsi ack agar buffer baca utama tidak tercemar.
                drop(w);
            }
        });
        // NOTE: ack heartbeat dilewati oleh read_batch_response di loop utama,
        // karena heartbeat berjalan di task terpisah pada koneksi yang sama.

        let semaphore = Arc::new(Semaphore::new(self.max_concurrent));
        let mut all_results = Vec::new();
        let mut batches_done = 0usize;

        // Main work loop.
        let result = self
            .work_loop(
                &mut reader,
                &writer,
                &worker_id,
                &run_id,
                &semaphore,
                &tasks_done,
                &tasks_failed,
                &mut all_results,
                &mut batches_done,
            )
            .await;

        if let Err(e) = result {
            log::debug!("Work loop ended: {}", e);
        }

        // Graceful drain: checkpoint sudah ditulis per ack di work_loop.
        hb_handle.abort();
        log::info!(
            "Worker {} done: {} results ({} batches)",
            &worker_id[..8.min(worker_id.len())],
            all_results.len(),
            batches_done
        );
        all_results
    }

    #[allow(clippy::too_many_arguments)]
    async fn work_loop(
        &self,
        reader: &mut BufReader<OwnedReadHalf>,
        writer: &Arc<Mutex<OwnedWriteHalf>>,
        worker_id: &str,
        run_id: &str,
        semaphore: &Arc<Semaphore>,
        tasks_done: &Arc<AtomicU64>,
        tasks_failed: &Arc<AtomicU64>,
        all_results: &mut Vec<AuthResult>,
        batches_done: &mut usize,
    ) -> Result<(), String> {
        let running = Arc::clone(&self.running);
        let mut line = String::new();
        loop {
            if !running.load(Ordering::SeqCst) {
                break;
            }
            if let Some(max_b) = self.stop_after_batches {
                if *batches_done >= max_b {
                    log::warn!("Worker stopping after {} batches (test hook)", max_b);
                    break;
                }
            }

            // Request next batch (ukuran = chunk penuh agar tidak terpotong).
            {
                let req = DistributedMessage::TaskRequest {
                    worker_id: worker_id.to_string(),
                    batch_size: usize::MAX / 2,
                };
                let mut w = writer.lock().await;
                send(&mut w, &req).await.map_err(|e| e.to_string())?;
            }

            line.clear();
            let response = read_batch_response(reader, &mut line).await?;
            match response {
                DistributedMessage::TaskBatch { chunk, tasks } => {
                    // Verifikasi checksum sebelum eksekusi (F7.1).
                    let ids: Vec<String> = tasks.iter().map(|t| t.task_id.clone()).collect();
                    let expect = chunk_checksum(&chunk.run_id, &chunk.chunk_id, &ids);
                    if expect != chunk.checksum {
                        log::error!("Chunk {} checksum mismatch, skipping batch", chunk.chunk_id);
                        continue;
                    }
                    log::debug!("Received chunk {} with {} tasks", chunk.chunk_id, tasks.len());

                    let mut handles = Vec::new();
                    for task in tasks {
                        let sem = Arc::clone(semaphore);
                        let running = Arc::clone(&running);
                        handles.push(tokio::spawn(async move {
                            let _permit = sem.acquire().await.unwrap();
                            execute_task(task, running).await
                        }));
                    }
                    let mut batch_results = Vec::new();
                    for h in handles {
                        if let Ok(r) = h.await {
                            if r.success {
                                tasks_done.fetch_add(1, Ordering::Relaxed);
                            } else if r.error.is_some() {
                                tasks_failed.fetch_add(1, Ordering::Relaxed);
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

                    // Report + tunggu ack (graceful drain: batch aktif selalu dilaporkan).
                    let acked: Vec<String> = batch_results.iter().map(|r| r.task_id.clone()).collect();
                    {
                        let report = DistributedMessage::ResultReport {
                            worker_id: worker_id.to_string(),
                            run_id: run_id.to_string(),
                            chunk_id: chunk.chunk_id.clone(),
                            results: batch_results,
                        };
                        let mut w = writer.lock().await;
                        send(&mut w, &report).await.map_err(|e| e.to_string())?;
                    }
                    line.clear();
                    match read_batch_response(reader, &mut line).await {
                        Ok(DistributedMessage::ResultAck { accepted, duplicate_count, .. }) => {
                            if !accepted {
                                log::warn!("Chunk {} rejected by coordinator", chunk.chunk_id);
                            } else {
                                if duplicate_count > 0 {
                                    log::info!("Chunk {}: {} duplicates ignored", chunk.chunk_id, duplicate_count);
                                }
                                // Checkpoint: hanya task yang di-ack coordinator.
                                *batches_done += 1;
                                self.append_checkpoint(run_id, &acked).await;
                            }
                        }
                        Ok(_) => {
                            log::warn!("Unexpected message after ResultReport; continuing");
                        }
                        Err(e) => return Err(e),
                    }
                }
                DistributedMessage::NoMoreWork { reason } => {
                    // "retry shortly" = jeda lalu minta lagi; "settled" = selesai.
                    if reason.contains("settled") || reason.contains("completed") {
                        log::info!("Coordinator: {}", reason);
                        break;
                    }
                    log::debug!("Coordinator: {}, retrying", reason);
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
                DistributedMessage::HeartbeatAck { .. } => {
                    // Balasan heartbeat kita; abaikan.
                }
                DistributedMessage::Error { message, .. } => {
                    return Err(format!("coordinator error: {}", message));
                }
                _ => {
                    log::warn!("Unexpected message from coordinator");
                }
            }
        }
        Ok(())
    }

    /// Tulis checkpoint JSON {run_id, task_ids} (atomik via tmp+rename).
    async fn append_checkpoint(&self, run_id: &str, acked: &[String]) {
        let path = match &self.checkpoint_path {
            Some(p) => p.clone(),
            None => return,
        };
        // Baca yang ada, gabung (dedup), tulis ulang atomik via tmp+rename.
        let mut ids: Vec<String> = self.load_checkpoint();
        ids.extend(acked.iter().cloned());
        ids.sort();
        ids.dedup();
        let doc = serde_json::json!({ "run_id": run_id, "task_ids": ids });
        let tmp = path.with_extension("tmp");
        let written = serde_json::to_string(&doc)
            .map(|s| std::fs::write(&tmp, s).is_ok())
            .unwrap_or(false);
        if written {
            let _ = std::fs::rename(&tmp, &path);
        }
    }

    fn load_checkpoint(&self) -> Vec<String> {
        let path = match &self.checkpoint_path {
            Some(p) => p,
            None => return Vec::new(),
        };
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };
        serde_json::from_str::<serde_json::Value>(&content)
            .ok()
            .and_then(|v| v.get("task_ids").cloned())
            .and_then(|v| serde_json::from_value::<Vec<String>>(v).ok())
            .unwrap_or_default()
    }
}

async fn send(writer: &mut OwnedWriteHalf, msg: &DistributedMessage) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut s = serde_json::to_string(msg).unwrap_or_default();
    s.push('\n');
    writer.write_all(s.as_bytes()).await
}

/// Baca respons batch berikutnya, lewati HeartbeatAck yang terselip
/// (heartbeat berjalan di task terpisah pada koneksi yang sama).
async fn read_batch_response(
    reader: &mut BufReader<OwnedReadHalf>,
    line: &mut String,
) -> Result<DistributedMessage, String> {
    loop {
        line.clear();
        let n = reader.read_line(line).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("coordinator closed connection".into());
        }
        let msg: DistributedMessage =
            serde_json::from_str(line.trim()).map_err(|e| e.to_string())?;
        match msg {
            DistributedMessage::HeartbeatAck { .. } => continue,
            other => return Ok(other),
        }
    }
}

async fn execute_task(
    task: SerializedTask,
    running: Arc<AtomicBool>,
) -> SerializedResult {
    if !running.load(Ordering::SeqCst) {
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
    let timeout = std::time::Duration::from_secs(task.timeout_secs.max(1));
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
    let result = handler.authenticate(&target, &credential, timeout, &proxy).await;
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
}
