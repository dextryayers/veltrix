//! F7.2/F7.4/F7.5: coordinator veltrix-dist-v2.
//! - Split deterministik: ruang task global diiris chunk contiguous; chunk_id
//!   dan checksum dapat diverifikasi worker dan dihitung ulang.
//! - Retry: chunk InFlight yang melewati chunk_timeout dikembalikan ke Pending
//!   (maks max_attempts, lalu Failed). Hasil didedup per task_id stabil.
//! - Token per-run + expiry (F7.4). Status observability (F7.5).

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use chrono::Utc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use uuid::Uuid;

use super::protocol::*;
use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;

#[derive(Debug, Clone)]
pub struct CoordinatorConfig {
    pub bind: String,
    /// Token per-run (F7.4). Wajib dipegang worker saat Hello.
    pub run_token: String,
    /// Umur token sejak coordinator start.
    pub token_ttl_secs: u64,
    pub chunk_size: usize,
    /// InFlight lebih lama dari ini dianggap mati -> requeue.
    pub chunk_timeout_secs: u64,
    /// Worker tanpa heartbeat lebih lama dari ini dianggap mati.
    pub heartbeat_timeout_secs: u64,
    /// Maks assignment ulang per chunk sebelum Failed.
    pub max_chunk_attempts: u32,
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:5555".into(),
            run_token: String::new(),
            token_ttl_secs: 6 * 3600,
            chunk_size: 100,
            chunk_timeout_secs: 120,
            heartbeat_timeout_secs: 60,
            max_chunk_attempts: 3,
        }
    }
}

#[derive(Debug, Clone)]
enum ChunkStatus {
    Pending,
    InFlight { worker_id: String, since: Instant, attempts: u32 },
    Done,
    Failed(String),
}

#[derive(Debug, Clone)]
struct ChunkState {
    spec: ChunkSpec,
    tasks: Vec<SerializedTask>,
    status: ChunkStatus,
}

struct WorkerInfo {
    id: String,
    hostname: String,
    max_concurrent: usize,
    addr: SocketAddr,
    connected_at: Instant,
    last_heartbeat: Instant,
    tasks_done: u64,
    tasks_failed: u64,
}

pub struct Coordinator {
    config: CoordinatorConfig,
    run_id: String,
    started_at: Instant,
    targets: Vec<Target>,
    credentials: Vec<Credential>,
    timeout_secs: u64,
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl Coordinator {
    pub fn new(
        config: CoordinatorConfig,
        targets: Vec<Target>,
        credentials: Vec<Credential>,
        timeout_secs: u64,
        running: Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self {
            config,
            run_id: Uuid::new_v4().to_string(),
            started_at: Instant::now(),
            targets,
            credentials,
            timeout_secs,
            running,
        }
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Materialisasi ruang task deterministik (target-major, lalu credential).
    fn build_tasks(&self) -> Vec<SerializedTask> {
        let mut tasks = Vec::new();
        let mut idx = 0usize;
        for t in &self.targets {
            for c in &self.credentials {
                tasks.push(SerializedTask {
                    task_id: task_id_for(&self.run_id, idx),
                    target_host: t.host.clone(),
                    target_port: t.port,
                    protocol: t.protocol.clone(),
                    username: c.username.clone(),
                    password: c.password.clone(),
                    timeout_secs: self.timeout_secs,
                });
                idx += 1;
            }
        }
        tasks
    }

    fn build_chunks(&self, tasks: Vec<SerializedTask>) -> Vec<ChunkState> {
        let size = self.config.chunk_size.max(1);
        tasks
            .chunks(size)
            .enumerate()
            .map(|(n, slice)| {
                let start = n * size;
                let end = start + slice.len();
                let ids: Vec<String> = slice.iter().map(|t| t.task_id.clone()).collect();
                ChunkState {
                    spec: ChunkSpec::new(&self.run_id, start, end, &ids),
                    tasks: slice.to_vec(),
                    status: ChunkStatus::Pending,
                }
            })
            .collect()
    }

    pub async fn run(&mut self) -> Vec<AuthResult> {
        let tasks = self.build_tasks();
        let total = tasks.len();
        if total == 0 {
            log::warn!("Coordinator: empty task space, nothing to distribute");
            return Vec::new();
        }
        let chunks = self.build_chunks(tasks);
        log::info!(
            "Coordinator run {}: {} tasks in {} chunks (size {})",
            self.run_id, total, chunks.len(), self.config.chunk_size
        );

        let shared = Arc::new(Mutex::new(Shared {
            chunks,
            workers: HashMap::new(),
            seen_task_ids: HashSet::new(),
            results: Vec::new(),
            failed_chunks: Vec::new(),
        }));
        let token = self.config.run_token.clone();
        let token_deadline = Instant::now() + Duration::from_secs(self.config.token_ttl_secs.max(60));
        let run_id = self.run_id.clone();
        let chunk_timeout = Duration::from_secs(self.config.chunk_timeout_secs.max(1));
        let hb_timeout = Duration::from_secs(self.config.heartbeat_timeout_secs.max(5));
        let max_attempts = self.config.max_chunk_attempts.max(1);

        let listener = TcpListener::bind(&self.config.bind).await.unwrap_or_else(|e| {
            panic!("Failed to bind coordinator to {}: {}", self.config.bind, e);
        });
        log::info!("Coordinator listening on {}", self.config.bind);

        let running = Arc::clone(&self.running);
        let mut status_tick = tokio::time::interval(Duration::from_secs(15));
        status_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    let (stream, addr) = match accept_result {
                        Ok(v) => v,
                        Err(e) => { log::error!("Accept error: {}", e); continue; }
                    };
                    let shared = Arc::clone(&shared);
                    let running = Arc::clone(&running);
                    let token = token.clone();
                    let run_id = run_id.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_worker(stream, addr, token, token_deadline, run_id, shared, running).await {
                            log::debug!("Worker {} session ended: {}", addr, e);
                        }
                    });
                }
                _ = status_tick.tick() => {
                    Self::reap_and_log(&shared, chunk_timeout, hb_timeout, max_attempts).await;
                }
                _ = async {
                    while running.load(std::sync::atomic::Ordering::SeqCst) {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                } => break,
            }
            // F7.2: selesai bila semua chunk Done/Failed.
            if Self::is_complete(&shared).await {
                log::info!("Coordinator run {}: all chunks settled", run_id);
                break;
            }
            if !self.running.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
        }

        let shared = shared.lock().await;
        log::info!(
            "Coordinator finished run {}: {} results ({} unique), {} failed chunks, {} workers seen",
            run_id, shared.results.len(), shared.seen_task_ids.len(), shared.failed_chunks.len(),
            shared.workers.len(),
        );
        shared.results.clone()
    }

    async fn is_complete(shared: &Arc<Mutex<Shared>>) -> bool {
        let s = shared.lock().await;
        s.chunks.iter().all(|c| matches!(c.status, ChunkStatus::Done | ChunkStatus::Failed(_)))
    }

    /// Reaper: kembalikan chunk InFlight kadaluarsa ke Pending, drop worker basi,
    /// lalu tulis ringkasan observability (F7.5).
    async fn reap_and_log(
        shared: &Arc<Mutex<Shared>>,
        chunk_timeout: Duration,
        hb_timeout: Duration,
        max_attempts: u32,
    ) {
        let mut s = shared.lock().await;
        let now = Instant::now();
        // Drop worker basi.
        let stale: Vec<String> = s
            .workers
            .iter()
            .filter(|(_, w)| now.duration_since(w.last_heartbeat) > hb_timeout)
            .map(|(id, _)| id.clone())
            .collect();
        for id in stale {
            log::warn!("Coordinator: worker {} heartbeat timeout, dropping", id);
            s.workers.remove(&id);
        }
        // Requeue chunk yatim / kadaluarsa (kumpulkan dulu agar tak double-borrow).
        let mut requeue: Vec<usize> = Vec::new();
        let mut failed: Vec<usize> = Vec::new();
        for (i, chunk) in s.chunks.iter().enumerate() {
            let (wid, since, attempts) = match &chunk.status {
                ChunkStatus::InFlight { worker_id, since, attempts } => {
                    (worker_id.clone(), *since, *attempts)
                }
                _ => continue,
            };
            let orphaned = !s.workers.contains_key(&wid);
            let expired = now.duration_since(since) > chunk_timeout;
            if orphaned || expired {
                if attempts + 1 >= max_attempts && expired && !orphaned {
                    failed.push(i);
                } else {
                    requeue.push(i);
                }
            }
        }
        for i in requeue {
            let wid = match &s.chunks[i].status {
                ChunkStatus::InFlight { worker_id, .. } => worker_id.clone(),
                _ => String::new(),
            };
            log::warn!("Coordinator: requeue chunk {} (worker {})", s.chunks[i].spec.chunk_id, wid);
            s.chunks[i].status = ChunkStatus::Pending;
        }
        for i in failed {
            let cid = s.chunks[i].spec.chunk_id.clone();
            let attempts = match &s.chunks[i].status {
                ChunkStatus::InFlight { attempts, .. } => *attempts + 1,
                _ => max_attempts,
            };
            s.chunks[i].status = ChunkStatus::Failed(format!("chunk {} timed out {} times", cid, attempts));
            s.failed_chunks.push(cid.clone());
            log::error!("Coordinator: chunk {} FAILED after {} attempts", cid, attempts);
        }
        let (done, pending, inflight, failed) =
            (s.count_done(), s.count_pending(), s.count_inflight(), s.failed_chunks.len());
        log::info!(
            "Coordinator status: {}/{} chunks done, {} pending, {} inflight, {} failed | {} results, {} workers",
            done, s.chunks.len(), pending, inflight, failed, s.results.len(), s.workers.len()
        );
        for (id, w) in s.workers.iter() {
            let secs = now.duration_since(w.connected_at).as_secs_f64().max(1.0);
            log::info!(
                "  worker {} ({}): done={} failed={} rate={:.1}/s",
                &id[..8.min(id.len())], w.hostname, w.tasks_done, w.tasks_failed,
                w.tasks_done as f64 / secs
            );
        }
    }

    /// Snapshot observability untuk log status (F7.5).
    fn status_snapshot(s: &Shared) -> CoordinatorStatus {
        CoordinatorStatus {
            chunks_total: s.chunks.len(),
            chunks_done: s.count_done(),
            chunks_pending: s.count_pending(),
            chunks_inflight: s.count_inflight(),
            failed_chunks: s.failed_chunks.clone(),
            unique_results: s.seen_task_ids.len(),
            workers: s.workers.len(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CoordinatorStatus {
    pub chunks_total: usize,
    pub chunks_done: usize,
    pub chunks_pending: usize,
    pub chunks_inflight: usize,
    pub failed_chunks: Vec<String>,
    pub unique_results: usize,
    pub workers: usize,
}

struct Shared {
    chunks: Vec<ChunkState>,
    workers: HashMap<String, WorkerInfo>,
    seen_task_ids: HashSet<String>,
    results: Vec<AuthResult>,
    failed_chunks: Vec<String>,
}

impl Shared {
    fn count_done(&self) -> usize {
        self.chunks.iter().filter(|c| matches!(c.status, ChunkStatus::Done)).count()
    }
    fn count_pending(&self) -> usize {
        self.chunks.iter().filter(|c| matches!(c.status, ChunkStatus::Pending)).count()
    }
    fn count_inflight(&self) -> usize {
        self.chunks.iter().filter(|c| matches!(c.status, ChunkStatus::InFlight { .. })).count()
    }
}

async fn send_msg(writer: &mut tokio::net::tcp::OwnedWriteHalf, msg: &DistributedMessage) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut s = serde_json::to_string(msg).unwrap_or_default();
    s.push('\n');
    writer.write_all(s.as_bytes()).await
}

async fn handle_worker(
    stream: TcpStream,
    addr: SocketAddr,
    token: String,
    token_deadline: Instant,
    run_id: String,
    shared: Arc<Mutex<Shared>>,
    running: Arc<std::sync::atomic::AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, writer) = stream.into_split();
    let writer = Arc::new(Mutex::new(writer));
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    reader.read_line(&mut line).await?;
    let msg: DistributedMessage = serde_json::from_str(line.trim())?;
    let (hostname, max_concurrent, completed_hint) = match msg {
        DistributedMessage::Hello { version, run_token, hostname, max_concurrent, completed_hint } => {
            if version != PROTOCOL_VERSION {
                let mut w = writer.lock().await;
                send_msg(&mut w, &DistributedMessage::HelloAck {
                    accepted: false,
                    message: format!("Unsupported version: {} (need {})", version, PROTOCOL_VERSION),
                    worker_id: String::new(),
                    run_id: String::new(),
                    heartbeat_interval_secs: 0,
                }).await?;
                return Ok(());
            }
            // F7.4: token salah atau kadaluarsa -> tolak.
            if run_token != token {
                let mut w = writer.lock().await;
                send_msg(&mut w, &DistributedMessage::HelloAck {
                    accepted: false,
                    message: "Invalid run token".into(),
                    worker_id: String::new(),
                    run_id: String::new(),
                    heartbeat_interval_secs: 0,
                }).await?;
                return Ok(());
            }
            if Instant::now() > token_deadline {
                let mut w = writer.lock().await;
                send_msg(&mut w, &DistributedMessage::HelloAck {
                    accepted: false,
                    message: "Run token expired".into(),
                    worker_id: String::new(),
                    run_id: String::new(),
                    heartbeat_interval_secs: 0,
                }).await?;
                return Ok(());
            }
            (hostname, max_concurrent, completed_hint)
        }
        _ => {
            let mut w = writer.lock().await;
            send_msg(&mut w, &DistributedMessage::Error {
                worker_id: String::new(),
                message: "Expected Hello first".into(),
            }).await?;
            return Ok(());
        }
    };

    let worker_id = Uuid::new_v4().to_string();
    {
        let mut s = shared.lock().await;
        // Seed dedup dari checkpoint worker (hasil yang sudah di-ack sebelum crash).
        for id in completed_hint.iter().take(10_000) {
            s.seen_task_ids.insert(id.clone());
        }
        s.workers.insert(worker_id.clone(), WorkerInfo {
            id: worker_id.clone(),
            hostname: hostname.clone(),
            max_concurrent: max_concurrent.max(1),
            addr,
            connected_at: Instant::now(),
            last_heartbeat: Instant::now(),
            tasks_done: 0,
            tasks_failed: 0,
        });
    }
    log::info!("Coordinator: worker {} ({}) joined run {}", &worker_id[..8.min(worker_id.len())], hostname, &run_id[..8.min(run_id.len())]);
    {
        let mut w = writer.lock().await;
        send_msg(&mut w, &DistributedMessage::HelloAck {
            accepted: true,
            message: "Welcome to Veltrix distributed coordinator v2".into(),
            worker_id: worker_id.clone(),
            run_id: run_id.clone(),
            heartbeat_interval_secs: 10,
        }).await?;
    }

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            log::info!("Worker {} disconnected", &worker_id[..8.min(worker_id.len())]);
            break;
        }
        let msg: DistributedMessage = match serde_json::from_str(line.trim()) {
            Ok(m) => m,
            Err(e) => {
                log::warn!("Worker {} sent invalid message: {}", &worker_id[..8.min(worker_id.len())], e);
                continue;
            }
        };
        match msg {
            DistributedMessage::TaskRequest { worker_id: wid, batch_size } => {
                if wid != worker_id {
                    continue;
                }
                let assignment = {
                    let mut s = shared.lock().await;
                    assign_chunk(&mut s, &wid, batch_size.max(1))
                };
                let mut w = writer.lock().await;
                match assignment {
                    Some((spec, tasks)) => {
                        send_msg(&mut w, &DistributedMessage::TaskBatch { chunk: spec, tasks }).await?;
                    }
                    None => {
                        // Belum tentu selesai: mungkin semua InFlight. Kirim tunggu.
                        let done = {
                            let s = shared.lock().await;
                            s.chunks.iter().all(|c| matches!(c.status, ChunkStatus::Done | ChunkStatus::Failed(_)))
                        };
                        if done {
                            send_msg(&mut w, &DistributedMessage::NoMoreWork { reason: "All chunks settled".into() }).await?;
                            break;
                        } else {
                            send_msg(&mut w, &DistributedMessage::NoMoreWork { reason: "No pending chunks right now, retry shortly".into() }).await?;
                        }
                    }
                }
            }
            DistributedMessage::ResultReport { worker_id: wid, run_id: rid, chunk_id, results } => {
                if wid != worker_id || rid != run_id {
                    continue;
                }
                let (accepted, dups) = {
                    let mut s = shared.lock().await;
                    // Verifikasi checksum chunk: task_ids harus cocok.
                    let ok = s.chunks.iter().find(|c| c.spec.chunk_id == chunk_id).map(|c| {
                        let ids: Vec<String> = results.iter().map(|r| r.task_id.clone()).collect();
                        // Izinkan subset (worker boleh skip task busuk) tapi tolak task asing.
                        let known: HashSet<String> = c.tasks.iter().map(|t| t.task_id.clone()).collect();
                        ids.iter().all(|id| known.contains(id))
                    }).unwrap_or(false);
                    if !ok {
                        (false, 0)
                    } else {
                        let mut dups = 0usize;
                        for sr in &results {
                            if !s.seen_task_ids.insert(sr.task_id.clone()) {
                                dups += 1;
                                continue;
                            }
                            s.results.push(AuthResult {
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
                        // Tandai chunk Done; worker jujur melaporkan semua task chunknya.
                        if let Some(c) = s.chunks.iter_mut().find(|c| c.spec.chunk_id == chunk_id) {
                            c.status = ChunkStatus::Done;
                        }
                        if let Some(h) = s.workers.get_mut(&wid) {
                            h.tasks_done += results.iter().filter(|r| r.success).count() as u64;
                            h.tasks_failed += results.iter().filter(|r| !r.success && r.error.is_some()).count() as u64;
                        }
                        (true, dups)
                    }
                };
                let mut w = writer.lock().await;
                send_msg(&mut w, &DistributedMessage::ResultAck { chunk_id, accepted, duplicate_count: dups }).await?;
            }
            DistributedMessage::Heartbeat { worker_id: wid, tasks_done, tasks_failed, .. } => {
                {
                    let mut s = shared.lock().await;
                    if let Some(h) = s.workers.get_mut(&wid) {
                        h.last_heartbeat = Instant::now();
                        h.tasks_done = h.tasks_done.max(tasks_done);
                        h.tasks_failed = h.tasks_failed.max(tasks_failed);
                    }
                }
                let mut w = writer.lock().await;
                send_msg(&mut w, &DistributedMessage::HeartbeatAck { ok: true }).await?;
            }
            _ => {}
        }
        if !running.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
    }

    // Worker pergi: chunk InFlight-nya dibiarkan untuk reaper (retry otomatis).
    log::info!("Worker {} session closed", &worker_id[..8.min(worker_id.len())]);
    Ok(())
}

/// Ambil satu chunk Pending untuk worker (tandai InFlight).
/// Jika chunk lebih besar dari batch_size worker, potong: bagian aktif
/// di-assign (spec + checksum dihitung ulang), sisa jadi chunk Pending baru.
fn assign_chunk(
    s: &mut Shared,
    worker_id: &str,
    batch_size: usize,
) -> Option<(ChunkSpec, Vec<SerializedTask>)> {
    let idx = s.chunks.iter().position(|c| matches!(c.status, ChunkStatus::Pending))?;
    let prev_attempts = match &s.chunks[idx].status {
        ChunkStatus::InFlight { attempts, .. } => *attempts,
        _ => 0,
    };
    let run_id = s.chunks[idx].spec.run_id.clone();
    let base_start = s.chunks[idx].spec.start_idx;
    if s.chunks[idx].tasks.len() > batch_size {
        let rest = s.chunks[idx].tasks.split_off(batch_size);
        let mid = base_start + batch_size;
        let end = s.chunks[idx].spec.end_idx;
        let rest_ids: Vec<String> = rest.iter().map(|t| t.task_id.clone()).collect();
        let active_ids: Vec<String> =
            s.chunks[idx].tasks.iter().map(|t| t.task_id.clone()).collect();
        s.chunks[idx].spec = ChunkSpec::new(&run_id, base_start, mid, &active_ids);
        s.chunks.push(ChunkState {
            spec: ChunkSpec::new(&run_id, mid, end, &rest_ids),
            tasks: rest,
            status: ChunkStatus::Pending,
        });
    }
    let chunk = &mut s.chunks[idx];
    chunk.status = ChunkStatus::InFlight {
        worker_id: worker_id.to_string(),
        since: Instant::now(),
        attempts: prev_attempts + 1,
    };
    Some((chunk.spec.clone(), chunk.tasks.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_shared(n_tasks: usize, chunk_size: usize) -> (Coordinator, Shared) {
        let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let coord = Coordinator::new(
            CoordinatorConfig { chunk_size, ..Default::default() },
            vec![Target::new("127.0.0.1".into(), 22, "ssh")],
            (0..n_tasks).map(|i| Credential::new(format!("u{}", i), "p".into())).collect(),
            5,
            running,
        );
        let tasks = coord.build_tasks();
        let chunks = coord.build_chunks(tasks);
        let shared = Shared {
            chunks,
            workers: HashMap::new(),
            seen_task_ids: HashSet::new(),
            results: Vec::new(),
            failed_chunks: Vec::new(),
        };
        (coord, shared)
    }

    #[test]
    fn chunks_cover_all_tasks_exactly_once() {
        let (_c, shared) = test_shared(250, 100);
        assert_eq!(shared.chunks.len(), 3);
        let mut ids: Vec<String> = shared.chunks.iter().flat_map(|c| c.tasks.iter().map(|t| t.task_id.clone())).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 250);
        // Spec konsisten dengan isi.
        for ch in &shared.chunks {
            let content: Vec<String> = ch.tasks.iter().map(|t| t.task_id.clone()).collect();
            assert_eq!(ch.spec.checksum, chunk_checksum(&ch.spec.run_id, &ch.spec.chunk_id, &content));
            assert_eq!(ch.spec.end_idx - ch.spec.start_idx, ch.tasks.len());
        }
    }

    #[test]
    fn assign_marks_inflight_and_splits() {
        let (_c, mut shared) = test_shared(250, 100);
        let (spec, tasks) = assign_chunk(&mut shared, "w1", 40).unwrap();
        assert_eq!(tasks.len(), 40);
        assert_eq!(spec.end_idx - spec.start_idx, 40);
        // Sisa 60 jadi chunk Pending baru di ekor: total chunk 4.
        assert_eq!(shared.chunks.len(), 4);
        // Assign berikutnya ambil Pending pertama = chunk 100 utuh kedua.
        let (spec2, tasks2) = assign_chunk(&mut shared, "w1", 100).unwrap();
        assert_eq!(tasks2.len(), 100);
        assert_eq!(spec2.start_idx, 100);
        // Sisa Pending: 60 (ekor split) + 50.
        let pending: usize = shared.chunks.iter()
            .filter(|c| matches!(c.status, ChunkStatus::Pending))
            .map(|c| c.tasks.len())
            .sum();
        assert_eq!(pending, 110);
    }

    #[test]
    fn full_assign_drains_pending() {
        let (_c, mut shared) = test_shared(10, 10);
        assert!(assign_chunk(&mut shared, "w1", 100).is_some());
        assert!(assign_chunk(&mut shared, "w1", 100).is_none());
        assert_eq!(Coordinator::status_snapshot(&shared).chunks_inflight, 1);
    }
}
