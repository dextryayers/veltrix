use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering, AtomicU64};
use std::time::Duration;
use tokio::sync::{Semaphore, mpsc, Mutex};
use tokio::task::JoinSet;

use super::config::AttackConfig;
use super::credential::Credential;
use super::result::AuthResult;
use super::target::Target;
use crate::protocols::get_protocol;
use crate::proxy::ProxyConfig;

pub struct WorkerTask {
    pub target: Arc<Target>,
    pub credential: Arc<Credential>,
    pub attempt_index: u64,
}

pub struct WorkerPool {
    semaphore: Arc<Semaphore>,
    running: Arc<AtomicBool>,
    retries: u32,
    timeout: Duration,
    stop_on_first: bool,
    proxies: Vec<ProxyConfig>,
    proxy_failures: Arc<Mutex<Vec<u64>>>,
    skipped_users: Arc<Mutex<std::collections::HashSet<String>>>,
    tasks: JoinSet<()>,
    result_tx: mpsc::Sender<(AuthResult, bool)>,
    result_rx: mpsc::Receiver<(AuthResult, bool)>,
    total_submitted: Arc<AtomicU64>,
}

const CHANNEL_BUF: usize = 8192;

impl WorkerPool {
    pub fn new(config: &AttackConfig, running: Arc<AtomicBool>, proxies: Vec<ProxyConfig>) -> Self {
        let proxy_failures = Arc::new(Mutex::new(vec![0u64; proxies.len().max(1)]));
        let (tx, rx) = mpsc::channel(CHANNEL_BUF);
        WorkerPool {
            semaphore: Arc::new(Semaphore::new(config.threads)),
            running,
            retries: config.retries,
            timeout: config.timeout,
            stop_on_first: config.stop_on_first,
            proxies,
            proxy_failures,
            skipped_users: Arc::new(Mutex::new(std::collections::HashSet::new())),
            tasks: JoinSet::new(),
            result_tx: tx,
            result_rx: rx,
            total_submitted: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn submit(&mut self, task: WorkerTask) {
        if !self.running.load(Ordering::Relaxed) {
            return;
        }

        self.total_submitted.fetch_add(1, Ordering::Relaxed);

        let semaphore = Arc::clone(&self.semaphore);
        let running = Arc::clone(&self.running);
        let retries = self.retries;
        let timeout = self.timeout;
        let stop_early = self.stop_on_first;
        let proxy_fails = Arc::clone(&self.proxy_failures);
        let skipped = Arc::clone(&self.skipped_users);
        let proxy = self.get_proxy_for(task.attempt_index as usize);
        let current_proxy_idx = task.attempt_index as usize;
        let target = task.target;
        let credential = task.credential;
        let result_tx = self.result_tx.clone();

        self.tasks.spawn(async move {
            if is_skipped(&skipped, &credential.username).await {
                let _ = result_tx.send((
                    AuthResult::new(
                        target.host.clone(), target.port, &target.protocol,
                        credential.username.clone(), credential.password.clone(),
                        false, Duration::ZERO,
                        Some("Skipped (account locked)".into()),
                    ),
                    stop_early,
                )).await;
                return;
            }

            let handler = match get_protocol(&target.protocol) {
                Some(h) => h,
                None => {
                    let _ = result_tx.send((
                        AuthResult::new(
                        target.host.clone(), target.port, &target.protocol,
                        credential.username.clone(), credential.password.clone(),
                            false, Duration::ZERO,
                            Some(format!("Unsupported protocol: {}", target.protocol)),
                        ),
                        stop_early,
                    )).await;
                    return;
                }
            };

            let mut last_result = None;
            let mut current_proxy = proxy;

            for attempt in 0..=retries {
                if !running.load(Ordering::Relaxed) {
                    break;
                }

                // Acquire semaphore permit only during authenticate call
                let result = {
                    let _permit = semaphore.acquire().await.unwrap();
                    handler
                        .authenticate(&*target, &*credential, timeout, &current_proxy)
                        .await
                };

                let classified = crate::utils::patterns::classify_error(
                    result.error.as_deref(), result.success,
                );

                if result.success {
                    last_result = Some(result);
                    break;
                }

                if crate::utils::patterns::should_skip_user(&classified) {
                    add_skipped(&skipped, &credential.username).await;
                    let _ = result_tx.send((
                        AuthResult {
                            error: Some(format!("Account locked: {}", classified.message)),
                            ..result
                        },
                        stop_early,
                    )).await;
                    return;
                }

                if !classified._retryable {
                    last_result = Some(result);
                    break;
                }

                if crate::utils::patterns::should_rotate_proxy(&classified) && current_proxy.is_some() {
                    inc_proxy_fail(&proxy_fails, current_proxy_idx).await;
                    current_proxy = None;
                }

                if attempt == retries {
                    last_result = Some(result);
                    break;
                }

                tokio::time::sleep(crate::utils::patterns::compute_backoff(attempt)).await;
            }

            if let Some(r) = last_result {
                let _ = result_tx.send((r, stop_early)).await;
            }
        });
    }

    pub fn try_recv_result(&mut self) -> Option<(AuthResult, bool)> {
        self.result_rx.try_recv().ok()
    }

    pub async fn recv_result(&mut self) -> Option<(AuthResult, bool)> {
        self.result_rx.recv().await
    }

    pub fn submitted_count(&self) -> u64 {
        self.total_submitted.load(Ordering::Relaxed)
    }

    pub async fn wait_complete(&mut self) {
        while self.tasks.join_next().await.is_some() {}
        // Drain any remaining results
        while let Ok(r) = self.result_rx.try_recv() {
            drop(r);
        }
    }

    pub async fn collect_all(&mut self) -> Vec<(AuthResult, bool)> {
        while self.tasks.join_next().await.is_some() {}
        let mut results = Vec::new();
        while let Ok(r) = self.result_rx.try_recv() {
            results.push(r);
        }
        results
    }

    fn get_proxy_for(&self, index: usize) -> Option<ProxyConfig> {
        if self.proxies.is_empty() {
            None
        } else {
            Some(self.proxies[index % self.proxies.len()].clone())
        }
    }
}

async fn is_skipped(skipped: &Arc<Mutex<std::collections::HashSet<String>>>, username: &str) -> bool {
    let sk = skipped.lock().await;
    sk.contains(username)
}

async fn add_skipped(skipped: &Arc<Mutex<std::collections::HashSet<String>>>, username: &str) {
    let mut sk = skipped.lock().await;
    sk.insert(username.to_string());
}

async fn inc_proxy_fail(proxy_fails: &Arc<Mutex<Vec<u64>>>, idx: usize) {
    let mut fails = proxy_fails.lock().await;
    if idx < fails.len() {
        fails[idx] += 1;
    }
}
