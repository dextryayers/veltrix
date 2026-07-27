use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Semaphore, mpsc};

use super::config::AttackConfig;
use super::credential::Credential;
use super::result::AuthResult;
use super::target::Target;
use crate::protocols::get_protocol;
use crate::proxy::ProxyConfig;

pub struct WorkerTask {
    pub target: Target,
    pub credential: Credential,
    pub attempt_index: u64,
}

pub struct WorkerPool {
    semaphore: Arc<Semaphore>,
    running: Arc<AtomicBool>,
    retries: u32,
    timeout: Duration,
    stop_on_first: bool,
    proxies: Vec<ProxyConfig>,
    proxy_failures: Arc<std::sync::Mutex<Vec<u64>>>,
    skipped_users: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    result_tx: mpsc::UnboundedSender<(AuthResult, bool)>,
    result_rx: mpsc::UnboundedReceiver<(AuthResult, bool)>,
    dns_cache: Arc<std::sync::Mutex<HashMap<String, Option<SocketAddr>>>>,
    total_submitted: Arc<std::sync::atomic::AtomicU64>,
}

impl WorkerPool {
    pub fn new(config: &AttackConfig, running: Arc<AtomicBool>, proxies: Vec<ProxyConfig>) -> Self {
        let proxy_failures = Arc::new(std::sync::Mutex::new(vec![0u64; proxies.len().max(1)]));
        let (tx, rx) = mpsc::unbounded_channel();
        WorkerPool {
            semaphore: Arc::new(Semaphore::new(config.threads)),
            running,
            retries: config.retries,
            timeout: config.timeout,
            stop_on_first: config.stop_on_first,
            proxies,
            proxy_failures,
            skipped_users: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            tasks: Vec::new(),
            result_tx: tx,
            result_rx: rx,
            dns_cache: Arc::new(std::sync::Mutex::new(HashMap::new())),
            total_submitted: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    pub fn submit(&mut self, task: WorkerTask) {
        if !self.running.load(Ordering::Relaxed) {
            return;
        }

        let _submitted = self.total_submitted.fetch_add(1, Ordering::Relaxed);

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
        let protocol = target.protocol.clone();
        let result_tx = self.result_tx.clone();
        let _dns_cache = Arc::clone(&self.dns_cache);

        let handle = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            let mut last_result = None;
            let mut current_proxy = proxy;

            let is_skipped = {
                let sk = skipped.lock().unwrap();
                sk.contains(&credential.username)
            };
            if is_skipped {
                let _ = result_tx.send((
                    AuthResult::new(
                        target.host, target.port, &protocol,
                        credential.username, credential.password,
                        false, Duration::ZERO,
                        Some("Skipped (account locked)".into()),
                    ),
                    stop_early,
                ));
                return;
            }

            let handler = match get_protocol(&protocol) {
                Some(h) => h,
                None => {
                    let _ = result_tx.send((
                        AuthResult::new(
                            target.host, target.port, &protocol,
                            credential.username, credential.password,
                            false, Duration::ZERO,
                            Some(format!("Unsupported protocol: {}", protocol)),
                        ),
                        stop_early,
                    ));
                    return;
                }
            };

            for attempt in 0..=retries {
                if !running.load(Ordering::Relaxed) {
                    break;
                }

                let result = handler
                    .authenticate(&target, &credential, timeout, &current_proxy)
                    .await;

                let classified = crate::utils::patterns::classify_error(
                    result.error.as_deref(), result.success,
                );

                if result.success {
                    last_result = Some(result);
                    break;
                }

                if crate::utils::patterns::should_skip_user(&classified) {
                    skipped.lock().unwrap().insert(credential.username.clone());
                    let _ = result_tx.send((
                        AuthResult {
                            error: Some(format!("Account locked: {}", classified.message)),
                            ..result
                        },
                        stop_early,
                    ));
                    return;
                }

                if !classified._retryable {
                    last_result = Some(result);
                    break;
                }

                if crate::utils::patterns::should_rotate_proxy(&classified) && current_proxy.is_some() {
                    if let Ok(mut fails) = proxy_fails.lock() {
                        if current_proxy_idx < fails.len() {
                            fails[current_proxy_idx] += 1;
                        }
                    }
                    current_proxy = None;
                }

                if attempt == retries {
                    last_result = Some(result);
                    break;
                }

                let backoff = crate::utils::patterns::compute_backoff(attempt);
                tokio::time::sleep(backoff).await;
            }

            if let Some(r) = last_result {
                let _ = result_tx.send((r, stop_early));
            }
        });

        self.tasks.push(handle);
    }

    pub fn result_receiver(&mut self) -> &mut mpsc::UnboundedReceiver<(AuthResult, bool)> {
        &mut self.result_rx
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

    pub fn tasks_pending(&self) -> usize {
        self.tasks.len()
    }

    pub async fn drain_results(&mut self) -> Vec<(AuthResult, bool)> {
        let mut results = Vec::new();
        while let Some(r) = self.result_rx.recv().await {
            results.push(r);
        }
        results
    }

    pub async fn wait_complete(&mut self) {
        let handles: Vec<_> = self.tasks.drain(..).collect();
        for h in handles {
            let _ = h.await;
        }
    }

    pub async fn collect_all(&mut self) -> Vec<(AuthResult, bool)> {
        self.wait_complete().await;
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
