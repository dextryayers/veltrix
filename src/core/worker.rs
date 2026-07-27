use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering, AtomicU64};
use std::time::Duration;
use tokio::sync::{Semaphore, mpsc};
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
}

pub struct WorkerPool {
    semaphore: Arc<Semaphore>,
    running: Arc<AtomicBool>,
    retries: u32,
    timeout: Duration,
    stop_on_first: bool,
    proxies: Arc<Vec<ProxyConfig>>,
    proxy_failures: Arc<Vec<AtomicU64>>,
    tasks: JoinSet<()>,
    total_submitted: Arc<AtomicU64>,
    skipped_users: Arc<dashmap::DashSet<String>>,
}

impl WorkerPool {
    pub fn new(config: &AttackConfig, running: Arc<AtomicBool>, proxies: Vec<ProxyConfig>) -> Self {
        let proxy_count = proxies.len().max(1);
        let proxy_failures = Arc::new((0..proxy_count).map(|_| AtomicU64::new(0)).collect());
        WorkerPool {
            semaphore: Arc::new(Semaphore::new(config.threads)),
            running,
            retries: config.retries,
            timeout: config.timeout,
            stop_on_first: config.stop_on_first,
            proxies: Arc::new(proxies),
            proxy_failures,
            tasks: JoinSet::new(),
            total_submitted: Arc::new(AtomicU64::new(0)),
            skipped_users: Arc::new(dashmap::DashSet::new()),
        }
    }

    pub fn submit(&mut self, task: WorkerTask) {
        self.submit_inner(task, None);
    }

    pub fn submit_with_sender(&mut self, task: WorkerTask, result_tx: mpsc::UnboundedSender<(AuthResult, bool)>) {
        self.submit_inner(task, Some(result_tx));
    }

    fn submit_inner(&mut self, task: WorkerTask, external_tx: Option<mpsc::UnboundedSender<(AuthResult, bool)>>) {
        if !self.running.load(Ordering::Relaxed) {
            return;
        }

        self.total_submitted.fetch_add(1, Ordering::Relaxed);

        let semaphore = Arc::clone(&self.semaphore);
        let running = Arc::clone(&self.running);
        let retries = self.retries;
        let timeout = self.timeout;
        let stop_early = self.stop_on_first;
        let proxies = Arc::clone(&self.proxies);
        let proxy_fails = Arc::clone(&self.proxy_failures);
        let skipped = Arc::clone(&self.skipped_users);
        let target = task.target;
        let credential = task.credential;

        self.tasks.spawn(async move {
            if skipped.contains(&credential.username) {
                let _ = send_result(&external_tx, (
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
                    let _ = send_result(&external_tx, (
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
            let mut current_proxy = if proxies.is_empty() {
                None
            } else {
                Some(proxies[0].clone())
            };

            for attempt in 0..=retries {
                if !running.load(Ordering::Relaxed) {
                    break;
                }

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
                    skipped.insert(credential.username.clone());
                    let _ = send_result(&external_tx, (
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
                    for f in proxy_fails.iter() {
                        f.fetch_add(1, Ordering::Relaxed);
                    }
                    current_proxy = None;
                }

                if attempt == retries {
                    last_result = Some(result);
                    break;
                }

                tokio::time::sleep(crate::utils::patterns::compute_backoff(attempt)).await;
            }

            if let Some(r) = last_result {
                let _ = send_result(&external_tx, (r, stop_early)).await;
            }
        });
    }

    pub fn submitted_count(&self) -> u64 {
        self.total_submitted.load(Ordering::Relaxed)
    }

    pub async fn wait_complete(&mut self) {
        while self.tasks.join_next().await.is_some() {}
    }

    pub fn is_idle(&self) -> bool {
        self.tasks.is_empty()
    }
}

async fn send_result(tx: &Option<mpsc::UnboundedSender<(AuthResult, bool)>>, result: (AuthResult, bool)) {
    if let Some(ref t) = tx {
        let _ = t.send(result);
    }
}
