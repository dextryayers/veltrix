use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::Semaphore;

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
    timeout: std::time::Duration,
    stop_on_first: bool,
    proxies: Vec<ProxyConfig>,
    proxy_failures: Arc<std::sync::Mutex<Vec<u64>>>,
    skipped_users: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    tasks: Vec<tokio::task::JoinHandle<(AuthResult, bool)>>,
}

impl WorkerPool {
    pub fn new(config: &AttackConfig, running: Arc<AtomicBool>, proxies: Vec<ProxyConfig>) -> Self {
        let proxy_failures = Arc::new(std::sync::Mutex::new(vec![0u64; proxies.len().max(1)]));
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
        }
    }

    pub fn submit(&mut self, task: WorkerTask) {
        let semaphore = Arc::clone(&self.semaphore);
        let running = Arc::clone(&self.running);
        let retries = self.retries;
        let timeout = self.timeout;
        let stop_early = self.stop_on_first;
        let proxy_fails = Arc::clone(&self.proxy_failures);
        let skipped = Arc::clone(&self.skipped_users);
        let proxy = self.get_proxy_for(task.attempt_index as usize);
        let current_proxy_idx = task.attempt_index as usize;
        let protocol = task.target.protocol.clone();
        let target_clone = task.target;
        let credential_clone = task.credential;

        let handle = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            let mut last_result = None;
            let mut current_proxy = proxy;

            if skipped.lock().unwrap().contains(&credential_clone.username) {
                return (
                    AuthResult::new(
                        target_clone.host.clone(), target_clone.port, &protocol,
                        credential_clone.username.clone(), credential_clone.password.clone(),
                        false, std::time::Duration::ZERO,
                        Some("Skipped (account locked)".into()),
                    ),
                    stop_early,
                );
            }

            let handler = match get_protocol(&protocol) {
                Some(h) => h,
                None => {
                    return (
                        AuthResult::new(
                            target_clone.host.clone(), target_clone.port, &protocol,
                            credential_clone.username.clone(), credential_clone.password.clone(),
                            false, std::time::Duration::ZERO,
                            Some(format!("Unsupported protocol: {}", protocol)),
                        ),
                        stop_early,
                    );
                }
            };

            for attempt in 0..=retries {
                if !running.load(Ordering::SeqCst) {
                    break;
                }

                let result = handler
                    .authenticate(&target_clone, &credential_clone, timeout, &current_proxy)
                    .await;

                let classified = crate::utils::patterns::classify_error(
                    result.error.as_deref(), result.success,
                );

                if result.success {
                    last_result = Some(result);
                    break;
                }

                if crate::utils::patterns::should_skip_user(&classified) {
                    skipped.lock().unwrap().insert(credential_clone.username.clone());
                    last_result = Some(AuthResult {
                        error: Some(format!("Account locked: {}", classified.message)),
                        ..result
                    });
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

            (last_result.unwrap(), stop_early)
        });

        self.tasks.push(handle);
    }

    pub async fn collect(self) -> Vec<(AuthResult, bool)> {
        let mut stream: FuturesUnordered<_> = self.tasks.into_iter().collect();
        let mut results = Vec::with_capacity(stream.len());

        while let Some(fut_result) = stream.next().await {
            match fut_result {
                Ok((result, stop_early)) => {
                    results.push((result, stop_early));
                    if stop_early {
                        break;
                    }
                }
                Err(e) => {
                    log::error!("Worker task panicked: {}", e);
                }
            }
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
