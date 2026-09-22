use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering, AtomicU64};
use std::time::{Duration, Instant};
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
    proxies: Arc<Vec<ProxyConfig>>,
    proxy_failures: Arc<Vec<AtomicU64>>,
    tasks: JoinSet<()>,
    total_submitted: Arc<AtomicU64>,
    skipped_users: Arc<dashmap::DashSet<String>>,
    fp_check: bool,
    // F4.3: cooldown sementara pengganti skip permanen buta.
    lockout_cooldown: Duration,
    rate_cooldown: Duration,
    lockout_pause: bool,
    user_cooldowns: Arc<dashmap::DashMap<String, Instant>>,
    target_cooldowns: Arc<dashmap::DashMap<String, Instant>>,
    // ANON: rotasi proxy terjadwal tiap N attempt (0 = hanya saat sinyal).
    rotation_every: usize,
    rotation_counter: Arc<AtomicU64>,
    // ANON A3: health runtime — proxy yang beruntun gagal koneksi di-ban
    // sementara agar egress tidak macet di jalur mati.
    proxy_strikes: Arc<Vec<AtomicU64>>,
    proxy_banned_until: Arc<dashmap::DashMap<usize, Instant>>,
}

/// Proxy yang beruntun gagal koneksi/Timeout sebanyak ini → di-ban sementara.
const MAX_PROXY_STRIKES: u64 = 5;
/// Lama ban proxy mati (detik).
const PROXY_BAN_SECS: u64 = 60;

impl WorkerPool {
    pub fn new(config: &AttackConfig, running: Arc<AtomicBool>, proxies: Vec<ProxyConfig>) -> Self {
        let proxy_count = proxies.len().max(1);
        let proxy_failures = Arc::new((0..proxy_count).map(|_| AtomicU64::new(0)).collect());
        let proxy_strikes: Arc<Vec<AtomicU64>> =
            Arc::new((0..proxy_count).map(|_| AtomicU64::new(0)).collect());
        WorkerPool {
            semaphore: Arc::new(Semaphore::new(config.threads)),
            running,
            retries: config.retries,
            timeout: config.timeout,
            proxies: Arc::new(proxies),
            proxy_failures,
            tasks: JoinSet::new(),
            total_submitted: Arc::new(AtomicU64::new(0)),
            skipped_users: Arc::new(dashmap::DashSet::new()),
            fp_check: config.fp_check,
            lockout_cooldown: config.lockout_cooldown,
            rate_cooldown: config.rate_cooldown,
            lockout_pause: config.lockout_pause,
            user_cooldowns: Arc::new(dashmap::DashMap::new()),
            target_cooldowns: Arc::new(dashmap::DashMap::new()),
            rotation_every: config.rotate_proxy_every,
            rotation_counter: Arc::new(AtomicU64::new(0)),
            proxy_strikes: Arc::clone(&proxy_strikes),
            proxy_banned_until: Arc::new(dashmap::DashMap::new()),
        }
    }

    /// Jumlah proxy yang sedang di-ban (observability).
    pub fn banned_proxy_count(&self) -> usize {
        let now = Instant::now();
        self.proxy_banned_until.iter().filter(|r| *r.value() > now).count()
    }

    pub fn submit(&mut self, task: WorkerTask) {
        self.submit_inner(task, None);
    }

    pub fn submit_with_sender(&mut self, task: WorkerTask, result_tx: mpsc::UnboundedSender<AuthResult>) {
        self.submit_inner(task, Some(result_tx));
    }

    fn submit_inner(&mut self, task: WorkerTask, external_tx: Option<mpsc::UnboundedSender<AuthResult>>) {
        if !self.running.load(Ordering::Relaxed) {
            return;
        }

        self.total_submitted.fetch_add(1, Ordering::Relaxed);

        let semaphore = Arc::clone(&self.semaphore);
        let running = Arc::clone(&self.running);
        let retries = self.retries;
        let timeout = self.timeout;
        let proxies = Arc::clone(&self.proxies);
        let proxy_fails = Arc::clone(&self.proxy_failures);
        let fp_check = self.fp_check;
        let lockout_cooldown = self.lockout_cooldown;
        let rate_cooldown = self.rate_cooldown;
        let lockout_pause = self.lockout_pause;
        let user_cooldowns = Arc::clone(&self.user_cooldowns);
        let target_cooldowns = Arc::clone(&self.target_cooldowns);
        let rotation_every = self.rotation_every;
        let rotation_counter = Arc::clone(&self.rotation_counter);
        let proxy_strikes = Arc::clone(&self.proxy_strikes);
        let proxy_banned_until = Arc::clone(&self.proxy_banned_until);
        let skipped = Arc::clone(&self.skipped_users);
        let target = task.target;
        let credential = task.credential;

        self.tasks.spawn(async move {
            let target_key = format!("{}:{}", target.host, target.port);
            // F4.3: hormati cooldown user yang masih aktif, tanpa attempt baru.
            if let Some(until) = user_cooldowns.get(&credential.username).map(|r| *r) {
                if Instant::now() < until {
                    let _ = send_result(&external_tx,
                        AuthResult::new(
                            target.host.clone(), target.port, &target.protocol,
                            credential.username.clone(), credential.password.clone(),
                            false, Duration::ZERO,
                            Some(format!(
                                "Cooling down user '{}' until {:?} (lockout signal)",
                                credential.username, until
                            )),
                        ),
                    ).await;
                    return;
                } else {
                    user_cooldowns.remove(&credential.username);
                }
            }
            // F4.3: hormati cooldown target (rate-limit) dengan tidur bounded.
            if let Some(until) = target_cooldowns.get(&target_key).map(|r| *r) {
                let now = Instant::now();
                if now < until {
                    let sleep_for = (until - now).min(rate_cooldown.max(Duration::from_secs(1)));
                    log::warn!(
                        "Target {} cooling down {:.0}s (rate-limit signal)",
                        target_key,
                        sleep_for.as_secs_f64()
                    );
                    tokio::time::sleep(sleep_for).await;
                }
                target_cooldowns.remove(&target_key);
            }
            if skipped.contains(&credential.username) {
                let _ = send_result(&external_tx,
                    AuthResult::new(
                        target.host.clone(), target.port, &target.protocol,
                        credential.username.clone(), credential.password.clone(),
                        false, Duration::ZERO,
                        Some("Skipped (account locked)".into()),
                    ),
                ).await;
                return;
            }

            let handler = match get_protocol(&target.protocol) {
                Some(h) => h,
                None => {
                    let _ = send_result(&external_tx,
                        AuthResult::new(
                            target.host.clone(), target.port, &target.protocol,
                            credential.username.clone(), credential.password.clone(),
                            false, Duration::ZERO,
                            Some(format!("Unsupported protocol: {}", target.protocol)),
                        ),
                    ).await;
                    return;
                }
            };

            let mut last_result = None;
            let proxy_count = proxies.len();
            // ANON A3: lewati proxy yang sedang di-ban (ban kedaluwarsa = hidup lagi).
            let is_banned = |idx: usize| -> bool {
                proxy_banned_until
                    .get(&idx)
                    .map(|r| *r > Instant::now())
                    .unwrap_or(false)
            };
            let skip_banned = |mut idx: usize| -> usize {
                if proxy_count == 0 {
                    return idx;
                }
                for _ in 0..proxy_count {
                    if !is_banned(idx) {
                        return idx;
                    }
                    idx = (idx + 1) % proxy_count;
                }
                idx
            };
            // ANON: slot awal dari counter global. Tanpa jadwal: semua task mulai
            // dari proxy[0]. Dengan --rotate-proxy-every N: tiap N task global
            // pindah ke proxy berikutnya, egress tersebar merata dan periodik.
            let mut proxy_idx: usize = if rotation_every > 0 && proxy_count > 0 {
                let slot = rotation_counter.fetch_add(1, Ordering::Relaxed) as usize;
                skip_banned((slot / rotation_every) % proxy_count)
            } else {
                skip_banned(0)
            };
            let mut current_proxy = if proxy_count == 0 {
                None
            } else {
                Some(proxies[proxy_idx].clone())
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

                // ANON A3: health runtime. Gagal koneksi/Timeout beruntun pada
                // proxy yang sama = jalur mati → strike; 5 strike = ban 60 dtk.
                // Sukses me-reset strike (jalur terbukti hidup).
                if proxy_count > 0 {
                    use crate::utils::patterns::ResponseCategory as RC;
                    match (&classified.category, result.success) {
                        (_, true) => {
                            proxy_strikes[proxy_idx].store(0, Ordering::Relaxed);
                        }
                        (RC::ConnectionError | RC::Timeout, false) => {
                            let n = proxy_strikes[proxy_idx].fetch_add(1, Ordering::Relaxed) + 1;
                            if n >= MAX_PROXY_STRIKES {
                                proxy_banned_until.insert(
                                    proxy_idx,
                                    Instant::now() + Duration::from_secs(PROXY_BAN_SECS),
                                );
                                proxy_strikes[proxy_idx].store(0, Ordering::Relaxed);
                                log::warn!(
                                    "proxy[{}] banned {}s after {} consecutive connection failures",
                                    proxy_idx,
                                    PROXY_BAN_SECS,
                                    MAX_PROXY_STRIKES
                                );
                                proxy_idx = skip_banned((proxy_idx + 1) % proxy_count);
                                current_proxy = Some(proxies[proxy_idx].clone());
                            }
                        }
                        _ => {}
                    }
                }

                if result.success {
                    // F3.5 fp-check: verifikasi ulang sekali untuk eliminasi false positive.
                    if fp_check {
                        let verify = {
                            let _permit = semaphore.acquire().await.unwrap();
                            handler
                                .authenticate(&*target, &*credential, timeout, &current_proxy)
                                .await
                        };
                        if !verify.success {
                            log::warn!(
                                "fp-check rejected {}:{} {} (first success not reproducible)",
                                target.host, target.port, credential.username
                            );
                            last_result = Some(AuthResult {
                                error: Some("Rejected by fp-check re-verify".into()),
                                ..result
                            });
                            break;
                        }
                    }
                    last_result = Some(result);
                    break;
                }

                if crate::utils::patterns::should_skip_user(&classified) {
                    // F4.3: catat cooldown, lalu skip atau pause sesuai mode.
                    if !lockout_cooldown.is_zero() {
                        user_cooldowns.insert(
                            credential.username.clone(),
                            Instant::now() + lockout_cooldown,
                        );
                    }
                    if lockout_pause && !lockout_cooldown.is_zero() {
                        log::warn!(
                            "User '{}' locked, pausing {:.0}s (lockout-pause mode)",
                            credential.username,
                            lockout_cooldown.as_secs_f64()
                        );
                        tokio::time::sleep(lockout_cooldown).await;
                        user_cooldowns.remove(&credential.username);
                        continue;
                    }
                    skipped.insert(credential.username.clone());
                    let _ = send_result(&external_tx,
                        AuthResult {
                            error: Some(format!("Account locked: {}", classified.message)),
                            ..result
                        },
                    ).await;
                    return;
                }

                if !classified._retryable {
                    last_result = Some(result);
                    break;
                }

                if crate::utils::patterns::should_rotate_proxy(&classified) && proxy_count > 0 {
                    proxy_idx = skip_banned((proxy_idx + 1) % proxy_count);
                    current_proxy = Some(proxies[proxy_idx].clone());
                    for f in proxy_fails.iter() {
                        f.fetch_add(1, Ordering::Relaxed);
                    }
                }

                // F4.3: sinyal rate-limit memicu cooldown target bounded.
                if classified.category == crate::utils::patterns::ResponseCategory::RateLimited
                    && !rate_cooldown.is_zero()
                {
                    target_cooldowns.insert(target_key.clone(), Instant::now() + rate_cooldown);
                    log::warn!(
                        "Rate-limited on {}, cooling down {:.0}s",
                        target_key,
                        rate_cooldown.as_secs_f64()
                    );
                    tokio::time::sleep(rate_cooldown).await;
                    target_cooldowns.remove(&target_key);
                }

                if attempt == retries {
                    last_result = Some(result);
                    break;
                }

                tokio::time::sleep(crate::utils::patterns::compute_backoff(attempt)).await;
            }

            match last_result {
                Some(r) => { let _ = send_result(&external_tx, r).await; }
                None => {
                    let _ = send_result(&external_tx,
                        AuthResult::new(
                            target.host.clone(), target.port, &target.protocol,
                            credential.username.clone(), credential.password.clone(),
                            false, Duration::ZERO,
                            Some("Cancelled".into()),
                        ),
                    ).await;
                }
            }
        });
    }

    pub fn submitted_count(&self) -> u64 {
        self.total_submitted.load(Ordering::Relaxed)
    }

    /// Jumlah task yang masih berjalan di JoinSet. Dipakai untuk observability adaptif.
    pub fn inflight(&self) -> usize {
        self.tasks.len()
    }

    pub fn skipped_count(&self) -> usize {
        self.skipped_users.len()
    }

    pub fn user_cooldown_count(&self) -> usize {
        self.user_cooldowns.len()
    }

    pub fn target_cooldown_count(&self) -> usize {
        self.target_cooldowns.len()
    }

    pub fn proxy_failure_counts(&self) -> Vec<u64> {
        self.proxy_failures.iter().map(|c| c.load(Ordering::Relaxed)).collect()
    }

    pub async fn wait_complete(&mut self) {
        while self.tasks.join_next().await.is_some() {}
    }

    pub fn shutdown(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        self.tasks.abort_all();
        while self.tasks.try_join_next().is_some() {}
    }

    pub fn is_idle(&self) -> bool {
        self.tasks.is_empty()
    }
}

async fn send_result(tx: &Option<mpsc::UnboundedSender<AuthResult>>, result: AuthResult) {
    if let Some(ref t) = tx {
        let _ = t.send(result);
    }
}
