use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use chrono::Utc;
use futures::future::join_all;
use tokio::sync::Semaphore;

use super::cidr::expand_targets;
use super::config::AttackConfig;
use super::credential::Credential;
use super::error::AttackError;
use super::result::{AttackSummary, AuthResult};
use super::rules::{apply_rules, load_rules};
use super::target::{parse_targets, Target};
use super::wordlist::{load_combo_list, load_wordlist};
use super::worker::{WorkerPool, WorkerTask};
use crate::proxy::{load_proxy_list, ProxyConfig};
use crate::utils::output::OutputHandler;
use crate::utils::patterns::{classify_error, ResponseCategory};
use crate::utils::ratelimit::{JitterDelay, RateLimiter};
use crate::utils::report::save_html_report;
use crate::protocols::{http, rdp};
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
    running: Arc<AtomicBool>,
}

impl AttackOrchestrator {
    pub async fn new(config: AttackConfig, running: Arc<AtomicBool>) -> Result<Self, AttackError> {
        config.validate()?;

        let output = OutputHandler::new(
            config.output_format.clone(),
            config.output_file.as_deref(),
            config.verbose as u8,
        )?;

        if let Some(ref domain) = config.rdp_domain {
            rdp::set_domain(domain);
        }
        if let Some(ref v) = config.http_userfield {
            http::set_form_userfield(v);
        }
        if let Some(ref v) = config.http_passfield {
            http::set_form_passfield(v);
        }
        if let Some(ref v) = config.http_success {
            http::set_form_success(v);
        }

        Ok(AttackOrchestrator {
            targets: Vec::new(),
            credentials: Vec::new(),
            proxies: Vec::new(),
            results: Vec::new(),
            session: None,
            output,
            rate_limiter: RateLimiter::new(config.rate_limit),
            jitter: JitterDelay::new(config.delay, 100),
            config,
            running,
        })
    }

    pub async fn load_targets_for_distributed(config: &AttackConfig) -> Result<Vec<Target>, AttackError> {
        let dns_semaphore = Arc::new(Semaphore::new(50));
        Self::resolve_targets(config, dns_semaphore).await
    }

    pub async fn load_credentials_for_distributed(config: &AttackConfig) -> Result<Vec<Credential>, AttackError> {
        Self::load_credentials(config).await
    }

    async fn load_targets(config: &AttackConfig) -> Result<Vec<Target>, AttackError> {
        let dns_semaphore = Arc::new(Semaphore::new(50));
        Self::resolve_targets(config, dns_semaphore).await
    }

    async fn resolve_targets(config: &AttackConfig, dns_semaphore: Arc<Semaphore>) -> Result<Vec<Target>, AttackError> {
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
            crate::protocols::default_ports_for_protocols(&protocols)
        } else {
            config.ports.clone()
        };

        let mut targets = parse_targets(&target_strings, &protocols, &ports);

        let before = targets.len();
        let mut seen = HashSet::new();
        targets.retain(|t| seen.insert((t.host.clone(), t.port, t.protocol.clone())));
        if targets.len() < before {
            log::info!("Removed {} duplicate targets", before - targets.len());
        }

        let resolve_futures: Vec<_> = targets.iter_mut().map(|t| {
            let timeout = config.timeout;
            let permit = Arc::clone(&dns_semaphore);
            async move {
                let _guard = permit.acquire().await;
                if !t.is_resolved() {
                    let _ = t.resolve(timeout).await;
                }
            }
        }).collect();
        join_all(resolve_futures).await;

        targets.retain(|t| t.is_resolved());
        if targets.is_empty() {
            return Err(AttackError::config("No valid targets after DNS resolution"));
        }

        log::info!("Loaded {} targets ({} after expansion+dns)", config.targets.len(), targets.len());
        Ok(targets)
    }

    async fn load_credentials(config: &AttackConfig) -> Result<Vec<Credential>, AttackError> {
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
            return Err(AttackError::config("No users provided"));
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
            return Err(AttackError::config("No passwords provided"));
        };

        if users.is_empty() || passwords.is_empty() {
            return Err(AttackError::config("Empty user or password list"));
        }

        credentials = build_credentials(config, &users, &passwords);
        log::info!("Loaded {} credentials ({} users × {} passwords",
            credentials.len(), users.len(), passwords.len(),
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
        if let Some(ref chain) = config.proxy_chain {
            let chain_proxies: Vec<ProxyConfig> = chain.split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .filter_map(|s| ProxyConfig::parse(s).ok())
                .collect();
            if chain_proxies.len() > 1 {
                proxies.push(ProxyConfig::Chain { proxies: chain_proxies });
            } else if let Some(p) = chain_proxies.into_iter().next() {
                proxies.push(p);
            }
        }
        proxies
    }

    pub async fn run(&mut self) -> AttackSummary {
        let protocol_name = self.config.protocols.first().map(|s| s.as_str()).unwrap_or("unknown");
        let start_time = Utc::now();

        let targets = match Self::load_targets(&self.config).await {
            Ok(mut t) => {
                // Health check: parallel TCP probe to filter unreachable targets
                let before = t.len();
                if before > 10 {
                    let sem = Arc::new(Semaphore::new(50));
                    let mut handles = Vec::with_capacity(before);
                    for target in t {
                        let permit = Arc::clone(&sem);
                        let addr = target.addr_string();
                        let timeout_dur = std::time::Duration::from_secs(3);
                        handles.push(async move {
                            let _guard = permit.acquire().await;
                            match tokio::time::timeout(timeout_dur, tokio::net::TcpStream::connect(&addr)).await {
                                Ok(Ok(stream)) => {
                                    drop(stream);
                                    Some(target)
                                }
                                _ => None,
                            }
                        });
                    }
                    t = futures::future::join_all(handles).await.into_iter().filter_map(|x| x).collect();
                    let dead = before - t.len();
                    if dead > 0 {
                        log::info!("Health check: {} targets alive, {} unreachable (skipped)", t.len(), dead);
                    }
                }
                t
            }
            Err(e) => {
                log::error!("Failed to load targets: {}", e);
                return AttackSummary {
                    start_time,
                    end_time: Some(Utc::now()),
                    total_targets: 0,
                    total_credentials: 0,
                    attempts: 0,
                    successes: 0,
                    failures: 0,
                    errors: 0,
                    results: vec![],
                    total_duration: Some(std::time::Duration::ZERO),
                };
            }
        };
        self.targets = targets;

        let credentials = match Self::load_credentials(&self.config).await {
            Ok(c) => c,
            Err(e) => {
                log::error!("Failed to load credentials: {}", e);
                return AttackSummary {
                    start_time,
                    end_time: Some(Utc::now()),
                    total_targets: self.targets.len(),
                    total_credentials: 0,
                    attempts: 0,
                    successes: 0,
                    failures: 0,
                    errors: 0,
                    results: vec![],
                    total_duration: Some(std::time::Duration::ZERO),
                };
            }
        };
        self.credentials = credentials;
        self.proxies = Self::load_proxies(&self.config);

        // Deduplicate credentials
        let before = self.credentials.len();
        if before > 0 {
            let mut seen = std::collections::HashSet::new();
            self.credentials.retain(|c| seen.insert((c.username.clone(), c.password.clone())));
            let removed = before - self.credentials.len();
            if removed > 0 {
                log::info!("Removed {} duplicate credentials", removed);
            }
        }

        if let Some(resume_path) = &self.config.resume_file {
            match SessionState::load(resume_path) {
                Ok(state) => self.session = Some(state),
                Err(e) => log::warn!("Cannot load resume file (starting fresh): {}", e),
            }
        }

        let total_combinations = self.targets.len() * self.credentials.len();
        log::info!("Starting attack: {} targets × {} credentials ({} total attempts)",
            self.targets.len(), self.credentials.len(), total_combinations);

        self.output.init_dashboard(
            protocol_name,
            self.targets.len(),
            self.credentials.len(),
        );

        self.output.set_status(format!("Brute-forcing {} targets × {} credentials ({} total)",
            self.targets.len(), self.credentials.len(), total_combinations));

        let mut pool = WorkerPool::new(&self.config, Arc::clone(&self.running), self.proxies.clone());
        let mut attempt_count = 0u64;
        let mut successes_global = 0u64;
        let mut failures_global = 0u64;
        let mut errors_global = 0u64;
        let mut lockout_events = 0u64;
        let mut rate_limit_events = 0u64;

        let target_count = self.targets.len();
        let cred_count = self.credentials.len();

        'submit_loop: for target_idx in 0..target_count {
            let target = &self.targets[target_idx];
            for cred_idx in 0..cred_count {
                if !self.running.load(Ordering::SeqCst) {
                    log::info!("Graceful shutdown requested. Stopping at attempt {}.", attempt_count);
                    break 'submit_loop;
                }

                let credential = &self.credentials[cred_idx];

                if let Some(ref session) = self.session {
                    if session.is_tested(&credential.username, &credential.password) {
                        attempt_count += 1;
                        self.output.inc_progress();
                        continue;
                    }
                }

                self.rate_limiter.wait_if_needed().await;
                self.jitter.delay().await;

                pool.submit(WorkerTask {
                    target: Arc::new(target.clone()),
                    credential: Arc::new(credential.clone()),
                    attempt_index: attempt_count,
                });

                self.output.inc_progress();
                attempt_count += 1;

                if self.config.verbose > 0 {
                    self.output.set_status(format!("{}:{} -> {}:{}",
                        target.host, target.port,
                        credential.username, credential.password,
                    ));
                }

                while let Some((result, _stop_early)) = pool.try_recv_result() {
                    let classified = classify_error(result.error.as_deref(), result.success);

                    match classified.category {
                        ResponseCategory::AccountLocked => {
                            lockout_events += 1;
                        }
                        ResponseCategory::RateLimited => {
                            rate_limit_events += 1;
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
                        let prev_count = session.total_attempts;
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
                            let interval = self.config.checkpoint_interval as u64;
                            if session.total_attempts / interval > prev_count / interval {
                                if let Some(ref resume_path) = self.config.resume_file {
                                    let _ = session.save(resume_path);
                                }
                            }
                        }
                    }

                    self.output.on_result(&result);
                    self.results.push(result);
                }
            }
        }

        pool.wait_complete().await;

        while let Some((result, _stop_early)) = pool.try_recv_result() {
            let classified = classify_error(result.error.as_deref(), result.success);

            match classified.category {
                ResponseCategory::AccountLocked => lockout_events += 1,
                ResponseCategory::RateLimited => rate_limit_events += 1,
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
                    session.add_success(&result.target_host, &result.protocol, &result.username, &result.password);
                }
                if let Some(ref resume_path) = self.config.resume_file {
                    let _ = session.save(resume_path);
                }
            }

            self.output.on_result(&result);
            self.results.push(result);
        }

        if let Some(ref session) = self.session {
            if let Some(ref resume_path) = self.config.resume_file {
                let _ = session.save(resume_path);
            }
        }

        if lockout_events > 0 {
            log::warn!("Detected {} account lockout(s)", lockout_events);
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

        self.output.finish(&summary);

        if matches!(self.config.output_format, crate::core::config::OutputFormat::Html) {
            if let Some(ref output_path) = self.config.output_file {
                let html_path = if output_path.extension().map_or(true, |e| e != "html") {
                    output_path.with_extension("html")
                } else {
                    output_path.clone()
                };
                if let Err(e) = save_html_report(&html_path, &summary) {
                    log::error!("Failed to save HTML report: {}", e);
                } else {
                    log::info!("HTML report saved to {}", html_path.display());
                }
            }
        }

        summary
    }
}

fn build_credentials(config: &AttackConfig, users: &[String], passwords: &[String]) -> Vec<Credential> {
    let mut credentials = Vec::with_capacity(users.len() * passwords.len());
    let max_len = config.max_password_len.unwrap_or(usize::MAX);

    if config.spray_mode {
        for pass in passwords {
            for user in users {
                credentials.push(Credential::new(user.clone(), truncate_password(pass, max_len)));
            }
        }
    } else if config.single_user_mode {
        if let Some(user) = users.first() {
            for pass in passwords {
                credentials.push(Credential::new(user.clone(), truncate_password(pass, max_len)));
            }
        }
    } else {
        for user in users {
            for pass in passwords {
                credentials.push(Credential::new(user.clone(), truncate_password(pass, max_len)));
            }
        }
    }
    credentials
}

fn truncate_password(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        s.chars().take(max_len).collect()
    } else {
        s.to_string()
    }
}
