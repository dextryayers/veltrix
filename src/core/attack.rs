use crate::utils::fx_map::DedupSet;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use chrono::Utc;
use colored::Colorize;
use futures::future::join_all;
use tokio::sync::{Semaphore, mpsc};

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
        let mut seen: DedupSet<(String, u16, String)> = DedupSet::with_capacity(targets.len());
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
            let combo_count = combos.len();
            for (user, pass) in combos {
                credentials.push(Credential::new(user, pass));
            }
            println!("  {} {} {}",
                "Combo file:".bold().cyan(),
                combo_count.to_string().white(),
                "user:pass pairs loaded".dimmed(),
            );
            return Ok(credentials);
        }

        let mut users: Vec<String> = Vec::new();
        let mut user_sources = Vec::new();
        if !config.users.is_empty() {
            let count = config.users.len();
            users.extend(config.users.clone());
            user_sources.push(format!("{} individual", count));
        }
        if let Some(user_path) = &config.user_file {
            let file_users = load_wordlist(user_path).await?;
            let count = file_users.len();
            users.extend(file_users);
            user_sources.push(format!("{} from {:?}", count, user_path));
        }
        if users.is_empty() {
            return Err(AttackError::config("No users provided"));
        }

        let mut passwords: Vec<String> = Vec::new();
        let mut pass_sources = Vec::new();
        if !config.passwords.is_empty() {
            let count = config.passwords.len();
            passwords.extend(config.passwords.clone());
            pass_sources.push(format!("{} individual", count));
        }
        if let Some(pass_path) = &config.password_file {
            let base_passwords = load_wordlist(pass_path).await?;
            let base_count = base_passwords.len();
            let expanded = if let Some(rule_path) = &config.rule_file {
                if Path::new(rule_path).exists() {
                    match load_rules(rule_path) {
                        Ok(rules) => {
                            log::info!("Loaded {} mutation rules from {:?}", rules.len(), rule_path);
                            let mutated = apply_rules(&base_passwords, &rules, config.max_mutations);
                            log::info!("Expanded {} passwords to {} via rules", base_count, mutated.len());
                            pass_sources.push(format!("{} raw → {} mutated from {:?}", base_count, mutated.len(), pass_path));
                            mutated
                        }
                        Err(e) => {
                            log::warn!("Failed to load rules: {}. Using base passwords.", e);
                            pass_sources.push(format!("{} from {:?} (rules failed)", base_count, pass_path));
                            base_passwords
                        }
                    }
                } else {
                    pass_sources.push(format!("{} from {:?}", base_count, pass_path));
                    base_passwords
                }
            } else {
                pass_sources.push(format!("{} from {:?}", base_count, pass_path));
                base_passwords
            };
            passwords.extend(expanded);
        }
        if passwords.is_empty() {
            return Err(AttackError::config("No passwords provided"));
        }

        credentials = build_credentials(config, &users, &passwords);
        let total = users.len() * passwords.len();
        println!();
        println!("  {} {} {}",
            "Users:".bold().cyan(),
            users.len().to_string().white().bold(),
            format!("({})", user_sources.join(" + ")).dimmed(),
        );
        println!("  {} {} {}",
            "Passwords:".bold().cyan(),
            passwords.len().to_string().white().bold(),
            format!("({})", pass_sources.join(" + ")).dimmed(),
        );
        println!("  {} {} {}",
            "Combinations:".bold().green(),
            credentials.len().to_string().white().bold(),
            format!("({} users × {} passwords)", users.len(), passwords.len()).yellow(),
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
                let before = t.len();
                if before > 10 {
                    let sem = Arc::new(Semaphore::new(50));
                    let mut handles = Vec::with_capacity(before);
                    for target in t {
                        let permit = Arc::clone(&sem);
                        let addr = target.cached_addr.clone();
                        let timeout_dur = std::time::Duration::from_secs(3);
                        handles.push(async move {
                            let _guard = permit.acquire().await;
                            match tokio::time::timeout(timeout_dur, tokio::net::TcpStream::connect(&addr)).await {
                                Ok(Ok(stream)) => { drop(stream); Some(target) }
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
                return empty_summary(start_time);
            }
        };
        self.targets = targets;

        let credentials = match Self::load_credentials(&self.config).await {
            Ok(c) => c,
            Err(e) => {
                log::error!("Failed to load credentials: {}", e);
                return empty_summary(start_time);
            }
        };
        self.credentials = credentials;
        self.proxies = Self::load_proxies(&self.config);

        let cred_before_dedup = self.credentials.len();
        let mut seen: DedupSet<(String, String)> = DedupSet::with_capacity(self.credentials.len());
        self.credentials.retain(|c| seen.insert((c.username.clone(), c.password.clone())));
        let dedup_removed = cred_before_dedup - self.credentials.len();
        if dedup_removed > 0 {
            log::info!("Removed {} duplicate credential pairs", dedup_removed);
        }

        if let Some(resume_path) = &self.config.resume_file {
            match SessionState::load(resume_path) {
                Ok(state) => self.session = Some(state),
                Err(e) => log::warn!("Cannot load resume file (starting fresh): {}", e),
            }
        }

        let total_combinations = self.targets.len() * self.credentials.len();
        log::info!("Starting attack: {} targets × {} credentials = {} total combinations",
            self.targets.len(), self.credentials.len(), total_combinations);

        println!();
        println!("  {} {} {} {} {} {}",
            "Targets:".bold().cyan(),
            self.targets.len().to_string().white(),
            "×".dimmed(),
            "Credentials:".bold().cyan(),
            self.credentials.len().to_string().white(),
            format!("= {} total attempts", total_combinations).yellow().bold(),
        );
        println!();

        self.output.init_dashboard(
            protocol_name,
            self.targets.len(),
            self.credentials.len(),
        );

        self.output.set_status(format!("Brute-forcing {} targets × {} credentials ({} total)",
            self.targets.len(), self.credentials.len(), total_combinations));

        let mut pool = WorkerPool::new(&self.config, Arc::clone(&self.running), self.proxies.clone());
        let (result_tx, mut result_rx) = mpsc::unbounded_channel();

        let target_count = self.targets.len();
        let cred_count = self.credentials.len();
        let mut attempt_count = 0u64;
        let mut successes_global = 0u64;
        let mut failures_global = 0u64;
        let mut errors_global = 0u64;
        let mut last_prompted_count = 0u64;

        // ── Always-on anti-duplicate: track tested pairs in memory ──
        let mut tested_creds: DedupSet<(String, String)> = DedupSet::with_capacity(self.credentials.len());
        if let Some(ref session) = self.session {
            for c in &self.credentials {
                if session.is_tested(&c.username, &c.password) {
                    tested_creds.insert((c.username.clone(), c.password.clone()));
                }
            }
        }
        let mut first_success_found = false;
        let mut stop_early = false;

        fn ordinal(n: u64) -> String {
            match n {
                1 => "First".to_string(),
                2 => "Second".to_string(),
                3 => "Third".to_string(),
                4 => "Fourth".to_string(),
                5 => "Fifth".to_string(),
                6 => "Sixth".to_string(),
                7 => "Seventh".to_string(),
                8 => "Eighth".to_string(),
                9 => "Ninth".to_string(),
                10 => "Tenth".to_string(),
                _ => format!("#{}", n),
            }
        }

        fn drain_results(
            result_rx: &mut mpsc::UnboundedReceiver<(AuthResult, bool)>,
            output: &mut OutputHandler,
            results: &mut Vec<AuthResult>,
            session: &mut Option<SessionState>,
            successes_global: &mut u64,
            failures_global: &mut u64,
            errors_global: &mut u64,
        ) -> bool {
            let mut found_success = false;
            loop {
                match result_rx.try_recv() {
                    Ok((result, _stop_early)) => {
                        if result.success {
                            *successes_global += 1;
                            found_success = true;
                        } else if result.error.is_some() {
                            *errors_global += 1;
                        } else {
                            *failures_global += 1;
                        }

                        if let Some(ref mut s) = session {
                            s.mark_tested(&result.username, &result.password);
                            if result.success {
                                s.add_success(&result.target_host, &result.protocol, &result.username, &result.password);
                            }
                        }
                        output.on_result(&result);
                        results.push(result);
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                }
            }
            found_success
        }

        async fn prompt_continue(count: u64) -> bool {
            use std::io::Write;
            use tokio::io::AsyncBufReadExt;
            let ord = ordinal(count);
            println!();
            println!("  {}",
                "┌──────────────────────────────────────┐".bright_black(),
            );
            println!("  │  {} {}",
                format!("{} credential FOUND!", ord).green().bold(),
                format!("(total found: {})", count).white(),
            );
            println!("  │  {}",
                "Continue attacking? [y/N]: ".white().bold(),
            );
            print!("  │  {} ", ">>".green().bold());
            let _ = std::io::stdout().flush();
            let mut input = String::new();
            let mut reader = tokio::io::BufReader::new(tokio::io::stdin());
            reader.read_line(&mut input).await.ok();
            let input = input.trim().to_lowercase();
            input == "y" || input == "yes"
        }

        const BATCH: usize = 256;
        let mut batch_submitted = 0usize;
        let mut status_counter = 0usize;

        let arc_targets: Vec<Arc<Target>> = self.targets.iter().map(|t| Arc::new(t.clone())).collect();
        let arc_credentials: Vec<Arc<Credential>> = self.credentials.iter().map(|c| Arc::new(c.clone())).collect();

        'outer: for t_idx in 0..target_count {
            let target = &arc_targets[t_idx];
            for c_idx in 0..cred_count {
                if !self.running.load(Ordering::SeqCst) || stop_early {
                    break 'outer;
                }

                let credential = &arc_credentials[c_idx];
                // Always-on anti-duplicate
                if tested_creds.contains(&(credential.username.clone(), credential.password.clone())) {
                    attempt_count += 1;
                    self.output.inc_progress();
                    continue;
                }
                tested_creds.insert((credential.username.clone(), credential.password.clone()));

                self.rate_limiter.wait_if_needed().await;
                self.jitter.delay().await;

                if status_counter & 3 == 0 {
                    self.output.set_status(format!("{}:{} -> {}:{}",
                        target.host, target.port,
                        credential.username, credential.password));
                }
                status_counter += 1;

                pool.submit_with_sender(WorkerTask {
                    target: Arc::clone(target),
                    credential: Arc::clone(credential),
                }, result_tx.clone());

                attempt_count += 1;
                self.output.inc_progress();
                batch_submitted += 1;

                if batch_submitted >= BATCH {
                    drain_results(
                        &mut result_rx, &mut self.output, &mut self.results,
                        &mut self.session,
                        &mut successes_global, &mut failures_global,
                        &mut errors_global,
                    );
                    batch_submitted = 0;
                }
            }

            // Drain & prompt after each target's credentials
            if batch_submitted > 0 {
                drain_results(
                    &mut result_rx, &mut self.output, &mut self.results,
                    &mut self.session,
                    &mut successes_global, &mut failures_global,
                    &mut errors_global,
                );
                batch_submitted = 0;
            }

            if successes_global > last_prompted_count {
                last_prompted_count = successes_global;
                if self.config.stop_on_first {
                    stop_early = true;
                    log::info!("stop-on-first enabled, halting after first success");
                    break 'outer;
                }
                if !first_success_found {
                    first_success_found = true;
                }
                if !prompt_continue(successes_global).await {
                    stop_early = true;
                    log::info!("User requested stop after {} successes", successes_global);
                    break 'outer;
                }
            }
        }

        // Drain remaining results after submission
        drop(result_tx);
        pool.wait_complete().await;
        drain_results(
            &mut result_rx, &mut self.output, &mut self.results,
            &mut self.session,
            &mut successes_global, &mut failures_global,
            &mut errors_global,
        );

        if let Some(ref session) = self.session {
            if let Some(ref resume_path) = self.config.resume_file {
                let _ = session.save(resume_path);
            }
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

fn empty_summary(start_time: chrono::DateTime<Utc>) -> AttackSummary {
    AttackSummary {
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
    if s.len() > max_len { s.chars().take(max_len).collect() } else { s.to_string() }
}
