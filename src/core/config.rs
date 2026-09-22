use std::path::PathBuf;
use std::time::Duration;

use super::error::AttackError;

#[derive(Clone, Debug)]
pub enum DistributedMode {
    Coordinator { bind: String },
    Worker { connect: String },
}

#[derive(Clone, Debug)]
pub struct AttackConfig {
    pub targets: Vec<String>,
    pub target_file: Option<PathBuf>,
    pub users: Vec<String>,
    pub passwords: Vec<String>,
    pub user_file: Option<PathBuf>,
    pub password_file: Option<PathBuf>,
    pub combo_file: Option<PathBuf>,
    pub protocols: Vec<String>,
    pub ports: Vec<u16>,
    pub threads: usize,
    pub timeout: Duration,
    pub delay: Duration,
    pub rate_limit: Option<u64>,
    pub proxy: Option<String>,
    pub proxy_file: Option<PathBuf>,
    pub proxy_chain: Option<String>,
    pub output_file: Option<PathBuf>,
    pub output_format: OutputFormat,
    pub resume_file: Option<PathBuf>,
    #[allow(dead_code)]
    pub config_file: Option<PathBuf>,
    pub checkpoint_interval: u64,
    pub verbose: u8,
    pub quiet: bool,
    pub no_banner: bool,
    pub single_user_mode: bool,
    pub rdp_domain: Option<String>,
    pub http_userfield: Option<String>,
    pub http_passfield: Option<String>,
    pub http_success: Option<String>,
    pub spray_mode: bool,
    pub stop_on_first: bool,
    pub retries: u32,
    pub rule_file: Option<PathBuf>,
    pub max_mutations: usize,
    pub max_password_len: Option<usize>,
    // Distributed mode
    pub distributed: Option<DistributedMode>,
    pub distributed_token: Option<String>,
    pub distributed_name: Option<String>,
    // Plugin system
    pub plugins: Vec<String>,
    // REST API
    pub api_bind: Option<String>,
    // Encrypted output
    pub encrypt: bool,
    pub encrypt_passphrase: Option<String>,
    pub decrypt_file: Option<std::path::PathBuf>,
    pub decrypt_output: Option<std::path::PathBuf>,
    // Fase 1: dry-run preview tanpa network I/O
    pub dry_run: bool,
    // Fase 2+3: fingerprint re-verify untuk eliminasi false positive
    pub fp_check: bool,
    // Fase 4: stealth, spray cadence, limiter 3 level, cooldown
    pub spray_interval: Duration,
    pub spray_jitter_pct: u8,
    pub target_rate_limit: Option<u64>,
    pub user_cooldown: Duration,
    pub lockout_cooldown: Duration,
    pub rate_cooldown: Duration,
    pub lockout_pause: bool,
    pub user_agent: Option<String>,
    pub safe_profile: bool,
    pub aggressive_lab: bool,
    pub i_understand_risk: bool,
    // Fase 5: batasi attack ke hasil scan terakhir
    pub only_open: Option<PathBuf>,
    // Fase 6: tampilkan password penuh (default masked)
    pub show_secrets: bool,
    // ANON: fail-closed proxy, rotasi terjadwal, egress source IP.
    pub proxy_required: bool,
    pub rotate_proxy_every: usize,
    pub source_ip: Option<std::net::IpAddr>,
    // ANON A2: jitter acak 0..=N ms di atas --delay (anti-fingerprinting ritme).
    pub delay_jitter_ms: u64,
    // ANON A3: pre-flight check proxy (fail-closed bila semua mati).
    pub check_proxy: bool,
}

#[derive(Clone, Debug)]
pub enum OutputFormat {
    Json,
    Csv,
    Plain,
    Html,
    Yaml,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "json" => OutputFormat::Json,
            "csv" => OutputFormat::Csv,
            "html" => OutputFormat::Html,
            "yaml" | "yml" => OutputFormat::Yaml,
            _ => OutputFormat::Plain,
        }
    }
}

impl AttackConfig {
    pub fn validate(&self) -> Result<(), AttackError> {
        if let Some(ref mode) = self.distributed {
            match mode {
                DistributedMode::Coordinator { .. } => {
                    if self.targets.is_empty() && self.target_file.is_none() {
                        return Err(AttackError::config(
                            "Coordinator requires targets. Use --target or --target-file.",
                        ));
                    }
                    if self.protocols.is_empty() {
                        return Err(AttackError::config(
                            "Coordinator requires protocols. Use --protocol.",
                        ));
                    }
                    if self.combo_file.is_none() && self.users.is_empty() && self.user_file.is_none() {
                        return Err(AttackError::config(
                            "Coordinator requires users. Use --user, --user-file, or --combo.",
                        ));
                    }
                    if self.combo_file.is_none() && self.passwords.is_empty() && self.password_file.is_none() {
                        return Err(AttackError::config(
                            "Coordinator requires passwords. Use --password, --password-file, or --combo.",
                        ));
                    }
                    if self.distributed_token.is_none() {
                        return Err(AttackError::config(
                            "Coordinator requires --distributed-token for worker authentication.",
                        ));
                    }
                }
                DistributedMode::Worker { .. } => {
                    if self.distributed_token.is_none() {
                        return Err(AttackError::config(
                            "Worker requires --distributed-token for authentication.",
                        ));
                    }
                }
            }
            return Ok(());
        }

        if self.targets.is_empty() && self.target_file.is_none() {
            return Err(AttackError::config(
                "No targets specified. Use --target or --target-file.",
            ));
        }
        if self.protocols.is_empty() {
            return Err(AttackError::config(
                "No protocols specified. Use --protocol.",
            ));
        }
        if self.combo_file.is_none() {
            if self.users.is_empty() && self.user_file.is_none() {
                return Err(AttackError::config(
                    "No users specified. Use --user, --user-file, or --combo.",
                ));
            }
            if self.passwords.is_empty() && self.password_file.is_none() {
                return Err(AttackError::config(
                    "No passwords specified. Use --password, --password-file, or --combo.",
                ));
            }
        }
        if self.threads == 0 {
            return Err(AttackError::config("Thread count must be > 0"));
        }
        if self.max_mutations == 0 {
            return Err(AttackError::config("Max mutations must be > 0"));
        }
        if self.checkpoint_interval == 0 {
            return Err(AttackError::config("Checkpoint interval must be > 0"));
        }
        if self.spray_mode && self.single_user_mode {
            return Err(AttackError::config(
                "Cannot combine --spray and --single-user. Choose one credential order.",
            ));
        }
        if self.threads > 100 {
            return Err(AttackError::config(
                "Thread count above 100 is blocked for safety. Use max 100, or split via distributed mode.",
            ));
        }
        // F4.2/F4.5/F4.6
        if self.spray_jitter_pct > 100 {
            return Err(AttackError::config("--spray-jitter must be 0-100."));
        }
        if self.safe_profile && self.aggressive_lab {
            return Err(AttackError::config(
                "Cannot combine --safe-profile and --aggressive-lab.",
            ));
        }
        if self.aggressive_lab && !self.i_understand_risk {
            if self.target_file.is_some() {
                return Err(AttackError::config(
                    "--aggressive-lab with --list target file requires --i-understand-risk (targets cannot be verified as lab-local).",
                ));
            }
            let non_lab: Vec<_> = self
                .targets
                .iter()
                .filter(|t| !super::cidr::spec_is_lab(t))
                .collect();
            if !non_lab.is_empty() {
                return Err(AttackError::config(format!(
                    "--aggressive-lab blocked: non-lab target(s) {:?}. Use RFC1918/loopback targets or pass --i-understand-risk.",
                    non_lab
                )));
            }
        }
        // ANON: fail-closed bila operator menuntut proxy.
        if self.proxy_required
            && self.proxy.is_none()
            && self.proxy_file.is_none()
            && self.proxy_chain.is_none()
        {
            return Err(AttackError::config(
                "--proxy-required set but no proxy configured. Use --proxy, --proxy-file, or --proxy-chain.",
            ));
        }
        Ok(())
    }

    /// Peringatan non-fatal untuk pola berisiko lockout atau salah konfigurasi.
    /// Dipanggil setelah `validate()` lolos, ditampilkan sebelum attack jalan.
    pub fn risk_warnings(&self) -> Vec<String> {
        let mut w = Vec::new();
        if self.spray_mode && self.delay.as_millis() == 0 && self.rate_limit.is_none() {
            w.push("Spray mode without --delay or --rate-limit risks account lockout. Add --delay 1000 or --rate-limit 5 for production-like targets.".into());
        }
        if !self.spray_mode && self.threads >= 20 && self.delay.as_millis() == 0 {
            w.push(format!(
                "High threads ({}) with zero delay can trigger lockout or IDS. Consider --spray, --delay 200, or --rate-limit.",
                self.threads
            ));
        }
        if self.password_file.is_some() && self.users.is_empty() && self.user_file.is_none() {
            w.push("Password file set but no users provided. Add -u or -U, or use --single-user.".into());
        }
        if self.combo_file.is_some() && (!self.users.is_empty() || !self.passwords.is_empty()) {
            w.push("Combo file ignores -u/--password direct values for credential building. Remove combo or direct values to avoid confusion.".into());
        }
        if self.proxy_chain.is_some() && self.protocols.iter().any(|p| p == "http") {
            w.push("HTTP via proxy-chain currently uses the first proxy for reqwest. Chain is honored for raw TCP protocols; HTTP chain support is partial.".into());
        }
        if self.api_bind.is_some() {
            w.push("API bind is enabled without built-in auth/TLS. Bind to 127.0.0.1 or put behind authenticated reverse proxy.".into());
        }
        if self.timeout.as_secs() < 3 {
            w.push("Timeout below 3s can cause false negatives on slow networks. Use 5-10s unless lab is local.".into());
        }
        // F4.x tambahan
        if !self.spray_interval.is_zero() && !self.spray_mode {
            w.push("--spray-interval is set but --spray is off; interval only applies between spray rounds.".into());
        }
        if self.lockout_pause && self.lockout_cooldown.is_zero() {
            w.push("--lockout-pause has no effect with zero --lockout-cooldown.".into());
        }
        if self.aggressive_lab {
            w.push("Aggressive lab profile: high threads, low timeout. Only for isolated lab networks you own.".into());
        }
        if self.safe_profile {
            w.push("Safe profile active: conservative threads/delay/rate for production-like targets.".into());
        }
        w
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_config() -> AttackConfig {
        AttackConfig {
            targets: vec!["10.0.0.1".into()],
            target_file: None,
            users: vec!["admin".into()],
            passwords: vec!["pass".into()],
            user_file: None,
            password_file: None,
            combo_file: None,
            protocols: vec!["ssh".into()],
            ports: vec![22],
            threads: 10,
            timeout: Duration::from_secs(5),
            delay: Duration::ZERO,
            rate_limit: None,
            proxy: None,
            proxy_file: None,
            proxy_chain: None,
            output_file: None,
            output_format: OutputFormat::Plain,
            resume_file: None,
            config_file: None,
            checkpoint_interval: 100,
            verbose: 0,
            quiet: false,
            no_banner: false,
            single_user_mode: false,
            rdp_domain: None,
            http_userfield: None,
            http_passfield: None,
            http_success: None,
            spray_mode: false,
            stop_on_first: false,
            retries: 1,
            rule_file: None,
            max_mutations: 500,
            max_password_len: None,
            distributed: None,
            distributed_token: None,
            distributed_name: None,
            plugins: vec![],
            api_bind: None,
            encrypt: false,
            encrypt_passphrase: None,
            decrypt_file: None,
            decrypt_output: None,
            dry_run: false,
            fp_check: false,
            spray_interval: Duration::ZERO,
            spray_jitter_pct: 20,
            target_rate_limit: None,
            user_cooldown: Duration::ZERO,
            lockout_cooldown: Duration::from_secs(600),
            rate_cooldown: Duration::from_secs(60),
            lockout_pause: false,
            user_agent: None,
            safe_profile: false,
            aggressive_lab: false,
            i_understand_risk: false,
            only_open: None,
            proxy_required: false,
            rotate_proxy_every: 0,
            source_ip: None,
            delay_jitter_ms: 100,
            check_proxy: false,
            show_secrets: false,
        }
    }

    #[test]
    fn test_validate_ok() {
        let cfg = make_config();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_validate_no_targets() {
        let mut cfg = make_config();
        cfg.targets.clear();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_no_protocols() {
        let mut cfg = make_config();
        cfg.protocols.clear();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_no_users() {
        let mut cfg = make_config();
        cfg.users.clear();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_no_passwords() {
        let mut cfg = make_config();
        cfg.passwords.clear();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_zero_threads() {
        let mut cfg = make_config();
        cfg.threads = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_output_format_from_str() {
        assert!(matches!(OutputFormat::from_str("json"), OutputFormat::Json));
        assert!(matches!(OutputFormat::from_str("csv"), OutputFormat::Csv));
        assert!(matches!(OutputFormat::from_str("html"), OutputFormat::Html));
        assert!(matches!(OutputFormat::from_str("plain"), OutputFormat::Plain));
        assert!(matches!(OutputFormat::from_str("unknown"), OutputFormat::Plain));
        assert!(matches!(OutputFormat::from_str("JSON"), OutputFormat::Json));
    }

    #[test]
    fn test_with_combo_file_skips_user_pass_check() {
        let mut cfg = make_config();
        cfg.users.clear();
        cfg.passwords.clear();
        cfg.combo_file = Some(PathBuf::from("combos.txt"));
        assert!(cfg.validate().is_ok());
    }
}
