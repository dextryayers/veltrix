use std::path::PathBuf;
use std::time::Duration;
use clap::Parser;
use colored::Colorize;

use std::path::Path;
use crate::core::config::{AttackConfig, OutputFormat};
use crate::core::config_loader::ConfigFile;
use crate::core::error::AttackError;
use crate::utils::wordlist_gen::WordlistConfig;

#[derive(Parser, Debug)]
#[command(
    name = "veltrix",
    version = "1.0.0",
    author = "aniippxploit",
    about = "Multi-protocol brute force toolkit for security professionals",
    long_about = concat!(
        "Veltrix - Multi-Protocol Brute Force Toolkit\n",
        "=============================================\n\n",
        "A high-performance, multi-protocol brute force tool written in Rust.\n",
        "Supports SSH, FTP, Telnet, SMTP, POP3, RDP, MySQL, HTTP, and more.\n\n",
        "Examples:\n",
        "  veltrix -t 192.168.1.1 -P ssh -U users.txt -W passwords.txt\n",
        "  veltrix -T targets.txt -P ssh,ftp -U users.txt -W passes.txt -x 20\n",
        "  veltrix -t 10.0.0.5:3389 -P rdp -C combos.txt -o results.json -f json\n\n",
        "CIDR & Range:\n",
        "  veltrix -t 192.168.1.0/24 -P ssh -U users.txt -W passes.txt\n",
        "  veltrix -t 10.0.0.1-10.0.0.10 -P rdp -C combos.txt\n\n",
        "Hybrid Attack (Rules):\n",
        "  veltrix -t 10.0.0.1 -P ssh -U users.txt -W passes.txt --rules rules/common.rule\n\n",
        "⚠  WARNING: Only use on systems you own or have written permission to test."
    ),
    verbatim_doc_comment
)]
pub struct CliArgs {
    // ── Target Options ──
    #[arg(short = 't', long = "target", help = "Target host:port, CIDR, or range (repeatable)", value_name = "HOST[:PORT]")]
    pub targets: Vec<String>,

    #[arg(short = 'T', long = "target-file", help = "File containing list of targets (one per line)", value_name = "FILE")]
    pub target_file: Option<PathBuf>,

    #[arg(short = 'p', long = "port", help = "Port number(s) - defaults per protocol", value_name = "PORT")]
    pub ports: Vec<u16>,

    // ── Protocol Options ──
    #[arg(
        short = 'P',
        long = "protocol",
        help = "Protocol(s): ssh, ftp, telnet, smtp, pop3, rdp, mysql, postgres, ldap, redis, http",
        value_name = "PROTO",
        value_delimiter = ',',
        required_unless_present = "list_protocols"
    )]
    pub protocols: Vec<String>,

    #[arg(short = 'L', long = "list-protocols", help = "List supported protocols and exit")]
    pub list_protocols: bool,

    // ── Credential Options ──
    #[arg(short = 'u', long = "user", help = "Single username (repeatable)", value_name = "USER")]
    pub users: Vec<String>,

    #[arg(short = 'U', long = "user-file", help = "File with usernames (one per line)", value_name = "FILE")]
    pub user_file: Option<PathBuf>,

    #[arg(short = 'w', long = "password", help = "Single password (repeatable)", value_name = "PASS")]
    pub passwords: Vec<String>,

    #[arg(short = 'W', long = "password-file", help = "File with passwords (one per line)", value_name = "FILE")]
    pub password_file: Option<PathBuf>,

    #[arg(short = 'C', long = "combo", help = "Combo list: user:pass per line", value_name = "FILE")]
    pub combo_file: Option<PathBuf>,

    #[arg(long = "single-user", help = "Single user mode: use only the first user")]
    pub single_user: bool,

    #[arg(long = "spray", help = "Credential spraying: one password against all users (anti-lockout)")]
    pub spray: bool,

    // ── Hybrid Attack ──
    #[arg(long = "rules", help = "Rule file for password mutation (hybrid attack)", value_name = "FILE")]
    pub rules: Option<PathBuf>,

    #[arg(long = "max-mutations", help = "Max password mutations per base word", default_value = "500", value_name = "N")]
    pub max_mutations: usize,

    // ── Performance Options ──
    #[arg(short = 'x', long = "threads", help = "Concurrent workers", default_value = "10", value_name = "N")]
    pub threads: usize,

    #[arg(long = "timeout", help = "Connection timeout (seconds)", default_value = "10", value_name = "SEC")]
    pub timeout: u64,

    #[arg(long = "delay", help = "Delay between attempts (ms)", default_value = "0", value_name = "MS")]
    pub delay: u64,

    #[arg(long = "rate-limit", help = "Max attempts/sec (0=unlimited)", value_name = "N")]
    pub rate_limit: Option<u64>,

    #[arg(long = "retries", help = "Connection retries", default_value = "1", value_name = "N")]
    pub retries: u32,

    // ── RDP Options ──
    #[arg(long = "rdp-domain", help = "RDP domain (prepended to username)", value_name = "DOMAIN")]
    pub rdp_domain: Option<String>,

    // ── HTTP Form Options ──
    #[arg(long = "http-userfield", help = "HTTP form username field name", value_name = "FIELD")]
    pub http_userfield: Option<String>,
    #[arg(long = "http-passfield", help = "HTTP form password field name", value_name = "FIELD")]
    pub http_passfield: Option<String>,
    #[arg(long = "http-success", help = "HTTP form success indicator string", value_name = "TEXT")]
    pub http_success: Option<String>,

    #[arg(long = "max-password-len", help = "Truncate passwords to N characters", value_name = "N")]
    pub max_password_len: Option<usize>,

    // ── Proxy Options ──
    #[arg(long = "proxy", help = "Proxy: type://host[:port]", value_name = "PROXY")]
    pub proxy: Option<String>,

    #[arg(long = "proxy-file", help = "Proxy rotation list (one per line)", value_name = "FILE")]
    pub proxy_file: Option<PathBuf>,

    #[arg(long = "proxy-chain", help = "Comma-separated proxy chain: type://host:port,...", value_name = "PROXIES")]
    pub proxy_chain: Option<String>,

    // ── Output Options ──
    #[arg(short = 'o', long = "output", help = "Write results to FILE", value_name = "FILE")]
    pub output: Option<PathBuf>,

    #[arg(short = 'f', long = "format", help = "Output format: plain, json, csv, html", default_value = "plain", value_name = "FMT")]
    pub format: String,

    #[arg(long = "resume", help = "Resume from session file", value_name = "FILE")]
    pub resume: Option<PathBuf>,

    // ── Config ──
    #[arg(long = "config", help = "JSON config file", value_name = "FILE")]
    pub config: Option<PathBuf>,

    // ── Distributed Mode Options ──
    #[arg(long = "distributed-coordinator", help = "Run as coordinator on addr:port (e.g. 0.0.0.0:8443)", value_name = "BIND")]
    pub distributed_coordinator: Option<String>,

    #[arg(long = "distributed-worker", help = "Run as worker, connect to coordinator addr:port", value_name = "ADDR")]
    pub distributed_worker: Option<String>,

    #[arg(long = "distributed-token", help = "Auth token for coordinator↔worker communication", value_name = "TOKEN")]
    pub distributed_token: Option<String>,

    #[arg(long = "distributed-name", help = "Worker hostname (defaults to OS hostname)", value_name = "NAME")]
    pub distributed_name: Option<String>,

    // ── Plugin Options ──
    #[arg(long = "plugin", help = "External plugin binary path (repeatable)", value_name = "PATH")]
    pub plugins: Vec<String>,

    // ── REST API Options ──
    #[arg(long = "api", help = "Start REST API server on addr:port (e.g. 127.0.0.1:8080)", value_name = "BIND")]
    pub api_bind: Option<String>,

    // ── Encrypted Output Options ──
    #[arg(long = "encrypt", help = "Encrypt output file with AES-256-GCM")]
    pub encrypt: bool,

    #[arg(long = "encrypt-passphrase", help = "Passphrase for encryption (prompted if not provided)", value_name = "PASSPHRASE")]
    pub encrypt_passphrase: Option<String>,

    #[arg(long = "decrypt", help = "Decrypt an encrypted file", value_name = "FILE")]
    pub decrypt_file: Option<PathBuf>,

    #[arg(long = "decrypt-output", help = "Output path for decrypted file (default: stdout)", value_name = "FILE")]
    pub decrypt_output: Option<PathBuf>,

    // ── Wordlist Generation Options ──
    #[arg(long = "gen-wordlist", help = "Generate a wordlist from target information")]
    pub gen_wordlist: bool,

    #[arg(long = "wl-name", help = "Target name (e.g. 'John Smith')", value_name = "NAME")]
    pub wl_name: Option<String>,

    #[arg(long = "wl-company", help = "Company name", value_name = "COMPANY")]
    pub wl_company: Option<String>,

    #[arg(long = "wl-dob", help = "Date of birth (YYYY-MM-DD)", value_name = "DATE")]
    pub wl_dob: Option<String>,

    #[arg(long = "wl-keyword", help = "Additional keyword (repeatable)", value_name = "WORD")]
    pub wl_keywords: Vec<String>,

    #[arg(long = "wl-min-len", help = "Minimum password length", default_value = "4", value_name = "N")]
    pub wl_min_len: usize,

    #[arg(long = "wl-max-len", help = "Maximum password length", default_value = "32", value_name = "N")]
    pub wl_max_len: usize,

    #[arg(long = "wl-no-leet", help = "Disable leet speak variations")]
    pub wl_no_leet: bool,

    #[arg(long = "wl-output", help = "Write wordlist to file (default: stdout)", value_name = "FILE")]
    pub wl_output: Option<PathBuf>,

    // ── ML Password Prediction Options ──
    #[arg(long = "ml-train", help = "Train Markov model on a wordlist file", value_name = "FILE")]
    pub ml_train: Option<PathBuf>,

    #[arg(long = "ml-generate", help = "Generate N passwords from trained model (use after --ml-train)", value_name = "N")]
    pub ml_generate: Option<usize>,

    #[arg(long = "ml-order", help = "Markov chain order (default: 3)", default_value = "3", value_name = "N")]
    pub ml_order: usize,

    #[arg(long = "ml-max-len", help = "Max generated password length (default: 24)", default_value = "24", value_name = "N")]
    pub ml_max_len: usize,

    #[arg(long = "ml-score", help = "Score password(s) from a file (one per line) against the trained model", value_name = "FILE")]
    pub ml_score: Option<PathBuf>,

    #[arg(long = "ml-output", help = "Output file for generated passwords", value_name = "FILE")]
    pub ml_output: Option<PathBuf>,

    // ── Behavior Options ──
    #[arg(long = "stop-on-first", help = "Stop after first success per target")]
    pub stop_on_first: bool,

    #[arg(short = 'v', long = "verbose", help = "Verbose output (all attempts)")]
    pub verbose: bool,

    #[arg(short = 'q', long = "quiet", help = "Quiet mode (successes only)")]
    pub quiet: bool,

    #[arg(long = "no-banner", help = "Hide startup banner")]
    pub no_banner: bool,

}

impl CliArgs {
    pub fn into_config(self) -> Result<AttackConfig, AttackError> {
        let distributed = match (&self.distributed_coordinator, &self.distributed_worker) {
            (Some(bind), None) => Some(crate::core::config::DistributedMode::Coordinator { bind: bind.clone() }),
            (None, Some(addr)) => Some(crate::core::config::DistributedMode::Worker { connect: addr.clone() }),
            (Some(_), Some(_)) => return Err(AttackError::config("Cannot be both coordinator and worker")),
            (None, None) => None,
        };

        let mut config = AttackConfig {
            targets: Vec::new(),
            target_file: None,
            users: Vec::new(),
            passwords: Vec::new(),
            user_file: None,
            password_file: None,
            combo_file: None,
            protocols: Vec::new(),
            ports: Vec::new(),
            threads: 10,
            timeout: Duration::from_secs(10),
            delay: Duration::ZERO,
            rate_limit: None,
            proxy: None,
            proxy_file: None,
            proxy_chain: None,
            output_file: None,
            output_format: OutputFormat::Plain,
            resume_file: None,
            config_file: self.config.clone(),
            checkpoint_interval: 100,
            rdp_domain: None,
            http_userfield: None,
            http_passfield: None,
            http_success: None,
            verbose: false,
            quiet: false,
            no_banner: false,
            single_user_mode: false,
            spray_mode: false,
            stop_on_first: false,
            retries: 1,
            rule_file: None,
            max_mutations: 500,
            max_password_len: None,
            distributed,
            distributed_token: self.distributed_token,
            distributed_name: self.distributed_name,
            plugins: self.plugins.clone(),
            api_bind: self.api_bind.clone(),
            encrypt: self.encrypt,
            encrypt_passphrase: self.encrypt_passphrase,
            decrypt_file: self.decrypt_file,
            decrypt_output: self.decrypt_output,
        };

        if let Some(ref config_path) = self.config {
            let path = Path::new(config_path);
            if path.exists() {
                let cf = ConfigFile::load(path)?;
                cf.merge_into(&mut config);
            } else {
                return Err(AttackError::config(format!("Config file not found: {}", config_path.display())));
            }
        }

        if !self.targets.is_empty() {
            config.targets = self.targets;
        }
        if self.target_file.is_some() {
            config.target_file = self.target_file;
        }
        if !self.users.is_empty() {
            config.users = self.users;
        }
        if !self.passwords.is_empty() {
            config.passwords = self.passwords;
        }
        if self.user_file.is_some() {
            config.user_file = self.user_file;
        }
        if self.password_file.is_some() {
            config.password_file = self.password_file;
        }
        if self.combo_file.is_some() {
            config.combo_file = self.combo_file;
        }
        if !self.protocols.is_empty() {
            config.protocols = self.protocols;
        }
        if !self.ports.is_empty() {
            config.ports = self.ports;
        }
        if self.config.is_some() {
            // config_file already set above
        }
        if self.single_user {
            config.single_user_mode = true;
        }
        if self.spray {
            config.spray_mode = true;
        }
        if self.rules.is_some() {
            config.rule_file = self.rules;
        }
        config.max_mutations = self.max_mutations;
        config.threads = self.threads;
        config.timeout = Duration::from_secs(self.timeout);
        config.delay = Duration::from_millis(self.delay);
        if self.rate_limit.is_some() {
            config.rate_limit = self.rate_limit;
        }
        if self.retries != 1 {
            config.retries = self.retries;
        }
        if let Some(max_len) = self.max_password_len {
            config.max_password_len = Some(max_len);
        }
        if self.proxy.is_some() {
            config.proxy = self.proxy;
        }
        if self.proxy_file.is_some() {
            config.proxy_file = self.proxy_file;
        }
        if self.proxy_chain.is_some() {
            config.proxy_chain = self.proxy_chain;
        }
        if self.rdp_domain.is_some() {
            config.rdp_domain = self.rdp_domain;
        }
        if self.http_userfield.is_some() {
            config.http_userfield = self.http_userfield;
        }
        if self.http_passfield.is_some() {
            config.http_passfield = self.http_passfield;
        }
        if self.http_success.is_some() {
            config.http_success = self.http_success;
        }
        if self.output.is_some() {
            config.output_file = self.output;
        }
        if self.format != "plain" {
            config.output_format = OutputFormat::from_str(&self.format);
        }
        if self.resume.is_some() {
            config.resume_file = self.resume;
        }
        if self.verbose {
            config.verbose = true;
        }
        if self.quiet {
            config.quiet = true;
        }
        if self.no_banner {
            config.no_banner = true;
        }
        if self.stop_on_first {
            config.stop_on_first = true;
        }

        Ok(config)
    }

    pub fn to_wordlist_config(&self) -> WordlistConfig {
        WordlistConfig {
            name: self.wl_name.clone(),
            company: self.wl_company.clone(),
            dob: self.wl_dob.clone(),
            keywords: self.wl_keywords.clone(),
            min_len: self.wl_min_len,
            max_len: self.wl_max_len,
            leet: !self.wl_no_leet,
        }
    }

    pub fn should_show_banner(&self) -> bool {
        !self.no_banner && !self.quiet
    }
}

pub fn print_banner() {
    let banner = r#"
╔══════════════════════════════════════════════════════╗
║                    VELTRIX v1.0                      ║
║         Multi-Protocol Brute Force Toolkit           ║
║           An advanced security auditing tool         ║
╚══════════════════════════════════════════════════════╝
    "#;
    println!("{}", banner.yellow());
    println!("{}", "⚠  WARNING: Only use on systems you own or have permission to test.".red().bold());
    println!();
}

pub fn print_protocols() {
    println!("{}", "Supported Protocols:".green().bold());
    println!("  {:<12} {:<10} {}", "Protocol", "Default", "Auth Methods");
    println!("  {:<12} {:<10} {}", "────────", "───────", "────────────");
    println!("  {:<12} {:<10} {}", "ssh", "22", "password, key");
    println!("  {:<12} {:<10} {}", "ftp", "21", "plain, TLS/SSL");
    println!("  {:<12} {:<10} {}", "telnet", "23", "plaintext");
    println!("  {:<12} {:<10} {}", "smtp", "25", "LOGIN, PLAIN, CRAM-MD5");
    println!("  {:<12} {:<10} {}", "pop3", "110", "USER/PASS, APOP");
    println!("  {:<12} {:<10} {}", "rdp", "3389", "NLA, RDP Standard");
    println!("  {:<12} {:<10} {}", "mysql", "3306", "mysql_native_password");
    println!("  {:<12} {:<10} {}", "postgres", "5432", "md5, cleartext");
    println!("  {:<12} {:<10} {}", "ldap", "389", "simple bind");
    println!("  {:<12} {:<10} {}", "redis", "6379", "AUTH");
    println!("  {:<12} {:<10} {}", "http", "80/443", "Basic, Digest");
}
