use std::path::PathBuf;
use std::time::Duration;
use clap::Parser;
use colored::Colorize;

use crate::core::config::{AttackConfig, OutputFormat};

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
        "⚠  WARNING: Only use on systems you own or have written permission to test."
    ),
    verbatim_doc_comment
)]
pub struct CliArgs {
    // ── Target Options ──
    #[arg(short = 't', long = "target", help = "Target host:port (can be specified multiple times)", value_name = "HOST:PORT")]
    pub targets: Vec<String>,

    #[arg(short = 'T', long = "target-file", help = "File containing list of targets (one per line)", value_name = "FILE")]
    pub target_file: Option<PathBuf>,

    #[arg(short = 'p', long = "port", help = "Port number(s) - defaults per protocol", value_name = "PORT")]
    pub ports: Vec<u16>,

    // ── Protocol Options ──
    #[arg(
        short = 'P',
        long = "protocol",
        help = "Protocol(s) to attack (ssh, ftp, telnet, smtp, pop3, rdp, mysql, http)",
        value_name = "PROTO",
        value_delimiter = ',',
        required_unless_present = "list_protocols"
    )]
    pub protocols: Vec<String>,

    #[arg(short = 'L', long = "list-protocols", help = "List all supported protocols and exit")]
    pub list_protocols: bool,

    // ── Credential Options ──
    #[arg(short = 'u', long = "user", help = "Single username (can be specified multiple times)", value_name = "USER")]
    pub users: Vec<String>,

    #[arg(short = 'U', long = "user-file", help = "File containing list of usernames", value_name = "FILE")]
    pub user_file: Option<PathBuf>,

    #[arg(short = 'w', long = "password", help = "Single password (can be specified multiple times)", value_name = "PASS")]
    pub passwords: Vec<String>,

    #[arg(short = 'W', long = "password-file", help = "File containing list of passwords", value_name = "FILE")]
    pub password_file: Option<PathBuf>,

    #[arg(short = 'C', long = "combo", help = "Combo list file (format: user:pass per line)", value_name = "FILE")]
    pub combo_file: Option<PathBuf>,

    #[arg(long = "single-user", help = "Single user mode: use only the first user against all passwords")]
    pub single_user: bool,

    #[arg(long = "spray", help = "Credential spraying: try each password against all users (anti-lockout)")]
    pub spray: bool,

    // ── Performance Options ──
    #[arg(short = 'x', long = "threads", help = "Number of concurrent workers", default_value = "10", value_name = "N")]
    pub threads: usize,

    #[arg(long = "timeout", help = "Connection timeout in seconds", default_value = "10", value_name = "SEC")]
    pub timeout: u64,

    #[arg(long = "delay", help = "Delay between attempts in milliseconds", default_value = "0", value_name = "MS")]
    pub delay: u64,

    #[arg(long = "rate-limit", help = "Max attempts per second (0 = unlimited)", value_name = "N")]
    pub rate_limit: Option<u64>,

    #[arg(long = "retries", help = "Number of retries per failed connection", default_value = "1", value_name = "N")]
    pub retries: u32,

    // ── Proxy Options ──
    #[arg(long = "proxy", help = "Proxy to use (format: type://host:port or type://user:pass@host:port)", value_name = "PROXY")]
    pub proxy: Option<String>,

    #[arg(long = "proxy-file", help = "File containing list of proxies (rotation)", value_name = "FILE")]
    pub proxy_file: Option<PathBuf>,

    // ── Output Options ──
    #[arg(short = 'o', long = "output", help = "Output file path", value_name = "FILE")]
    pub output: Option<PathBuf>,

    #[arg(short = 'f', long = "format", help = "Output format: plain, json, csv", default_value = "plain", value_name = "FMT")]
    pub format: String,

    #[arg(long = "resume", help = "Resume from session file", value_name = "FILE")]
    pub resume: Option<PathBuf>,

    // ── Behavior Options ──
    #[arg(long = "stop-on-first", help = "Stop after first success per target")]
    pub stop_on_first: bool,

    #[arg(short = 'v', long = "verbose", help = "Verbose output (show all attempts)")]
    pub verbose: bool,

    #[arg(short = 'q', long = "quiet", help = "Quiet mode (show successes only)")]
    pub quiet: bool,

    #[arg(long = "no-banner", help = "Hide startup banner")]
    pub no_banner: bool,
}

impl CliArgs {
    pub fn into_config(self) -> Result<AttackConfig, String> {
        Ok(AttackConfig {
            targets: self.targets,
            target_file: self.target_file,
            users: self.users,
            passwords: self.passwords,
            user_file: self.user_file,
            password_file: self.password_file,
            combo_file: self.combo_file,
            protocols: self.protocols,
            ports: self.ports,
            threads: self.threads,
            timeout: Duration::from_secs(self.timeout),
            delay: Duration::from_millis(self.delay),
            rate_limit: self.rate_limit,
            proxy_file: self.proxy_file,
            output_file: self.output,
            output_format: OutputFormat::from_str(&self.format),
            resume_file: self.resume,
            verbose: self.verbose,
            single_user_mode: self.single_user,
            spray_mode: self.spray,
            stop_on_first: self.stop_on_first,
            retries: self.retries,
        })
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
    println!("{}", banner);
    println!("{}", "⚠  WARNING: Only use on systems you own or have permission to test.\n".to_string());
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
    println!("  {:<12} {:<10} {}", "http", "80/443", "Basic, Digest");
}
