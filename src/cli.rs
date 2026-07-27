use std::path::PathBuf;
use clap::{Parser, Subcommand, Args};
use colored::Colorize;

use crate::core::config::{AttackConfig, OutputFormat};
use crate::utils::wordlist_gen::WordlistConfig;

#[derive(Args, Debug, Clone)]
pub struct ProtocolArgs {
    #[arg(long = "rdp-domain", help = "RDP domain (prepended to username)", value_name = "DOMAIN")]
    pub rdp_domain: Option<String>,

    #[arg(long = "http-userfield", help = "HTTP form username field name", value_name = "FIELD")]
    pub http_userfield: Option<String>,

    #[arg(long = "http-passfield", help = "HTTP form password field name", value_name = "FIELD")]
    pub http_passfield: Option<String>,

    #[arg(long = "http-success", help = "HTTP form success indicator string", value_name = "TEXT")]
    pub http_success: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct ScanPortsArgs {
    #[arg(long = "ports", help = "Ports to scan: '22,80,443', '1-1000', or 'common' (default: common ~1200 ports)", value_name = "PORTS")]
    pub port_spec: Option<String>,

    #[arg(long = "scan-timeout", help = "Per-port timeout in seconds", default_value = "3", value_name = "SEC")]
    pub scan_timeout: u64,

    #[arg(long = "rate", help = "Max concurrent scans", default_value = "500", value_name = "N")]
    pub scan_rate: usize,

    #[arg(long = "no-banner", help = "Disable banner grabbing")]
    pub no_banner: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(about = "Fast TCP port scanner with banner grabbing and service fingerprinting")]
    ScanPorts(ScanPortsArgs),

    #[command(about = "SSH protocol brute force attack")]
    Ssh(ProtocolArgs),

    #[command(about = "FTP protocol brute force attack with TLS/SSL support")]
    Ftp(ProtocolArgs),

    #[command(about = "Telnet protocol brute force attack")]
    Telnet(ProtocolArgs),

    #[command(about = "SMTP protocol brute force attack with STARTTLS support")]
    Smtp(ProtocolArgs),

    #[command(about = "POP3 protocol brute force attack with STLS support")]
    Pop3(ProtocolArgs),

    #[command(about = "IMAP protocol brute force attack with STARTTLS support")]
    Imap(ProtocolArgs),

    #[command(about = "RDP protocol brute force attack with NLA support")]
    Rdp(ProtocolArgs),

    #[command(about = "MySQL database brute force attack")]
    Mysql(ProtocolArgs),

    #[command(about = "PostgreSQL database brute force attack with SSL support")]
    Postgres(ProtocolArgs),

    #[command(about = "LDAP protocol brute force attack with LDAPS support")]
    Ldap(ProtocolArgs),

    #[command(about = "Redis database brute force attack with TLS support")]
    Redis(ProtocolArgs),

    #[command(about = "HTTP/HTTPS form-based brute force attack")]
    Http(ProtocolArgs),

    #[command(about = "VNC authentication brute force attack")]
    Vnc(ProtocolArgs),

    #[command(about = "MongoDB database brute force attack")]
    Mongodb(ProtocolArgs),

    #[command(about = "MSSQL database brute force attack")]
    Mssql(ProtocolArgs),

    #[command(about = "SMB/CIFS protocol brute force attack")]
    Smb(ProtocolArgs),

    #[command(about = "SNMP protocol brute force attack with community string enumeration")]
    Snmp(ProtocolArgs),

    #[command(about = "Generate a wordlist from target/personal information")]
    Create(CreateArgs),
}

#[derive(Args, Debug, Clone)]
pub struct CreateArgs {
    #[arg(short = 'n', long = "name", help = "Target name (e.g. 'John Smith')", value_name = "NAME")]
    pub name: Option<String>,

    #[arg(short = 'c', long = "company", help = "Company name", value_name = "COMPANY")]
    pub company: Option<String>,

    #[arg(short = 'd', long = "dob", help = "Date of birth (YYYY-MM-DD)", value_name = "DATE")]
    pub dob: Option<String>,

    #[arg(short = 'k', long = "keyword", help = "Additional keyword (repeatable)", value_name = "WORD")]
    pub keywords: Vec<String>,

    #[arg(long = "min-len", help = "Minimum password length", default_value = "4", value_name = "N")]
    pub min_len: usize,

    #[arg(long = "max-len", help = "Maximum password length", default_value = "32", value_name = "N")]
    pub max_len: usize,

    #[arg(long = "no-leet", help = "Disable leet speak variations")]
    pub no_leet: bool,

    #[arg(short = 'F', long = "filename", help = "Custom filename (without extension) inside wordlists folder", value_name = "NAME")]
    pub filename: Option<String>,

    #[arg(long = "dir", help = "Custom output directory (default: ./wordlists/)", value_name = "DIR")]
    pub dir: Option<PathBuf>,

    #[arg(short = 'o', long = "output", help = "Exact output file path (overrides --dir/--filename)", value_name = "FILE")]
    pub output: Option<PathBuf>,
}

#[derive(Parser, Debug)]
#[command(
    name = "veltrix",
    version = "1.1.0",
    about = "\
VELTRIX v1.1 - Multi-Protocol Brute Force & Security Auditing Toolkit - By AniipID

\u{26a0}  WARNING: For authorized security testing ONLY.
\u{26a0}  Unauthorized use is ILLEGAL.

Supports 18+ protocols (ssh, ftp, telnet, smtp, pop3, imap, rdp,
mysql, postgres, ldap, redis, http, vnc, mongodb, mssql, smb, snmp)
plus port scanning, wordlist gen, ML prediction, distributed mode.",
    long_about = concat!(
        "VELTRIX v1.1 - Multi-Protocol Brute Force & Security Auditing Toolkit - By AniipID\n",
        "===================================================\n\n",
        "A high-performance, multi-protocol brute force & security auditing tool\n",
        "written in Rust. Supports 18+ protocols with advanced features.\n\n",
        "\u{26a0}  WARNING: This tool is for authorized security testing ONLY.\n",
        "\u{26a0}  Unauthorized use against systems you do not own or lack\n",
        "\u{26a0}  explicit written permission to test is ILLEGAL.\n",
        "\u{26a0}  Users are solely responsible for complying with all\n",
        "\u{26a0}  applicable local, state, and federal laws.\n\n",
        "Features:\n",
        "  - 18 attack protocols: ssh, ftp, telnet, smtp, pop3, imap, rdp,\n",
        "    mysql, postgres, ldap, redis, http, vnc, mongodb, mssql, smb, snmp\n",
        "  - Fast TCP port scanner with banner grabbing & service fingerprinting\n",
        "  - Wordlist generation from target information\n",
        "  - Markov-chain based password generation & scoring (ML mode)\n",
        "  - Distributed brute force across multiple nodes\n",
        "  - Proxy support: HTTP, SOCKS4, SOCKS5, with rotation & chaining\n",
        "  - Plugin system for custom protocol modules\n",
        "  - AES-256-GCM output encryption\n",
        "  - CIDR & range target expansion\n\n",
        "Examples:\n",
        "  veltrix ssh -t 192.168.1.1 -u admin -W passwords.txt\n",
        "  veltrix ftp -t 10.0.0.1 -U users.txt -W passes.txt -x 20\n",
        "  veltrix scan-ports -t 10.0.0.1 --ports 22,80,443\n",
        "  veltrix rdp -t 10.0.0.5 -C combos.txt -o results.json -f json\n",
        "  veltrix smtp -t mail.example.com -U users.txt -W pass.txt\n",
        "  veltrix http -t https://example.com/login -u admin -W pass.txt\n\n",
        "CIDR & Range:\n",
        "  veltrix ssh -t 192.168.1.0/24 -U users.txt -W passes.txt\n",
        "  veltrix ssh -t 10.0.0.1-10.0.0.10 -C combos.txt\n\n",
        "\u{26a0}  WARNING: Only use on systems you own or have written permission to test."
    ),
    verbatim_doc_comment,
    subcommand_required = true,
    arg_required_else_help = true,
    override_usage = "veltrix <COMMAND> [OPTIONS]",
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    // ── Target ──
    #[arg(short = 't', long = "target", help = "Target host:port or IP address (support domain/IP local/public)", value_name = "HOST[:PORT]", global = true)]
    pub targets: Vec<String>,

    #[arg(short = 'l', long = "list", help = "File containing list of target hosts (one per line)", value_name = "FILE", global = true)]
    pub target_file: Option<PathBuf>,

    #[arg(short = 'p', long = "port", help = "Port number(s)", value_name = "PORT", global = true)]
    pub ports: Vec<u16>,

    #[arg(short = 'L', long = "list-protocols", help = "List supported protocols and exit", global = true)]
    pub list_protocols: bool,

    // ── Credentials ──
    #[arg(short = 'u', long = "user", help = "Single username", value_name = "USER", global = true)]
    pub users: Vec<String>,

    #[arg(short = 'U', long = "user-file", help = "File containing list of usernames (one per line)", value_name = "FILE", global = true)]
    pub user_file: Option<PathBuf>,

    #[arg(long = "password", visible_alias = "pwd", help = "Single password", value_name = "PASS", global = true)]
    pub passwords: Vec<String>,

    #[arg(short = 'W', long = "password-list", visible_alias = "pl", help = "File containing list of passwords (one per line)", value_name = "FILE", global = true)]
    pub password_file: Option<PathBuf>,

    #[arg(short = 'C', long = "combo", help = "Combo list: user:pass per line", value_name = "FILE", global = true)]
    pub combo_file: Option<PathBuf>,

    // ── Performance ──
    #[arg(short = 'x', long = "threads", help = "Concurrent workers", default_value = "10", value_name = "N", global = true)]
    pub threads: usize,

    #[arg(long = "timeout", help = "Connection timeout (seconds)", default_value = "10", value_name = "SEC", global = true)]
    pub timeout: u64,

    #[arg(long = "delay", help = "Delay between attempts (ms)", default_value = "0", value_name = "MS", global = true)]
    pub delay: u64,

    #[arg(long = "rate-limit", help = "Max attempts/sec (0=unlimited)", value_name = "N", global = true)]
    pub rate_limit: Option<u64>,

    #[arg(long = "retries", help = "Connection retries", default_value = "1", value_name = "N", global = true)]
    pub retries: u32,

    #[arg(long = "stop-on-first", help = "Stop after first success per target", global = true)]
    pub stop_on_first: bool,

    #[arg(long = "max-password-len", help = "Truncate passwords to N characters", value_name = "N", global = true)]
    pub max_password_len: Option<usize>,

    // ── Proxy ──
    #[arg(long = "proxy", help = "Proxy: type://host[:port]", value_name = "PROXY", global = true)]
    pub proxy: Option<String>,

    #[arg(long = "proxy-file", help = "Proxy rotation list (one per line)", value_name = "FILE", global = true)]
    pub proxy_file: Option<PathBuf>,

    #[arg(long = "proxy-chain", help = "Comma-separated proxy chain: type://host:port,...", value_name = "PROXIES", global = true)]
    pub proxy_chain: Option<String>,

    // ── Output ──
    #[arg(short = 'o', long = "output", help = "Write results to FILE", value_name = "FILE", global = true)]
    pub output: Option<PathBuf>,

    #[arg(short = 'f', long = "format", help = "Output format: plain, json, csv, html", default_value = "plain", value_name = "FMT", global = true)]
    pub format: String,

    // ── Plugin ──
    #[arg(long = "plugin", help = "External plugin binary path (repeatable)", value_name = "PATH", global = true)]
    pub plugins: Vec<String>,

    #[arg(long = "list-plugin", help = "List all registered plugins and exit", global = true)]
    pub list_plugin: bool,

    // ── Encrypt ──
    #[arg(long = "encrypt", help = "Encrypt output file with AES-256-GCM", global = true)]
    pub encrypt: bool,

    #[arg(long = "encrypt-passphrase", help = "Passphrase for encryption (prompted if not provided)", value_name = "PASSPHRASE", global = true)]
    pub encrypt_passphrase: Option<String>,

    // ── Decrypt ──
    #[arg(long = "decrypt", help = "Decrypt an encrypted file", value_name = "FILE", global = true)]
    pub decrypt_file: Option<PathBuf>,

    #[arg(long = "decrypt-output", help = "Output path for decrypted file (default: stdout)", value_name = "FILE", global = true)]
    pub decrypt_output: Option<PathBuf>,

    // ── Wordlist Generation ──
    #[arg(long = "gen-wordlist", help = "Generate a wordlist from target information", global = true)]
    pub gen_wordlist: bool,

    #[arg(long = "wl-name", help = "Target name (e.g. 'John Smith')", value_name = "NAME", global = true)]
    pub wl_name: Option<String>,

    #[arg(long = "wl-company", help = "Company name", value_name = "COMPANY", global = true)]
    pub wl_company: Option<String>,

    #[arg(long = "wl-dob", help = "Date of birth (YYYY-MM-DD)", value_name = "DATE", global = true)]
    pub wl_dob: Option<String>,

    #[arg(long = "wl-keyword", help = "Additional keyword (repeatable)", value_name = "WORD", global = true)]
    pub wl_keywords: Vec<String>,

    #[arg(long = "wl-min-len", help = "Minimum password length", default_value = "4", value_name = "N", global = true)]
    pub wl_min_len: usize,

    #[arg(long = "wl-max-len", help = "Maximum password length", default_value = "32", value_name = "N", global = true)]
    pub wl_max_len: usize,

    #[arg(long = "wl-no-leet", help = "Disable leet speak variations", global = true)]
    pub wl_no_leet: bool,

    #[arg(long = "wl-output", help = "Write wordlist to file (default: stdout)", value_name = "FILE", global = true)]
    pub wl_output: Option<PathBuf>,

    // ── ML Password Prediction ──
    #[arg(long = "ml-train", help = "Train Markov model on a wordlist file", value_name = "FILE", global = true)]
    pub ml_train: Option<PathBuf>,

    #[arg(long = "ml-generate", help = "Generate N passwords from trained model (use after --ml-train)", value_name = "N", global = true)]
    pub ml_generate: Option<usize>,

    #[arg(long = "ml-order", help = "Markov chain order (default: 3)", default_value = "3", value_name = "N", global = true)]
    pub ml_order: usize,

    #[arg(long = "ml-max-len", help = "Max generated password length (default: 24)", default_value = "24", value_name = "N", global = true)]
    pub ml_max_len: usize,

    #[arg(long = "ml-score", help = "Score password(s) from a file (one per line) against the trained model", value_name = "FILE", global = true)]
    pub ml_score: Option<PathBuf>,

    #[arg(long = "ml-output", help = "Output file for generated passwords", value_name = "FILE", global = true)]
    pub ml_output: Option<PathBuf>,

    // ── Verbose ──
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count, help = "Verbose level 1 (-v) or verbose level 2 (-vv)", global = true)]
    pub verbose: u8,
}

impl Cli {
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
        self.verbose > 0
    }

    pub fn build_attack_config(&self, protocol: &str, args: &ProtocolArgs) -> AttackConfig {
        AttackConfig {
            targets: self.targets.clone(),
            target_file: self.target_file.clone(),
            users: self.users.clone(),
            passwords: self.passwords.clone(),
            user_file: self.user_file.clone(),
            password_file: self.password_file.clone(),
            combo_file: self.combo_file.clone(),
            protocols: vec![protocol.to_string()],
            ports: self.ports.clone(),
            threads: self.threads,
            timeout: std::time::Duration::from_secs(self.timeout),
            delay: std::time::Duration::from_millis(self.delay),
            rate_limit: self.rate_limit,
            proxy: self.proxy.clone(),
            proxy_file: self.proxy_file.clone(),
            proxy_chain: self.proxy_chain.clone(),
            output_file: self.output.clone(),
            output_format: OutputFormat::from_str(&self.format),
            resume_file: None,
            config_file: None,
            checkpoint_interval: 100,
            rdp_domain: args.rdp_domain.clone(),
            http_userfield: args.http_userfield.clone(),
            http_passfield: args.http_passfield.clone(),
            http_success: args.http_success.clone(),
            verbose: self.verbose,
            quiet: false,
            no_banner: false,
            single_user_mode: false,
            spray_mode: false,
            stop_on_first: self.stop_on_first,
            retries: self.retries,
            rule_file: None,
            max_mutations: 500,
            max_password_len: self.max_password_len,
            distributed: None,
            distributed_token: None,
            distributed_name: None,
            plugins: self.plugins.clone(),
            api_bind: None,
            encrypt: self.encrypt,
            encrypt_passphrase: self.encrypt_passphrase.clone(),
            decrypt_file: self.decrypt_file.clone(),
            decrypt_output: self.decrypt_output.clone(),
        }
    }
}

pub fn port_to_protocol(port: u16) -> Option<&'static str> {
    match port {
        22 => Some("ssh"),
        21 => Some("ftp"),
        23 => Some("telnet"),
        25 => Some("smtp"),
        110 => Some("pop3"),
        143 => Some("imap"),
        389 => Some("ldap"),
        636 => Some("ldap"),
        443 => Some("http"),
        445 => Some("smb"),
        993 => Some("imap"),
        995 => Some("pop3"),
        1433 => Some("mssql"),
        3306 => Some("mysql"),
        3389 => Some("rdp"),
        5432 => Some("postgres"),
        587 => Some("smtp"),
        465 => Some("smtp"),
        5900 => Some("vnc"),
        5901 => Some("vnc"),
        6379 => Some("redis"),
        6380 => Some("redis"),
        8080 => Some("http"),
        8443 => Some("http"),
        27017 => Some("mongodb"),
        161 => Some("snmp"),
        _ => None,
    }
}

pub fn print_banner() {
    let banner = r#"
╔══════════════════════════════════════════════════════╗
║                  VELTRIX v1.1                        ║
║         Multi-Protocol Brute Force Toolkit           ║
║           An advanced security auditing tool         ║
║                   By AniipID                         ║
╚══════════════════════════════════════════════════════╝
    "#;
    println!("{}", banner.yellow());
    println!("{}", "\u{26a0}  WARNING: Only use on systems you own or have permission to test.".red().bold());
    println!();
}

pub fn print_protocols() {
    println!("{}", "Supported Protocols:".green().bold());
    println!("  {:<12} {:<12} {}", "Protocol", "Default Port(s)", "Auth Methods");
    println!("  {:<12} {:<12} {}", "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}", "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}", "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}");
    println!("  {:<12} {:<12} {}", "ssh", "22", "password, key");
    println!("  {:<12} {:<12} {}", "ftp", "21", "plain, TLS/SSL");
    println!("  {:<12} {:<12} {}", "telnet", "23", "plaintext");
    println!("  {:<12} {:<12} {}", "smtp", "25/465/587", "LOGIN, PLAIN, CRAM-MD5, STARTTLS");
    println!("  {:<12} {:<12} {}", "pop3", "110/995", "USER/PASS, APOP, STLS");
    println!("  {:<12} {:<12} {}", "imap", "143/993", "LOGIN, PLAIN, CRAM-MD5, STARTTLS");
    println!("  {:<12} {:<12} {}", "rdp", "3389", "NLA, RDP Standard");
    println!("  {:<12} {:<12} {}", "mysql", "3306", "mysql_native_password");
    println!("  {:<12} {:<12} {}", "postgres", "5432", "md5, cleartext, SSL");
    println!("  {:<12} {:<12} {}", "ldap", "389/636", "simple bind, LDAPS");
    println!("  {:<12} {:<12} {}", "redis", "6379/6380", "AUTH, TLS");
    println!("  {:<12} {:<12} {}", "http", "80/443", "Basic, Digest, Form");
    println!("  {:<12} {:<12} {}", "vnc", "5900", "VNC Auth");
    println!("  {:<12} {:<12} {}", "mongodb", "27017", "SCRAM, MONGODB-CR");
    println!("  {:<12} {:<12} {}", "mssql", "1433", "SQL Server Auth");
    println!("  {:<12} {:<12} {}", "smb", "445", "NTLMv1/v2");
    println!("  {:<12} {:<12} {}", "snmp", "161", "community strings (v1/v2c)");
    println!();
}
