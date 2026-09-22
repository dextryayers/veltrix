use std::path::PathBuf;
use clap::{Parser, Subcommand, Args};
use colored::Colorize;
use std::io::Write;

use crate::core::config::{AttackConfig, OutputFormat};
use crate::utils::wordlist_gen::WordlistConfig;

#[derive(Args, Debug, Clone)]
pub struct ProtocolArgs {
    #[arg(help_heading = "Protocol Options", long = "rdp-domain", help = "RDP domain (prepended to username)", value_name = "DOMAIN")]
    pub rdp_domain: Option<String>,

    #[arg(help_heading = "Protocol Options", long = "http-userfield", help = "HTTP form username field name", value_name = "FIELD")]
    pub http_userfield: Option<String>,

    #[arg(help_heading = "Protocol Options", long = "http-passfield", help = "HTTP form password field name", value_name = "FIELD")]
    pub http_passfield: Option<String>,

    #[arg(help_heading = "Protocol Options", long = "http-success", help = "HTTP form success indicator string", value_name = "TEXT")]
    pub http_success: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct ScanPortsArgs {
    #[arg(help_heading = "Scanner Options", long = "ports", help = "Ports to scan: '22,80,443', '1-1000', or 'common' (default: common ~1200 ports)", value_name = "PORTS")]
    pub port_spec: Option<String>,

    #[arg(help_heading = "Scanner Options", long = "scan-timeout", help = "Per-port timeout in seconds", default_value = "3", value_name = "SEC")]
    pub scan_timeout: u64,

    #[arg(help_heading = "Scanner Options", long = "rate", help = "Max concurrent scans", default_value = "500", value_name = "N")]
    pub scan_rate: usize,

    #[arg(help_heading = "Scanner Options", long = "no-banner", help = "Disable banner grabbing")]
    pub no_banner: bool,

    #[arg(help_heading = "Scanner Options", long = "shuffle", help = "Randomize probe order (anti-fingerprint IDS)", global = true)]
    pub shuffle: bool,
}

#[derive(Args, Debug, Clone)]
pub struct AutoArgs {
    #[command(flatten)]
    pub scan: ScanPortsArgs,

    #[arg(help_heading = "Auto Options", long = "policy", help = "Auto-mode policy file (TOML): allowed protocols/subnets, max threads, min confidence", value_name = "FILE")]
    pub policy: Option<PathBuf>,

    #[arg(help_heading = "Auto Options", long = "min-confidence", help = "Minimum fingerprint confidence 0-100 to launch an attack group", value_name = "N")]
    pub min_confidence: Option<u8>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(about = "Fast TCP port scanner with banner grabbing and service fingerprinting")]
    ScanPorts(ScanPortsArgs),

    #[command(about = "Automatic scan-to-attack: scan ports, fingerprint services, brute-force only open attackable services")]
    Auto(AutoArgs),

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

    // ── Database ──
    #[command(about = "Oracle database brute force attack")]
    Oracle(ProtocolArgs),
    #[command(about = "Cassandra database brute force attack")]
    Cassandra(ProtocolArgs),
    #[command(about = "CouchDB NoSQL database brute force attack")]
    Couchdb(ProtocolArgs),
    #[command(about = "Elasticsearch database brute force attack")]
    Elasticsearch(ProtocolArgs),
    #[command(about = "Firebird database brute force attack")]
    Firebird(ProtocolArgs),

    // ── Message Queue ──
    #[command(about = "RabbitMQ message broker brute force attack")]
    Rabbitmq(ProtocolArgs),
    #[command(about = "ActiveMQ message broker brute force attack")]
    Activemq(ProtocolArgs),
    #[command(about = "Apache Kafka message broker brute force attack")]
    Kafka(ProtocolArgs),

    // ── VoIP / Media ──
    #[command(about = "SIP VoIP protocol brute force attack")]
    Sip(ProtocolArgs),
    #[command(about = "RTSP media streaming brute force attack")]
    Rtsp(ProtocolArgs),

    // ── Web Apps ──
    #[command(about = "Apache Tomcat brute force attack")]
    Tomcat(ProtocolArgs),
    #[command(about = "Jenkins CI brute force attack")]
    Jenkins(ProtocolArgs),
    #[command(about = "GitLab brute force attack")]
    Gitlab(ProtocolArgs),
    #[command(about = "SonarQube brute force attack")]
    Sonarqube(ProtocolArgs),
    #[command(about = "Docker registry brute force attack")]
    Docker(ProtocolArgs),
    #[command(about = "Kubernetes API server brute force attack")]
    Kubernetes(ProtocolArgs),
    #[command(about = "HashiCorp Vault brute force attack")]
    Vault(ProtocolArgs),
    #[command(about = "HashiCorp Consul brute force attack")]
    Consul(ProtocolArgs),

    // ── Remote Management ──
    #[command(about = "VMware vSphere brute force attack")]
    Vmware(ProtocolArgs),
    #[command(about = "HP iLO remote management brute force attack")]
    Ilo(ProtocolArgs),
    #[command(about = "IPMI remote management brute force attack")]
    Ipmi(ProtocolArgs),

    // ── Chat / News ──
    #[command(about = "XMPP instant messaging brute force attack")]
    Xmpp(ProtocolArgs),
    #[command(about = "IRC chat protocol brute force attack")]
    Irc(ProtocolArgs),
    #[command(about = "NNTP newsgroup brute force attack")]
    Nntp(ProtocolArgs),

    // ── Version Control ──
    #[command(about = "CVS version control brute force attack")]
    Cvs(ProtocolArgs),
    #[command(about = "SVN Subversion brute force attack")]
    Svn(ProtocolArgs),

    // ── Legacy ──
    #[command(about = "Rexec remote execution brute force attack")]
    Rexec(ProtocolArgs),
    #[command(about = "Rlogin remote login brute force attack")]
    Rlogin(ProtocolArgs),

    // ── Other ──
    #[command(about = "Squid proxy brute force attack")]
    Squid(ProtocolArgs),
    #[command(about = "Memcached brute force attack")]
    Memcached(ProtocolArgs),

    #[command(about = "Generate a wordlist from target/personal information")]
    Create(CreateArgs),

    #[command(about = "Wordlist utilities: rank candidates probable-first with a Markov model")]
    Wordlist(WordlistArgs),

    #[command(about = "Validate a TOML or JSON config file without attacking")]
    Validate(ValidateArgs),

    #[command(about = "Print shell completion script (bash, zsh, fish, powershell)")]
    Completion(CompletionArgs),

    #[command(about = "Start REST API v2 + Web UI server (JWT auth, job queue, live progress)")]
    Serve(ServeArgs),

    #[command(about = "Distributed coordinator: split work into chunks and serve workers (veltrix-dist-v2)")]
    DistCoordinator(DistCoordinatorArgs),

    #[command(about = "Distributed worker: pull chunks from a coordinator and execute them")]
    DistWorker(DistWorkerArgs),

    #[command(about = "Display comprehensive manual with detailed usage, examples, and option reference", visible_alias = "how")]
    Man,

    #[command(about = "Check egress IP via proxy (or direct): verify your cover before attacking")]
    CheckIp(CheckIpArgs),
}

#[derive(Subcommand, Debug, Clone)]
pub enum WordlistCommand {
    #[command(about = "Rank candidates probable-first using a Markov model trained on a wordlist")]
    Rank(RankArgs),
    #[command(about = "Evaluate a ranked list: precision@K against a held-out relevant set (F8.4, angka bukan klaim)")]
    Eval(EvalArgs),
}

#[derive(Args, Debug, Clone)]
pub struct WordlistArgs {
    #[command(subcommand)]
    pub command: WordlistCommand,
}

#[derive(Args, Debug, Clone)]
pub struct RankArgs {
    #[arg(help_heading = "Wordlist Options", long = "input", help = "Candidate passwords file (one per line)", value_name = "FILE")]
    pub input: PathBuf,

    #[arg(help_heading = "Wordlist Options", long = "model", help = "Training wordlist file for the Markov model (one per line). Defaults to --input itself", value_name = "FILE")]
    pub model: Option<PathBuf>,

    #[arg(help_heading = "Wordlist Options", long = "order", help = "Markov chain order", value_name = "N", default_value = "3")]
    pub order: usize,

    #[arg(help_heading = "Wordlist Options", long = "top", help = "Keep only top N candidates (0 = all)", value_name = "N", default_value = "10000")]
    pub top: usize,

    #[arg(help_heading = "Wordlist Options", long = "min-score", help = "Drop candidates with score above this (lower = more probable)", value_name = "F")]
    pub min_score: Option<f64>,

    #[arg(help_heading = "Output Options", short = 'o', long = "output", help = "Output file (default: stdout)", value_name = "FILE")]
    pub output: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct EvalArgs {
    #[arg(help_heading = "Wordlist Options", long = "ranked", help = "Ranked list file from `wordlist rank` (format: password<TAB>score, most-probable first)", value_name = "FILE")]
    pub ranked: PathBuf,

    #[arg(help_heading = "Wordlist Options", long = "relevant", help = "Held-out relevant passwords file (one per line, e.g. real leaks for the target profile)", value_name = "FILE")]
    pub relevant: PathBuf,

    #[arg(help_heading = "Wordlist Options", long = "k", help = "Comma-separated K values for precision@K (e.g. 10,20,50,100)", value_name = "LIST", default_value = "10,20,50")]
    pub k: String,
}

#[derive(Args, Debug, Clone)]
pub struct CheckIpArgs {
    #[arg(help_heading = "Check Options", long = "timeout", help = "Egress check timeout in seconds", value_name = "SEC", default_value = "10")]
    pub timeout: u64,

    #[arg(help_heading = "Check Options", long = "url", help = "IP echo service URL (must return plain-text IP)", value_name = "URL", default_value = "https://api.ipify.org")]
    pub url: String,
}

#[derive(Args, Debug, Clone)]
pub struct ValidateArgs {
    #[arg(help_heading = "Validate Options", help = "Config file to validate (TOML or JSON)", value_name = "FILE")]
    pub file: PathBuf,
}

#[derive(Args, Debug, Clone)]
pub struct CompletionArgs {
    #[arg(help_heading = "Completion Options", help = "Shell: bash, zsh, fish, powershell")]
    pub shell: String,
}

#[derive(Args, Debug, Clone)]
pub struct ServeArgs {
    #[arg(help_heading = "Server Options", long = "bind", help = "API bind address (default 127.0.0.1:8080; bind 0.0.0.0 only on trusted nets)", value_name = "ADDR", default_value = "127.0.0.1:8080")]
    pub bind: String,

    #[arg(help_heading = "Server Options", long = "api-token", help = "Pre-shared API token (or env VELTRIX_API_TOKEN; ephemeral if omitted)", value_name = "TOKEN")]
    pub api_token: Option<String>,

    #[arg(help_heading = "Server Options", long = "api-rate-limit", help = "Max API requests per minute per IP", value_name = "N", default_value = "120")]
    pub rate_per_min: u32,
}

#[derive(Args, Debug, Clone)]
pub struct DistCoordinatorArgs {
    #[arg(help_heading = "Server Options", long = "bind", help = "Coordinator bind address", value_name = "ADDR", default_value = "127.0.0.1:5555")]
    pub bind: String,

    #[arg(help_heading = "Server Options", long = "dist-token", help = "Per-run worker token (or env VELTRIX_DIST_TOKEN)", value_name = "TOKEN")]
    pub dist_token: Option<String>,

    #[arg(help_heading = "Server Options", long = "dist-token-ttl", help = "Token lifetime in seconds", value_name = "SEC", default_value = "21600")]
    pub token_ttl: u64,

    #[arg(help_heading = "Server Options", long = "chunk-size", help = "Tasks per chunk", value_name = "N", default_value = "100")]
    pub chunk_size: usize,

    #[arg(help_heading = "Server Options", long = "chunk-timeout", help = "Seconds before an in-flight chunk is requeued", value_name = "SEC", default_value = "120")]
    pub chunk_timeout: u64,

    #[arg(help_heading = "Server Options", long = "heartbeat-timeout", help = "Seconds without heartbeat before a worker is dropped", value_name = "SEC", default_value = "60")]
    pub heartbeat_timeout: u64,

    #[arg(help_heading = "Server Options", long = "max-attempts", help = "Max assignments per chunk before marking failed", value_name = "N", default_value = "3")]
    pub max_attempts: u32,

    #[arg(help_heading = "Server Options", long = "protocol", help = "Attack protocol (repeatable)", value_name = "PROTO", default_value = "ssh")]
    pub protocols: Vec<String>,
}

#[derive(Args, Debug, Clone)]
pub struct DistWorkerArgs {
    #[arg(help_heading = "Server Options", long = "connect", help = "Coordinator address host:port", value_name = "ADDR")]
    pub connect: String,

    #[arg(help_heading = "Server Options", long = "dist-token", help = "Run token from coordinator (or env VELTRIX_DIST_TOKEN)", value_name = "TOKEN")]
    pub dist_token: Option<String>,

    #[arg(help_heading = "Generator Options", long = "name", help = "Worker hostname label", value_name = "NAME", default_value = "worker")]
    pub name: String,

    #[arg(long = "threads", help = "Max concurrent task executions", value_name = "N", default_value = "10")]
    pub threads: usize,

    #[arg(help_heading = "Server Options", long = "checkpoint-file", help = "Checkpoint file for acked task_ids", value_name = "FILE")]
    pub checkpoint_file: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct CreateArgs {
    #[arg(help_heading = "Generator Options", short = 'n', long = "name", help = "Target name (e.g. 'John Smith')", value_name = "NAME")]
    pub name: Option<String>,

    #[arg(help_heading = "Generator Options", short = 'c', long = "company", help = "Company name", value_name = "COMPANY")]
    pub company: Option<String>,

    #[arg(help_heading = "Generator Options", short = 'd', long = "dob", help = "Date of birth (YYYY-MM-DD)", value_name = "DATE")]
    pub dob: Option<String>,

    #[arg(help_heading = "Generator Options", short = 'k', long = "keyword", help = "Additional keyword (repeatable)", value_name = "WORD")]
    pub keywords: Vec<String>,

    #[arg(help_heading = "Generator Options", long = "min-len", help = "Minimum password length", default_value = "4", value_name = "N")]
    pub min_len: usize,

    #[arg(help_heading = "Generator Options", long = "max-len", help = "Maximum password length", default_value = "32", value_name = "N")]
    pub max_len: usize,

    #[arg(help_heading = "Generator Options", long = "no-leet", help = "Disable leet speak variations")]
    pub no_leet: bool,

    #[arg(help_heading = "Generator Options", long = "leet-level", help = "Leet depth 0-3 (default 2)", value_name = "N", default_value = "2")]
    pub leet_level: u8,

    #[arg(help_heading = "Generator Options", long = "no-seasons", help = "Disable season bases")]
    pub no_seasons: bool,

    #[arg(help_heading = "Generator Options", long = "no-keyboard", help = "Disable keyboard-walk bases")]
    pub no_keyboard: bool,

    #[arg(help_heading = "Generator Options", short = 'F', long = "filename", help = "Custom filename (without extension) inside wordlists folder", value_name = "NAME")]
    pub filename: Option<String>,

    #[arg(help_heading = "Generator Options", long = "dir", help = "Custom output directory (default: ./wordlists/)", value_name = "DIR")]
    pub dir: Option<PathBuf>,

    #[arg(help_heading = "Output Options", short = 'o', long = "output", help = "Exact output file path (overrides --dir/--filename)", value_name = "FILE")]
    pub output: Option<PathBuf>,
}

#[derive(Parser, Debug)]
#[command(
    name = "veltrix",
    version = env!("CARGO_PKG_VERSION"),
    about = "\
VELTRIX v2.0 - Multi-Protocol Brute Force Toolkit - By AniipID

\u{26a0}  Authorized testing only. Unauthorized use is ILLEGAL.

47 protocols: ssh, ftp, telnet, smtp, pop3, imap, rdp, mysql, postgres,
ldap, redis, http, vnc, mongodb, mssql, smb, snmp, oracle, cassandra,
couchdb, elasticsearch, firebird, rabbitmq, activemq, kafka, sip, rtsp,
tomcat, jenkins, gitlab, sonarqube, docker, kubernetes, vault, consul,
vmware, ilo, ipmi, xmpp, irc, nntp, cvs, svn, rexec, rlogin, squid,
memcached + scan-ports, wordlist-gen, ML, distributed mode, combo,

High-performance brute force & security auditing platform with smart
credential merger (combines -u/-U and --password/-W automatically) and
real-time adaptive progress tracking for all 47 protocols.",
    long_about = concat!(
        "VELTRIX v2.0 - Multi-Protocol Brute Force Toolkit - By AniipID\n",
        "=========================================================\n\n",
        "High-performance brute force & security auditing platform.\n",
        "47 protocols · smart credential merging · adaptive progress tracking.\n\n",
        "[ Protocols ]\n",
        "  47 attack protocols:\n",
        "    ssh, ftp, telnet, smtp, pop3, imap, rdp, mysql, postgres,\n",
        "    ldap, redis, http, vnc, mongodb, mssql, smb, snmp, oracle,\n",
        "    cassandra, couchdb, elasticsearch, firebird, rabbitmq,\n",
        "    activemq, kafka, sip, rtsp, tomcat, jenkins, gitlab,\n",
        "    sonarqube, docker, kubernetes, vault, consul, vmware,\n",
        "    ilo, ipmi, xmpp, irc, nntp, cvs, svn, rexec, rlogin,\n",
        "    squid, memcached\n\n",
        "[ Features ]\n",
        "  - Smart credential merger: combine -u + -U, --password + -W\n",
        "  - Adaptive progress tracking (auto-extends on overflow)\n",
        "  - TCP port scanner with banner grabbing & service fingerprinting\n",
        "  - Wordlist generation from target information\n",
        "  - ML password prediction (Markov chain model)\n",
        "  - Distributed mode across multiple nodes\n",
        "  - Proxy rotation & chaining (HTTP, SOCKS4/5)\n",
        "  - Plugin system for custom protocol modules\n",
        "  - AES-256-GCM encryption for output files\n",
        "  - CIDR notation & IP range expansion\n",
        "  - Resume session support with checkpoint/restore\n",
        "  - Rate limiting, jitter delay, retry logic\n\n",
        "[ Usage Examples ]\n",
        "  veltrix ssh -t 192.168.1.1 -u admin -W passwords.txt\n",
        "  veltrix oracle -t 10.0.0.1:1521 -U users.txt -W pass.txt\n",
        "  veltrix kafka -t kafka.example.com:9092 -u admin -W pass.txt\n",
        "  veltrix kubernetes -t 10.0.0.1:6443 -U users.txt -W pass.txt\n",
        "  veltrix scan-ports -t 10.0.0.1 --ports 22,80,443\n\n",
        "[ CIDR & Range ]\n",
        "  veltrix ssh -t 192.168.1.0/24 -U users.txt -W passes.txt\n",
        "  veltrix ssh -t 10.0.0.1-10.0.0.10 -C combos.txt\n\n",
        "\u{26a0}  Authorized testing only. Unauthorized use is ILLEGAL."
    ),
    verbatim_doc_comment,
    subcommand_required = false,
    arg_required_else_help = true,
    override_usage = "veltrix <COMMAND> [OPTIONS]",
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    // ── Target ──
    #[arg(help_heading = "1 Target", short = 't', long = "target", help = "Target host:port or IP address (support domain/IP local/public)", value_name = "HOST[:PORT]", global = true)]
    pub targets: Vec<String>,

    #[arg(help_heading = "1 Target", short = 'l', long = "list", help = "File containing list of target hosts (one per line)", value_name = "FILE", global = true)]
    pub target_file: Option<PathBuf>,

    #[arg(help_heading = "1 Target", short = 'p', long = "port", help = "Port number(s)", value_name = "PORT", global = true)]
    pub ports: Vec<u16>,

    #[arg(help_heading = "1 Target", short = 'L', long = "list-protocols", help = "List supported protocols and exit", global = true)]
    pub list_protocols: bool,

    // ── Credentials ──
    #[arg(help_heading = "2 Credentials", short = 'u', long = "user", help = "Single username", value_name = "USER", global = true)]
    pub users: Vec<String>,

    #[arg(help_heading = "2 Credentials", short = 'U', long = "user-file", help = "File containing list of usernames (one per line)", value_name = "FILE", global = true)]
    pub user_file: Option<PathBuf>,

    #[arg(help_heading = "2 Credentials", short = 'w', long = "password", visible_alias = "pwd", help = "Single password (repeatable)", value_name = "PASS", global = true)]
    pub passwords: Vec<String>,

    #[arg(help_heading = "2 Credentials", short = 'W', long = "password-list", visible_alias = "pl", help = "File containing list of passwords (one per line)", value_name = "FILE", global = true)]
    pub password_file: Option<PathBuf>,

    #[arg(help_heading = "2 Credentials", short = 'C', long = "combo", help = "Combo list: user:pass per line", value_name = "FILE", global = true)]
    pub combo_file: Option<PathBuf>,

    // ── Performance ──
    #[arg(help_heading = "3 Performance", short = 'x', long = "threads", help = "Concurrent workers", default_value = "10", value_name = "N", global = true)]
    pub threads: usize,

    #[arg(help_heading = "3 Performance", long = "timeout", help = "Connection timeout (seconds)", default_value = "10", value_name = "SEC", global = true)]
    pub timeout: u64,

    #[arg(help_heading = "3 Performance", long = "delay", help = "Delay between attempts (ms)", default_value = "0", value_name = "MS", global = true)]
    pub delay: u64,

    #[arg(help_heading = "3 Performance", long = "rate-limit", help = "Max attempts/sec (0=unlimited)", value_name = "N", global = true)]
    pub rate_limit: Option<u64>,

    #[arg(help_heading = "3 Performance", long = "retries", help = "Connection retries", default_value = "2", value_name = "N", global = true)]
    pub retries: u32,

    #[arg(help_heading = "2 Credentials", long = "spray", help = "Spray mode: try one password across all users before next password (safer against lockout)", global = true)]
    pub spray: bool,

    #[arg(help_heading = "2 Credentials", long = "single-user", help = "Single-user mode: only first username is tested with all passwords", global = true)]
    pub single_user: bool,

    #[arg(help_heading = "4 Hybrid Rules", long = "rule", help = "Password mutation rule file", value_name = "FILE", global = true)]
    pub rule_file: Option<PathBuf>,

    #[arg(help_heading = "4 Hybrid Rules", long = "max-mutations", help = "Max rule mutations per password", default_value = "500", value_name = "N", global = true)]
    pub max_mutations: usize,

    #[arg(help_heading = "5 Session & Config", long = "resume", help = "Resume session file (checkpoint/restore)", value_name = "FILE", global = true)]
    pub resume: Option<PathBuf>,

    #[arg(help_heading = "5 Session & Config", long = "config", help = "Load base config from TOML or JSON file (CLI flags override file)", value_name = "FILE", global = true)]
    pub config_file: Option<PathBuf>,

    #[arg(help_heading = "6 Attack Control", long = "stop-on-first", help = "Stop after first success per target", global = true)]
    pub stop_on_first: bool,

    #[arg(help_heading = "3 Performance", long = "checkpoint", help = "Session checkpoint interval (attempts)", default_value = "100", value_name = "N", global = true)]
    pub checkpoint: u64,

    #[arg(help_heading = "6 Attack Control", long = "api-bind", help = "Deprecated: no effect on attacks; use `veltrix serve --bind ADDR` instead", value_name = "ADDR", global = true)]
    pub api_bind: Option<String>,

    #[arg(help_heading = "6 Attack Control", long = "fp-check", help = "Fingerprint check: re-verify claimed successes to eliminate false positives", global = true)]
    pub fp_check: bool,

    #[arg(help_heading = "6 Attack Control", long = "hide-secrets", visible_alias = "mask", help = "Mask passwords in console and reports (default: shown in full)", global = true)]
    pub hide_secrets: bool,

    #[arg(long = "show-secrets", hide = true, help = "Deprecated: passwords are shown by default; use --hide-secrets to mask", global = true)]
    pub show_secrets: bool,

    // ── F4: stealth, spray cadence, limiter, cooldown ──
    #[arg(help_heading = "7 Stealth & Evasion", long = "spray-interval", help = "Pause between spray rounds, e.g. 30s, 30m, 2h (requires --spray)", value_name = "DUR", default_value = "0", global = true)]
    pub spray_interval: String,

    #[arg(help_heading = "7 Stealth & Evasion", long = "spray-jitter", help = "Symmetric jitter percent 0-100 applied to spray interval", value_name = "PCT", default_value = "20", global = true)]
    pub spray_jitter: u8,

    #[arg(help_heading = "7 Stealth & Evasion", long = "target-rate-limit", help = "Max attempts/sec per target (in addition to global --rate-limit)", value_name = "N", global = true)]
    pub target_rate_limit: Option<u64>,

    #[arg(help_heading = "7 Stealth & Evasion", long = "user-cooldown", help = "Minimum interval between attempts for the same username, e.g. 500ms, 5s", value_name = "DUR", default_value = "0", global = true)]
    pub user_cooldown: String,

    #[arg(help_heading = "7 Stealth & Evasion", long = "lockout-cooldown", help = "Cooldown seconds after an account-lockout signal", value_name = "SEC", default_value = "600", global = true)]
    pub lockout_cooldown: u64,

    #[arg(help_heading = "7 Stealth & Evasion", long = "rate-cooldown", help = "Cooldown seconds after a rate-limit signal on a target", value_name = "SEC", default_value = "60", global = true)]
    pub rate_cooldown: u64,

    #[arg(help_heading = "7 Stealth & Evasion", long = "lockout-pause", help = "Pause for lockout-cooldown then retry instead of skipping the user", global = true)]
    pub lockout_pause: bool,

    #[arg(help_heading = "7 Stealth & Evasion", long = "user-agent", help = "Override HTTP User-Agent (default: rotate realistic pool)", value_name = "STR", global = true)]
    pub user_agent: Option<String>,

    #[arg(help_heading = "7 Stealth & Evasion", long = "safe-profile", help = "Conservative preset for production-like targets: threads 3, delay 1000ms, rate 5/s, retries 1, stop-on-first", global = true)]
    pub safe_profile: bool,

    #[arg(help_heading = "7 Stealth & Evasion", long = "aggressive-lab", help = "Aggressive preset for isolated labs only: threads 50, timeout 5s. Blocked for non-lab targets unless --i-understand-risk", global = true)]
    pub aggressive_lab: bool,

    #[arg(help_heading = "7 Stealth & Evasion", long = "i-understand-risk", help = "Acknowledge risk for aggressive runs against non-lab targets", global = true)]
    pub i_understand_risk: bool,

    // ── F5: scan-gated attack ──
    #[arg(help_heading = "6 Attack Control", long = "only-open", help = "Restrict attack targets to open ports listed in a scan-ports output file", value_name = "FILE", global = true)]
    pub only_open: Option<PathBuf>,

    #[arg(help_heading = "6 Attack Control", long = "max-password-len", help = "Truncate passwords to N characters", value_name = "N", global = true)]
    pub max_password_len: Option<usize>,

    // ── Proxy ──
    #[arg(help_heading = "8 Proxy & Anonymity", long = "proxy", help = "Proxy: type://host[:port]", value_name = "PROXY", global = true)]
    pub proxy: Option<String>,

    #[arg(help_heading = "8 Proxy & Anonymity", long = "proxy-file", help = "Proxy rotation list (one per line)", value_name = "FILE", global = true)]
    pub proxy_file: Option<PathBuf>,

    #[arg(help_heading = "8 Proxy & Anonymity", long = "proxy-chain", help = "Comma-separated proxy chain: type://host:port,...", value_name = "PROXIES", global = true)]
    pub proxy_chain: Option<String>,

    #[arg(help_heading = "8 Proxy & Anonymity", long = "proxy-required", help = "Fail-closed: abort if no proxy is configured (exit 2)", global = true)]
    pub proxy_required: bool,

    #[arg(help_heading = "8 Proxy & Anonymity", long = "rotate-proxy-every", help = "Rotate egress proxy every N attempts (0 = only on signal)", value_name = "N", default_value = "0", global = true)]
    pub rotate_proxy_every: usize,

    #[arg(help_heading = "7 Stealth & Evasion", long = "random-delay", help = "Extra random delay 0..N ms on top of --delay per attempt (anti-rhythm fingerprinting)", value_name = "MS", default_value = "100", global = true)]
    pub random_delay: u64,

    #[arg(help_heading = "8 Proxy & Anonymity", long = "check-proxy", help = "Pre-flight check: TCP-test every configured proxy and drop dead ones before attacking (fail-closed if all dead)", global = true)]
    pub check_proxy: bool,

    #[arg(help_heading = "8 Proxy & Anonymity", long = "source-ip", help = "Bind egress sockets to this local IP (VPN/multihomed anonymity)", value_name = "IP", global = true)]
    pub source_ip: Option<String>,

    // ── Output ──
    #[arg(help_heading = "9 Output & Reporting", short = 'o', long = "output", help = "Write results to FILE", value_name = "FILE", global = true)]
    pub output: Option<PathBuf>,

    #[arg(help_heading = "9 Output & Reporting", short = 'f', long = "format", help = "Output format: plain, json, csv, html, yaml", default_value = "plain", value_name = "FMT", global = true)]
    pub format: String,

    // ── Plugin ──
    #[arg(help_heading = "10 Plugins & Encryption", long = "plugin", help = "External plugin binary path (repeatable)", value_name = "PATH", global = true)]
    pub plugins: Vec<String>,

    #[arg(help_heading = "10 Plugins & Encryption", long = "list-plugin", help = "List all registered plugins and exit", global = true)]
    pub list_plugin: bool,

    // ── Encrypt ──
    #[arg(help_heading = "10 Plugins & Encryption", long = "encrypt", help = "Encrypt output file with AES-256-GCM", global = true)]
    pub encrypt: bool,

    #[arg(help_heading = "10 Plugins & Encryption", long = "encrypt-passphrase", help = "Passphrase for encryption (prompted if not provided)", value_name = "PASSPHRASE", global = true)]
    pub encrypt_passphrase: Option<String>,

    // ── Decrypt ──
    #[arg(help_heading = "10 Plugins & Encryption", long = "decrypt", help = "Decrypt an encrypted file", value_name = "FILE", global = true)]
    pub decrypt_file: Option<PathBuf>,

    #[arg(help_heading = "10 Plugins & Encryption", long = "decrypt-output", help = "Output path for decrypted file (default: stdout)", value_name = "FILE", global = true)]
    pub decrypt_output: Option<PathBuf>,

    // ── Wordlist Generation ──
    #[arg(help_heading = "11 Wordlist Generator", long = "gen-wordlist", help = "Generate a wordlist from target information", global = true)]
    pub gen_wordlist: bool,

    #[arg(help_heading = "11 Wordlist Generator", long = "wl-name", help = "Target name (e.g. 'John Smith')", value_name = "NAME", global = true)]
    pub wl_name: Option<String>,

    #[arg(help_heading = "11 Wordlist Generator", long = "wl-company", help = "Company name", value_name = "COMPANY", global = true)]
    pub wl_company: Option<String>,

    #[arg(help_heading = "11 Wordlist Generator", long = "wl-dob", help = "Date of birth (YYYY-MM-DD)", value_name = "DATE", global = true)]
    pub wl_dob: Option<String>,

    #[arg(help_heading = "11 Wordlist Generator", long = "wl-keyword", help = "Additional keyword (repeatable)", value_name = "WORD", global = true)]
    pub wl_keywords: Vec<String>,

    #[arg(help_heading = "11 Wordlist Generator", long = "wl-min-len", help = "Minimum password length", default_value = "4", value_name = "N", global = true)]
    pub wl_min_len: usize,

    #[arg(help_heading = "11 Wordlist Generator", long = "wl-max-len", help = "Maximum password length", default_value = "32", value_name = "N", global = true)]
    pub wl_max_len: usize,

    #[arg(help_heading = "11 Wordlist Generator", long = "wl-no-leet", help = "Disable leet speak variations", global = true)]
    pub wl_no_leet: bool,

    #[arg(help_heading = "11 Wordlist Generator", long = "wl-leet-level", help = "Leet depth 0-3 (0 off, 1 single, 2 combos, 3 +case)", value_name = "N", default_value = "2", global = true)]
    pub wl_leet_level: u8,

    #[arg(help_heading = "11 Wordlist Generator", long = "wl-no-seasons", help = "Disable season bases (spring/summer/...)", global = true)]
    pub wl_no_seasons: bool,

    #[arg(help_heading = "11 Wordlist Generator", long = "wl-no-keyboard", help = "Disable keyboard-walk bases (qwerty/123456/...)", global = true)]
    pub wl_no_keyboard: bool,

    #[arg(help_heading = "11 Wordlist Generator", long = "wl-output", help = "Write wordlist to file (default: stdout)", value_name = "FILE", global = true)]
    pub wl_output: Option<PathBuf>,

    // ── ML Password Prediction ──
    #[arg(help_heading = "12 ML Prediction", long = "ml-train", help = "Train Markov model on a wordlist file", value_name = "FILE", global = true)]
    pub ml_train: Option<PathBuf>,

    #[arg(help_heading = "12 ML Prediction", long = "ml-generate", help = "Generate N passwords from trained model (use after --ml-train)", value_name = "N", global = true)]
    pub ml_generate: Option<usize>,

    #[arg(help_heading = "12 ML Prediction", long = "ml-order", help = "Markov chain order (default: 3)", default_value = "3", value_name = "N", global = true)]
    pub ml_order: usize,

    #[arg(help_heading = "12 ML Prediction", long = "ml-max-len", help = "Max generated password length (default: 24)", default_value = "24", value_name = "N", global = true)]
    pub ml_max_len: usize,

    #[arg(help_heading = "12 ML Prediction", long = "ml-score", help = "Score password(s) from a file (one per line) against the trained model", value_name = "FILE", global = true)]
    pub ml_score: Option<PathBuf>,

    #[arg(help_heading = "12 ML Prediction", long = "ml-output", help = "Output file for generated passwords", value_name = "FILE", global = true)]
    pub ml_output: Option<PathBuf>,

    // ── Verbose ──
    #[arg(help_heading = "13 Verbosity", short = 'v', long = "verbose", action = clap::ArgAction::Count, help = "Verbose level 1 (-v) or verbose level 2 (-vv)", global = true)]
    pub verbose: u8,

    #[arg(help_heading = "13 Verbosity", short = 'q', long = "quiet", help = "Quiet mode: successes only, no progress dashboard", global = true)]
    pub quiet: bool,

    #[arg(help_heading = "6 Attack Control", long = "dry-run", help = "Show attack plan without sending any network traffic", global = true)]
    pub dry_run: bool,
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
            leet_level: self.wl_leet_level.min(3),
            seasons: !self.wl_no_seasons,
            keyboard: !self.wl_no_keyboard,
        }
    }

    pub fn should_show_banner(&self) -> bool {
        self.verbose > 0
    }

    pub fn build_attack_config(&self, protocol: &str, args: &ProtocolArgs) -> AttackConfig {
        use crate::utils::ratelimit::parse_interval_ms;        let fail_cfg = |e: String| -> ! {
            eprintln!("Config error: {}", e);
            std::process::exit(2);
        };
        let spray_interval = match parse_interval_ms(&self.spray_interval) {
            Ok(ms) => std::time::Duration::from_millis(ms),
            Err(e) => fail_cfg(format!("--spray-interval: {}", e)),
        };
        let user_cooldown = match parse_interval_ms(&self.user_cooldown) {
            Ok(ms) => std::time::Duration::from_millis(ms),
            Err(e) => fail_cfg(format!("--user-cooldown: {}", e)),
        };
        let source_ip = match parse_source_ip(&self.source_ip) {
            Ok(ip) => ip,
            Err(e) => fail_cfg(e),
        };
        // F4.5/F4.6: preset hanya mengisi field yang masih di nilai default clap,
        // sehingga flag eksplisit user selalu menang atas preset.
        let mut threads = self.threads;
        let mut timeout = self.timeout;
        let mut delay = self.delay;
        let mut rate_limit = self.rate_limit;
        let mut retries = self.retries;
        let mut stop_on_first = self.stop_on_first;
        if self.safe_profile {
            if threads == 10 { threads = 3; }
            if delay == 0 { delay = 1000; }
            if rate_limit.is_none() { rate_limit = Some(5); }
            if retries == 2 { retries = 1; }
            stop_on_first = true;
            log::info!("safe-profile applied (threads={}, delay={}ms, rate={:?}/s, retries={}, stop-on-first)",
                threads, delay, rate_limit, retries);
        }
        if self.aggressive_lab {
            if threads == 10 { threads = 50; }
            if timeout == 10 { timeout = 5; }
            log::warn!("aggressive-lab applied (threads={}, timeout={}s) - lab networks only", threads, timeout);
        }
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
            threads,
            timeout: std::time::Duration::from_secs(timeout),
            delay: std::time::Duration::from_millis(delay),
            rate_limit,
            proxy: self.proxy.clone(),
            proxy_file: self.proxy_file.clone(),
            proxy_chain: self.proxy_chain.clone(),
            proxy_required: self.proxy_required,
            rotate_proxy_every: self.rotate_proxy_every,
            source_ip,
            delay_jitter_ms: self.random_delay,
            check_proxy: self.check_proxy,
            output_file: self.output.clone(),
            output_format: OutputFormat::from_str(&self.format),
            resume_file: self.resume.clone(),
            config_file: self.config_file.clone(),
            checkpoint_interval: self.checkpoint,
            rdp_domain: args.rdp_domain.clone(),
            http_userfield: args.http_userfield.clone(),
            http_passfield: args.http_passfield.clone(),
            http_success: args.http_success.clone(),
            verbose: self.verbose,
            quiet: self.quiet,
            no_banner: false,
            single_user_mode: self.single_user,
            spray_mode: self.spray,
            stop_on_first,
            retries,
            rule_file: self.rule_file.clone(),
            max_mutations: self.max_mutations,
            max_password_len: self.max_password_len,
            distributed: None,
            distributed_token: None,
            distributed_name: None,
            plugins: self.plugins.clone(),
            api_bind: self.api_bind.clone(),
            encrypt: self.encrypt,
            encrypt_passphrase: self.encrypt_passphrase.clone(),
            decrypt_file: self.decrypt_file.clone(),
            decrypt_output: self.decrypt_output.clone(),
            dry_run: self.dry_run,
            fp_check: self.fp_check,
            // Default: password tampil penuh saat attack; --hide-secrets
            // untuk mask. Flag lama --show-secrets diterima (no-op).
            show_secrets: !self.hide_secrets,
            spray_interval,
            spray_jitter_pct: self.spray_jitter,
            target_rate_limit: self.target_rate_limit,
            user_cooldown,
            lockout_cooldown: std::time::Duration::from_secs(self.lockout_cooldown),
            rate_cooldown: std::time::Duration::from_secs(self.rate_cooldown),
            lockout_pause: self.lockout_pause,
            user_agent: self.user_agent.clone(),
            safe_profile: self.safe_profile,
            aggressive_lab: self.aggressive_lab,
            i_understand_risk: self.i_understand_risk,
            only_open: self.only_open.clone(),
        }
    }

    /// Terapkan file config (TOML/JSON) dengan prioritas CLI > file > default.
    /// Hanya field yang kosong/default di CLI yang diisi dari file.
    pub fn apply_config_file(&self, config: &mut AttackConfig) -> Result<bool, String> {
        let path = match self.config_file.as_ref().or(config.config_file.as_ref()) {
            Some(p) => p.clone(),
            None => return Ok(false),
        };
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        if ext == "toml" {
            let fc = crate::core::config_toml::TomlConfig::load(&path)
                .map_err(|e| format!("config {}: {}", path.display(), e))?;
            Self::merge_toml_with_cli_priority(&fc, config, &path);
        } else {
            let fc = crate::core::config_loader::ConfigFile::load(&path)
                .map_err(|e| format!("config {}: {}", path.display(), e))?;
            Self::merge_json_with_cli_priority(&fc, config);
        }
        config.config_file = Some(path);
        Ok(true)
    }

    fn merge_toml_with_cli_priority(
        fc: &crate::core::config_toml::TomlConfig,
        config: &mut AttackConfig,
        path: &std::path::Path,
    ) {
        use std::path::PathBuf as PB;
        if let Some(a) = fc.attack.as_ref() {
            if config.targets.is_empty() {
                if let Some(t) = a.targets.clone() { config.targets = t; }
            }
            if config.target_file.is_none() {
                if let Some(f) = a.target_file.clone() { config.target_file = Some(PB::from(f)); }
            }
            if config.protocols.len() <= 1 && config.protocols.first().map(|s| s == "ssh").unwrap_or(true) {
                // Biarkan protokol CLI (single) menang; file hanya dipakai jika CLI masih default implisit.
                // Untuk run_attack protokol selalu di-set dari subcommand, jadi jangan timpa di sini.
            }
            if config.ports.is_empty() {
                if let Some(p) = a.ports.clone() { config.ports = p; }
            }
        }
        if let Some(c) = fc.credentials.as_ref() {
            if config.users.is_empty() {
                if let Some(u) = c.users.clone() { config.users = u; }
            }
            if config.passwords.is_empty() {
                if let Some(p) = c.passwords.clone() { config.passwords = p; }
            }
            if config.user_file.is_none() {
                if let Some(f) = c.user_file.clone() { config.user_file = Some(PB::from(f)); }
            }
            if config.password_file.is_none() {
                if let Some(f) = c.password_file.clone() { config.password_file = Some(PB::from(f)); }
            }
            if config.combo_file.is_none() {
                if let Some(f) = c.combo_file.clone() { config.combo_file = Some(PB::from(f)); }
            }
            if !config.single_user_mode {
                if let Some(v) = c.single_user { config.single_user_mode = v; }
            }
            if !config.spray_mode {
                if let Some(v) = c.spray { config.spray_mode = v; }
            }
            if config.max_password_len.is_none() {
                if let Some(n) = c.max_password_len { config.max_password_len = Some(n); }
            }
            if config.rdp_domain.is_none() {
                if let Some(v) = c.rdp_domain.clone() { config.rdp_domain = Some(v); }
            }
            if config.http_userfield.is_none() {
                if let Some(v) = c.http_userfield.clone() { config.http_userfield = Some(v); }
            }
            if config.http_passfield.is_none() {
                if let Some(v) = c.http_passfield.clone() { config.http_passfield = Some(v); }
            }
            if config.http_success.is_none() {
                if let Some(v) = c.http_success.clone() { config.http_success = Some(v); }
            }
        }
        if let Some(h) = fc.hybrid.as_ref() {
            if config.rule_file.is_none() {
                if let Some(f) = h.rules.clone() { config.rule_file = Some(PB::from(f)); }
            }
            if config.max_mutations == 500 {
                if let Some(n) = h.max_mutations { config.max_mutations = n; }
            }
        }
        if let Some(p) = fc.performance.as_ref() {
            // Performance: CLI selalu menang karena punya default eksplisit.
            // File hanya dipakai jika user mengubah default file dari nilai umum.
            // Dokumentasikan sebagai CLI > file untuk field ini.
            let _ = (p, path);
        }
        if let Some(p) = fc.proxy.as_ref() {
            if config.proxy.is_none() {
                if let Some(s) = p.proxy.clone() { config.proxy = Some(s); }
            }
            if config.proxy_file.is_none() {
                if let Some(f) = p.proxy_file.clone() { config.proxy_file = Some(PB::from(f)); }
            }
            if config.proxy_chain.is_none() {
                if let Some(s) = p.proxy_chain.clone() { config.proxy_chain = Some(s); }
            }
        }
        if let Some(o) = fc.output.as_ref() {
            if config.output_file.is_none() {
                if let Some(f) = o.file.clone() { config.output_file = Some(PB::from(f)); }
            }
            if config.resume_file.is_none() {
                if let Some(f) = o.resume.clone() { config.resume_file = Some(PB::from(f)); }
            }
        }
        if let Some(b) = fc.behavior.as_ref() {
            if !config.stop_on_first {
                if let Some(v) = b.stop_on_first { config.stop_on_first = v; }
            }
        }
    }

    fn merge_json_with_cli_priority(
        fc: &crate::core::config_loader::ConfigFile,
        config: &mut AttackConfig,
    ) {
        use std::path::PathBuf as PB;
        if config.targets.is_empty() && !fc.attack.targets.is_empty() {
            config.targets = fc.attack.targets.clone();
        }
        if config.target_file.is_none() {
            if let Some(ref f) = fc.attack.target_file { config.target_file = Some(PB::from(f)); }
        }
        if config.ports.is_empty() && !fc.attack.ports.is_empty() {
            config.ports = fc.attack.ports.clone();
        }
        if config.users.is_empty() && !fc.credentials.users.is_empty() {
            config.users = fc.credentials.users.clone();
        }
        if config.passwords.is_empty() && !fc.credentials.passwords.is_empty() {
            config.passwords = fc.credentials.passwords.clone();
        }
        if config.user_file.is_none() {
            if let Some(ref f) = fc.credentials.user_file { config.user_file = Some(PB::from(f)); }
        }
        if config.password_file.is_none() {
            if let Some(ref f) = fc.credentials.password_file { config.password_file = Some(PB::from(f)); }
        }
        if config.combo_file.is_none() {
            if let Some(ref f) = fc.credentials.combo_file { config.combo_file = Some(PB::from(f)); }
        }
        if !config.single_user_mode && fc.credentials.single_user {
            config.single_user_mode = true;
        }
        if !config.spray_mode && fc.credentials.spray {
            config.spray_mode = true;
        }
        if config.max_password_len.is_none() {
            if let Some(n) = fc.credentials.max_password_len { config.max_password_len = Some(n); }
        }
        if config.rdp_domain.is_none() {
            if let Some(ref v) = fc.credentials.rdp_domain { config.rdp_domain = Some(v.clone()); }
        }
        if config.rule_file.is_none() {
            if let Some(ref f) = fc.hybrid.rules { config.rule_file = Some(PB::from(f)); }
        }
        if config.max_mutations == 500 {
            if let Some(n) = fc.hybrid.max_mutations { config.max_mutations = n; }
        }
        if config.proxy.is_none() {
            if let Some(ref s) = fc.proxy.proxy { config.proxy = Some(s.clone()); }
        }
        if config.proxy_file.is_none() {
            if let Some(ref f) = fc.proxy.proxy_file { config.proxy_file = Some(PB::from(f)); }
        }
        if config.proxy_chain.is_none() {
            if let Some(ref s) = fc.proxy.proxy_chain { config.proxy_chain = Some(s.clone()); }
        }
        if config.output_file.is_none() {
            if let Some(ref f) = fc.output.file { config.output_file = Some(PB::from(f)); }
        }
        if config.resume_file.is_none() {
            if let Some(ref f) = fc.output.resume { config.resume_file = Some(PB::from(f)); }
        }
        if !config.stop_on_first {
            if let Some(v) = fc.behavior.stop_on_first { config.stop_on_first = v; }
        }
    }
}

/// Parse --source-ip. None bila flag kosong. Exit-2 style error string.
pub fn parse_source_ip(s: &Option<String>) -> Result<Option<std::net::IpAddr>, String> {
    match s {
        None => Ok(None),
        Some(v) if v.trim().is_empty() => Ok(None),
        Some(v) => v
            .trim()
            .parse::<std::net::IpAddr>()
            .map(Some)
            .map_err(|_| format!("--source-ip: '{}' bukan alamat IP valid", v.trim())),
    }
}

pub fn port_to_protocol(port: u16) -> Option<&'static str> {    match port {
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
    let version = env!("CARGO_PKG_VERSION");
    let banner = format!(
        r#"
╔══════════════════════════════════════════════════════╗
║                  VELTRIX v{}                        ║
║           Multi-Protocol Brute Force Toolkit         ║
║            47 protocols · optimized · fast           ║
║                   By AniipID                         ║
╚══════════════════════════════════════════════════════╝
    "#,
        version
    );
    println!("{}", banner.yellow());
    println!("{}", "\u{26a0}  WARNING: Authorized testing only. Unauthorized use is ILLEGAL.".red().bold());
    println!();
}

pub fn print_manual() {
    // F2.5: header selalu sinkron dengan versi Cargo dan jumlah protokol registry.
    let version = env!("CARGO_PKG_VERSION");
    let proto_count = crate::protocols::list_protocols().len();
    println!(
        "{}",
        format!(
            "VELTRIX v{} COMPLETE USER MANUAL ({} protocols registered)",
            version, proto_count
        )
        .green()
        .bold()
    );
    println!(
        "{}",
        "Generated header. Body below is the maintained manual; use --help for authoritative flags.".dimmed()
    );
    println!();
    let manual = r#"Original manual body follows.
╔══════════════════════════════════════════════════════════════════════════════╗
║                       VELTRIX — COMPLETE USER MANUAL                         ║
║               Multi-Protocol Brute Force & Security Auditing Toolkit         ║
║                               By AniipID                                     ║
╚══════════════════════════════════════════════════════════════════════════════╝

────────────────────────────────────────────────────────────────────────────────
TABLE OF CONTENTS
────────────────────────────────────────────────────────────────────────────────
  1.  INTRODUCTION
  2.  INSTALLATION & SETUP
  3.  COMMAND SYNTAX
  4.  PROTOCOLS OVERVIEW (ALL 47)
  5.  CREDENTIAL MANAGEMENT
  6.  TARGET SPECIFICATION
  7.  PROXY & NETWORK OPTIONS
  8.  PERFORMANCE TUNING
  9.  OUTPUT & REPORTING
  10. ADVANCED FEATURES
  11. USE CASES & COMBINATIONS
  12. EXAMPLES
  13. TROUBLESHOOTING
  14. LEGAL NOTICE

────────────────────────────────────────────────────────────────────────────────
1. INTRODUCTION
────────────────────────────────────────────────────────────────────────────────

VELTRIX v2.0 is a high-performance multi-protocol brute force toolkit supporting
47 network protocols. It is designed for authorized security auditing, penetration
testing, and password strength assessment.

Key capabilities:
  • 47 protocol-specific brute force modules
  • Smart credential merging (combine -u + -U and --password + -W sources)
  • Adaptive progress tracking (no fixed upper limit on progress bar)
  • TCP port scanner with banner grabbing
  • Wordlist generation from personal/intelligence data
  • Markov chain ML password prediction
  • Distributed mode across multiple nodes
  • Proxy rotation & chaining (HTTP, SOCKS4/5)
  • Plugin system for custom protocol modules
  • AES-256-GCM encryption for output files
  • CIDR notation & IP range expansion
  • Resume session support with checkpoint/restore
  • Rate limiting, jitter delay, connection retry logic

────────────────────────────────────────────────────────────────────────────────
2. INSTALLATION & SETUP
────────────────────────────────────────────────────────────────────────────────

Pre-compiled binary:
  Place the veltrix binary in your PATH (/usr/local/bin/ or ~/.local/bin/)
  Ensure it has execute permissions: chmod +x veltrix

Build from source:
  Requirements: Rust toolchain (rustc, cargo)
  git clone <repo>
  cd veltrix
  cargo build --release
  cp target/release/veltrix /usr/local/bin/

Verify installation:
  veltrix --version
  veltrix --help

────────────────────────────────────────────────────────────────────────────────
3. COMMAND SYNTAX
────────────────────────────────────────────────────────────────────────────────

  veltrix <COMMAND> [GLOBAL_OPTIONS] [PROTOCOL_OPTIONS]

  <COMMAND>           One of: ssh, ftp, telnet, smtp, pop3, imap, rdp, mysql,
                      postgres, ldap, redis, http, vnc, mongodb, mssql, smb,
                      snmp, oracle, cassandra, couchdb, elasticsearch, firebird,
                      rabbitmq, activemq, kafka, sip, rtsp, tomcat, jenkins,
                      gitlab, sonarqube, docker, kubernetes, vault, consul,
                      vmware, ilo, ipmi, xmpp, irc, nntp, cvs, svn, rexec,
                      rlogin, squid, memcached,
                      scan-ports, auto, create, wordlist, check-ip, validate,
                      completion, serve, dist-coordinator, dist-worker, man

────────────────────────────────────────────────────────────────────────────────
4. PROTOCOLS OVERVIEW
────────────────────────────────────────────────────────────────────────────────

  Use: veltrix --list-protocols

  ┌────────────────────┬──────────────┬────────────────────────────────────┐
  │ Protocol           │ Default Port │ Auth Methods                       │
  ├────────────────────┼──────────────┼────────────────────────────────────┤
  │ ssh                │ 22           │ password, key                      │
  │ ftp                │ 21           │ plain, TLS/SSL                     │
  │ telnet             │ 23           │ plaintext                          │
  │ smtp               │ 25/465/587   │ LOGIN, PLAIN, CRAM-MD5, STARTTLS   │
  │ pop3               │ 110/995      │ USER/PASS, APOP, STLS              │
  │ imap               │ 143/993      │ LOGIN, PLAIN, CRAM-MD5, STARTTLS   │
  │ rdp                │ 3389         │ NLA, RDP Standard                  │
  │ mysql              │ 3306         │ mysql_native_password              │
  │ postgres           │ 5432         │ md5, cleartext, SSL                │
  │ ldap               │ 389/636      │ simple bind, LDAPS                 │
  │ redis              │ 6379/6380    │ AUTH, TLS                          │
  │ http               │ 80/443       │ Basic, Digest, Form                │
  │ vnc                │ 5900         │ VNC Auth                           │
  │ mongodb            │ 27017        │ SCRAM, MONGODB-CR                  │
  │ mssql              │ 1433         │ SQL Server Auth                    │
  │ smb                │ 445          │ NTLMv1/v2                          │
  │ snmp               │ 161          │ community strings (v1/v2c)         │
  │ oracle             │ 1521         │ password                           │
  │ cassandra          │ 9042         │ password                           │
  │ couchdb            │ 5984         │ basic, cookie                      │
  │ elasticsearch      │ 9200         │ basic, API key                     │
  │ firebird           │ 3050         │ password                           │
  │ rabbitmq           │ 5672         │ PLAIN, AMQPLAIN                    │
  │ activemq           │ 61616        │ password                           │
  │ kafka              │ 9092         │ SASL/PLAIN                         │
  │ sip                │ 5060         │ digest                             │
  │ rtsp               │ 554          │ basic, digest                      │
  │ tomcat             │ 8080         │ manager-gui                        │
  │ jenkins            │ 8080         │ basic, form                        │
  │ gitlab             │ 80/443       │ token, basic                       │
  │ sonarqube          │ 9000         │ token, basic                       │
  │ docker             │ 2375/2376    │ basic                              │
  │ kubernetes         │ 6443         │ token, basic                       │
  │ vault              │ 8200         │ token, LDAP                        │
  │ consul             │ 8500         │ token, basic                       │
  │ vmware             │ 443          │ password                           │
  │ ilo                │ 443          │ password                           │
  │ ipmi               │ 623          │ RMCP+                              │
  │ xmpp               │ 5222         │ PLAIN, SCRAM                       │
  │ irc                │ 6667         │ PASS                               │
  │ nntp               │ 119          │ AUTHINFO                           │
  │ cvs                │ 2401         │ password                           │
  │ svn                │ 3690         │ password                           │
  │ rexec              │ 512          │ password                           │
  │ rlogin             │ 513          │ password                           │
  │ squid              │ 3128         │ basic, NTLM                        │
  │ memcached          │ 11211        │ SASL                               │
  └────────────────────┴──────────────┴────────────────────────────────────┘

────────────────────────────────────────────────────────────────────────────────
5. CREDENTIAL MANAGEMENT
────────────────────────────────────────────────────────────────────────────────

Users — three modes (combined automatically when both specified):
  -u, --user USER           Single username (repeatable)
  -U, --user-file FILE       File with one username per line
  Both -u and -U can be used simultaneously; all users are merged.

Passwords — three modes (combined automatically when both specified):
  -w, --password, --pwd PASS Single password (repeatable)
  -W, --password-list FILE   File with one password per line
  Both -w/--password and -W can be used simultaneously; all passwords are merged.

Combo list (alternative to separate user/password files):
  -C, --combo FILE           user:pass pairs, one per line

Smart Credential Merging:
  All credential sources are intelligently merged. Duplicates are removed
  automatically. This allows combining targeted passwords from command-line
  with large wordlists from files.

  Examples:
    veltrix ssh -t 10.0.0.1 -u admin -u root -U users.txt \\
                --password pass123 -W passwords.txt

    This will create: (admin + root + users_from_file) × (pass123 + passes_from_file)

────────────────────────────────────────────────────────────────────────────────
6. TARGET SPECIFICATION
────────────────────────────────────────────────────────────────────────────────

  -t, --target HOST[:PORT]   Target host (repeatable for multiple targets)
  -l, --list FILE            File with target hosts, one per line
  -p, --port PORT            Port number (overrides protocol default)

  Target formats:
    • IP address:       192.168.1.1
    • Hostname:         server.example.com
    • Host:Port:        10.0.0.1:3306
    • CIDR range:       192.168.1.0/24
    • IP range:         10.0.0.1-10.0.0.10
    • Mixed:            targets.txt (one per line, any format)

  Port specification:
    • Protocol default port is used if -p is omitted
    • Multiple -p flags for multiple ports
    • Combined with targets for exhaustive scanning

────────────────────────────────────────────────────────────────────────────────
7. PROXY & NETWORK OPTIONS
────────────────────────────────────────────────────────────────────────────────

  --proxy PROXY              Single proxy: type://host[:port]
                               Types: http, socks4, socks5
                               Example: --proxy socks5://127.0.0.1:9050

  --proxy-file FILE          Proxy rotation list (one per line, same format)

  --proxy-chain PROXIES      Comma-separated chain:
                               http://proxy1:8080,socks5://proxy2:1080

  --timeout SEC              Connection timeout in seconds (default: 10)
  --retries N                Connection retry count (default: 1)
  --delay MS                 Delay between attempts in ms (default: 0)
  --rate-limit N             Max attempts per second (0 = unlimited)

  Protocol-specific options:
  --rdp-domain DOMAIN        RDP domain (prepended to username)
  --http-userfield FIELD     HTTP form username field name
  --http-passfield FIELD     HTTP form password field name
  --http-success TEXT        HTTP form success indicator string

────────────────────────────────────────────────────────────────────────────────
8. PERFORMANCE TUNING
────────────────────────────────────────────────────────────────────────────────

  -x, --threads N            Concurrent worker count (default: 10)
                               Higher = faster but more network load.
                               Start with 10, increase to 50-100 for LAN.

  --timeout SEC              Lower timeout = faster failures (default: 10)
                               Set to 3-5 for local networks, 10-15 for WAN.

  --rate-limit N             Throttle to N attempts/sec (default: unlimited)
                               Use 10-100 for rate-limited services.

  --delay MS                 Pause between attempts (default: 0)
                               Useful for avoiding lockout policies.

  --retries N                Retry failed connections (default: 1)
                               Set to 0 for speed, 2-3 for unreliable hosts.

  --max-password-len N       Truncate passwords longer than N characters
                               Speeds up testing of very long passwords.

  --stop-on-first            Stop after first success per target
                               Saves time when any valid credential is sufficient.

  Performance tips:
    • For LAN targets:  -x 50 --timeout 3 --retries 0
    • For WAN targets:  -x 10 --timeout 10 --retries 2
    • For lockout avoidance: --delay 1000 --rate-limit 5

────────────────────────────────────────────────────────────────────────────────
9. OUTPUT & REPORTING
────────────────────────────────────────────────────────────────────────────────

  -o, --output FILE          Write results to FILE
  -f, --format FMT           Output format (default: plain)
                               Formats:
                                 plain    Human-readable text
                                 json     JSON lines
                                 csv      Comma-separated values
                                 html     HTML report with visual formatting
                                 yaml     YAML structured output

  -v, --verbose              Verbosity level:
                               1x (-v)    Show failed attempts
                               2x (-vv)   Show debug info + rate stats
  -q, --quiet                Quiet mode: successes only, no progress dashboard

  --encrypt                  Encrypt output file with AES-256-GCM
  --encrypt-passphrase TEXT  Passphrase for encryption (prompted if omitted)

  --decrypt FILE             Decrypt an encrypted output file
  --decrypt-output FILE      Where to save decrypted output (default: stdout)

  --gen-wordlist             Generate wordlist mode (see wordlist-gen below)
  --list-protocols           List all supported protocols and exit
  --list-plugin              List registered plugin modules

────────────────────────────────────────────────────────────────────────────────
10. ADVANCED FEATURES
────────────────────────────────────────────────────────────────────────────────

10.1 WORDLIST GENERATION
─────────────────────────
  Generate targeted wordlists from personal information:

  --gen-wordlist             Activate wordlist generation mode
  --wl-name "John Smith"     Target's full name
  --wl-company "ACME Inc"    Company name
  --wl-dob 1990-01-15        Date of birth (YYYY-MM-DD)
  --wl-keyword WORD          Additional keyword (repeatable)
  --wl-min-len N             Minimum password length (default: 4)
  --wl-max-len N             Maximum password length (default: 32)
  --wl-no-leet               Disable leet speak (1337) variations
  --wl-output FILE           Save wordlist to file (default: stdout)

  Example:
    veltrix --gen-wordlist \\
      --wl-name "John Smith" --wl-company "ACME" \\
      --wl-dob 1985-06-20 --wl-keyword admin --wl-keyword server \\
      --wl-min-len 6 --wl-max-len 16 --wl-output john_wordlist.txt

10.2 ML PASSWORD PREDICTION
─────────────────────────────
  Train a Markov chain model on existing password lists to generate
  statistically likely passwords:

  --ml-train FILE            Train model on a wordlist file
  --ml-generate N            Generate N passwords from trained model
  --ml-order N               Markov chain order (default: 3)
                               Higher = more similarity to training data
  --ml-max-len N             Max generated password length (default: 24)
  --ml-score FILE            Score passwords from file against model
  --ml-output FILE           Save generated passwords to file

  Example:
    veltrix --ml-train passwords.txt --ml-generate 1000 \\
      --ml-order 4 --ml-max-len 20 --ml-output predicted.txt

10.3 PORT SCANNING
────────────────────
  veltrix scan-ports [OPTIONS] [GLOBAL_OPTIONS]

  Options:
    --ports SPEC             Port specification:
                               '22,80,443'      Specific ports
                               '1-1000'          Range
                               'common'          ~1200 common ports (default)
    --scan-timeout SEC       Per-port timeout (default: 3)
    --rate N                 Max concurrent scans (default: 500)
    --no-banner              Disable banner grabbing

  Example:
    veltrix scan-ports -t 10.0.0.1 --ports 1-10000 --rate 1000

10.4 DISTRIBUTED MODE
───────────────────────
  Split attack across multiple machines:

  Coordinator node:
    veltrix ssh -t 10.0.0.0/24 -U users.txt -W passes.txt \\
      --distributed coordinator://0.0.0.0:5555

  Worker nodes:
    veltrix ssh --distributed worker://<coordinator_ip>:5555

10.5 SESSION RESUME
─────────────────────
  Resume an interrupted attack using saved session state:

  veltrix ssh -t 10.0.0.1 -U users.txt -W passes.txt \\
    --resume session.dat

  The session saves progress periodically, allowing recovery from crashes
  or manual interruptions (Ctrl+C sends SIGINT which triggers safe save).

10.6 PLUGIN SYSTEM
────────────────────
  Load external protocol modules:

  --plugin /path/to/plugin   Load plugin binary (repeatable)
  --list-plugin              List all registered plugins

  Plugins must implement the Veltrix plugin interface (see docs/PLUGINS.md).

10.7 ENCRYPTION
─────────────────
  All output files can be encrypted with AES-256-GCM:

  veltrix ssh -t 10.0.0.1 -u admin -W passwords.txt \\
    -o results.txt --encrypt --encrypt-passphrase "s3cr3t"

  Decrypt later:
    veltrix --decrypt results.txt.enc --decrypt-output results.txt \\
      --encrypt-passphrase "s3cr3t"

10.8 CONFIGURATION FILES
────────────────────────────
  Use TOML configuration files for complex setups:

  veltrix ssh -c config.toml

  See the config.toml.example file in the repository for format details.

────────────────────────────────────────────────────────────────────────────────
11. USE CASES & COMBINATIONS
────────────────────────────────────────────────────────────────────────────────

11.1 SINGLE TARGET, SINGLE USER, PASSWORD FILE
──────────────────────────────────────────────────
  veltrix ssh -t 192.168.1.100 -u admin -W passwords.txt

11.2 MULTIPLE TARGETS, USER FILE, PASSWORD FILE
─────────────────────────────────────────────────────
  veltrix ssh -t 10.0.0.1 -t 10.0.0.2 -U users.txt -W passwords.txt

11.3 CIDR RANGE, COMBINED USER SOURCES
───────────────────────────────────────────────
  veltrix rdp -t 192.168.1.0/24 -u admin -u administrator -u root \\
    --password 'P@ssw0rd' --password 'Welcome1' -W common_pass.txt

11.4 ALL SOURCES COMBINED (SMART MERGE)
───────────────────────────────────────────────
  veltrix ssh -t 10.0.0.0/24 -u admin -U users.txt \\
    --password 'temp123' -W rockyou.txt -x 20 --timeout 5

  Credential total = (individual_users + file_users) × (individual_passes + file_passes)

11.5 PROXY CHAIN FOR ANONYMITY
────────────────────────────────────
  veltrix ftp -t 10.0.0.5 -U users.txt -W passes.txt \\
    --proxy-chain socks5://127.0.0.1:9050,http://proxy2:8080

11.6 FULL NETWORK AUDIT WORKFLOW
───────────────────────────────────────
  Step 1 — Port scan to discover services:
    veltrix scan-ports -t 10.0.0.0/24 --ports common -o scan.txt

  Step 2 — Wordlist generation from OSINT:
    veltrix --gen-wordlist --wl-name "Company X" --wl-keyword vpn \\
      --wl-output custom.txt

  Step 3 — Brute force each discovered service:
    veltrix ssh -t 10.0.0.1 -u admin -W custom.txt -o results.json -f json
    veltrix ftp -t 10.0.0.2 -U ftp_users.txt -W custom.txt
    veltrix mysql -t 10.0.0.3:3306 -U db_users.txt -W custom.txt

11.7 ML-ENHANCED ATTACK
─────────────────────────────────
  veltrix --ml-train rockyou.txt --ml-generate 5000 --ml-output ml_pass.txt
  veltrix ssh -t 10.0.0.1 -u admin -W ml_pass.txt

11.8 MULTI-PROTOCOL DISTRIBUTED ATTACK
─────────────────────────────────────────────
  Coordinator:
    veltrix ssh -t 10.0.0.0/24 -U users.txt -W passes.txt \\
      --distributed coordinator://0.0.0.0:5555

  Worker 1:
    veltrix --distributed worker://10.0.0.100:5555

  Worker 2:
    veltrix --distributed worker://10.0.0.101:5555

────────────────────────────────────────────────────────────────────────────────
12. QUICK REFERENCE — ALL OPTIONS
────────────────────────────────────────────────────────────────────────────────

  TARGET:
    -t, --target HOST[:PORT]     Target host (repeatable)
    -l, --list FILE              Target list file
    -p, --port PORT              Port number(s)

  CREDENTIALS:
    -u, --user USER              Single username (repeatable)
    -U, --user-file FILE         Username list file
    --password, --pwd PASS       Single password (repeatable)
    -W, --password-list FILE     Password list file
    -C, --combo FILE             User:pass combo file

  PERFORMANCE:
    -x, --threads N              Concurrent workers (default: 10)
    --timeout SEC                Connection timeout (default: 10)
    --delay MS                   Delay between attempts (default: 0)
    --rate-limit N               Max attempts/second (0 = unlimited)
    --retries N                  Connection retries (default: 1)
    --stop-on-first              Stop after first success per target
    --max-password-len N         Truncate passwords

  PROXY:
    --proxy PROXY                Proxy (type://host:port)
    --proxy-file FILE            Proxy rotation list
    --proxy-chain PROXIES        Proxy chain

  OUTPUT:
    -o, --output FILE            Output file
    -f, --format FMT             Format: plain, json, csv, html, yaml
    -v, --verbose                Verbose mode (-v, -vv)

  ENCRYPTION:
    --encrypt                    Encrypt output (AES-256-GCM)
    --encrypt-passphrase TEXT    Encryption passphrase
    --decrypt FILE               Decrypt encrypted file
    --decrypt-output FILE        Decrypted output path

  WORDLIST GENERATION:
    --gen-wordlist               Enable wordlist generation
    --wl-name TEXT               Target name
    --wl-company TEXT            Company name
    --wl-dob DATE                Date of birth
    --wl-keyword WORD            Additional keyword (repeatable)
    --wl-min-len N               Min length (default: 4)
    --wl-max-len N               Max length (default: 32)
    --wl-no-leet                 Disable leet speak
    --wl-output FILE             Output file

  ML:
    --ml-train FILE              Train model
    --ml-generate N              Generate N passwords
    --ml-order N                 Markov order (default: 3)
    --ml-max-len N               Max password length (default: 24)
    --ml-score FILE              Score passwords
    --ml-output FILE             Output file

  MISC:
    --list-protocols             List protocols
    --list-plugin                List plugins
    --plugin PATH                Load plugin (repeatable)
    --encrypt-passphrase TEXT    Passphrase
    --rdp-domain DOMAIN          RDP domain
    --http-userfield FIELD       HTTP form user field
    --http-passfield FIELD       HTTP form pass field
    --http-success TEXT          HTTP success indicator
    -c, --config FILE            Config file (TOML)

────────────────────────────────────────────────────────────────────────────────
13. TROUBLESHOOTING
────────────────────────────────────────────────────────────────────────────────

PROBLEM: "No valid targets after DNS resolution"
  SOLUTION: Ensure targets are reachable. Check DNS resolution and
  network connectivity. Use IP addresses instead of hostnames.

PROBLEM: "Failed to load credentials"
  SOLUTION: Verify file paths exist and are readable. Ensure files
  contain at least one non-empty, non-comment line.

PROBLEM: Connection timeout errors
  SOLUTION: Increase --timeout value. Check firewall rules. The target
  service must be listening on the specified port.

PROBLEM: Too many authentication failures / account locked out
  SOLUTION: Use --delay and --rate-limit to slow down. Consider
  password spraying (single password across many users) instead.

PROBLEM: Progress bar shows unusual numbers
  SOLUTION: The progress tracker is adaptive. It shows attempt count
  against a dynamic estimate. The bar will not stop at a fixed number.
  All combined credential sources (individual + files) are counted.

PROBLEM: "Permission denied" when running
  SOLUTION: Ensure binary has execute permissions: chmod +x veltrix

PROBLEM: "Thread pool panic" or crashes with large wordlists
  SOLUTION: Reduce -x threads. Large wordlists require more memory.
  Use --max-password-len to truncate very long entries.

────────────────────────────────────────────────────────────────────────────────
14. LEGAL NOTICE
────────────────────────────────────────────────────────────────────────────────

  ⚠  WARNING: This tool is for AUTHORIZED SECURITY TESTING ONLY.

  VELTRIX performs brute force authentication attacks against network services.
  Unauthorized use of this tool against systems you do not own or have explicit
  written permission to test is ILLEGAL and may violate:

    • Computer Fraud and Abuse Act (CFAA) — US
    • Computer Misuse Act 1990 — UK
    • Cybercrime Prevention Act — Philippines
    • Similar laws in other jurisdictions

  By using this tool you agree to:
    1. Only test systems you own or have written permission to test
    2. Comply with all applicable local, state, and federal laws
    3. Accept full responsibility for any consequences of misuse
    4. Not engage in unauthorized access or credential theft

  The developer provides this tool for educational purposes and authorized
  security research only. Misuse may result in criminal prosecution.

════════════════════════════════════════════════════════════════════════════════
              End of VELTRIX v2.0 User Manual — By AniipID
════════════════════════════════════════════════════════════════════════════════
"#;
    let _ = std::io::stdout().write_all(manual.as_bytes());
    let _ = std::io::stdout().flush();
}

pub fn print_protocols() {
    println!("{}", "Supported Protocols:".green().bold());
    println!("  {:<14} {:<14} {:<30}", "Protocol", "Default Port(s)", "Auth Methods");
    println!("  {:<14} {:<14} {:<30}", "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}", "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}", "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}");
    println!("  {:<14} {:<14} {:<30}", "ssh", "22", "password, key");
    println!("  {:<14} {:<14} {:<30}", "ftp", "21", "plain, TLS/SSL");
    println!("  {:<14} {:<14} {:<30}", "telnet", "23", "plaintext");
    println!("  {:<14} {:<14} {:<30}", "smtp", "25/465/587", "LOGIN, PLAIN, CRAM-MD5, STARTTLS");
    println!("  {:<14} {:<14} {:<30}", "pop3", "110/995", "USER/PASS, APOP, STLS");
    println!("  {:<14} {:<14} {:<30}", "imap", "143/993", "LOGIN, PLAIN, CRAM-MD5, STARTTLS");
    println!("  {:<14} {:<14} {:<30}", "rdp", "3389", "NLA, RDP Standard");
    println!("  {:<14} {:<14} {:<30}", "mysql", "3306", "mysql_native_password");
    println!("  {:<14} {:<14} {:<30}", "postgres", "5432", "md5, cleartext, SSL");
    println!("  {:<14} {:<14} {:<30}", "ldap", "389/636", "simple bind, LDAPS");
    println!("  {:<14} {:<14} {:<30}", "redis", "6379/6380", "AUTH, TLS");
    println!("  {:<14} {:<14} {:<30}", "http", "80/443", "Basic, Digest, Form");
    println!("  {:<14} {:<14} {:<30}", "vnc", "5900", "VNC Auth");
    println!("  {:<14} {:<14} {:<30}", "mongodb", "27017", "SCRAM, MONGODB-CR");
    println!("  {:<14} {:<14} {:<30}", "mssql", "1433", "SQL Server Auth");
    println!("  {:<14} {:<14} {:<30}", "smb", "445", "NTLMv1/v2");
    println!("  {:<14} {:<14} {:<30}", "snmp", "161", "community strings (v1/v2c)");
    println!("  {:<14} {:<14} {:<30}", "oracle", "1521", "password");
    println!("  {:<14} {:<14} {:<30}", "cassandra", "9042", "password");
    println!("  {:<14} {:<14} {:<30}", "couchdb", "5984", "basic, cookie");
    println!("  {:<14} {:<14} {:<30}", "elasticsearch", "9200", "basic, API key");
    println!("  {:<14} {:<14} {:<30}", "firebird", "3050", "password");
    println!("  {:<14} {:<14} {:<30}", "rabbitmq", "5672", "PLAIN, AMQPLAIN");
    println!("  {:<14} {:<14} {:<30}", "activemq", "61616", "password");
    println!("  {:<14} {:<14} {:<30}", "kafka", "9092", "SASL/PLAIN");
    println!("  {:<14} {:<14} {:<30}", "sip", "5060", "digest");
    println!("  {:<14} {:<14} {:<30}", "rtsp", "554", "basic, digest");
    println!("  {:<14} {:<14} {:<30}", "tomcat", "8080", "manager-gui");
    println!("  {:<14} {:<14} {:<30}", "jenkins", "8080", "basic, form");
    println!("  {:<14} {:<14} {:<30}", "gitlab", "80/443", "token, basic");
    println!("  {:<14} {:<14} {:<30}", "sonarqube", "9000", "token, basic");
    println!("  {:<14} {:<14} {:<30}", "docker", "2375/2376", "basic");
    println!("  {:<14} {:<14} {:<30}", "kubernetes", "6443", "token, basic");
    println!("  {:<14} {:<14} {:<30}", "vault", "8200", "token, LDAP");
    println!("  {:<14} {:<14} {:<30}", "consul", "8500", "token, basic");
    println!("  {:<14} {:<14} {:<30}", "vmware", "443", "password");
    println!("  {:<14} {:<14} {:<30}", "ilo", "443", "password");
    println!("  {:<14} {:<14} {:<30}", "ipmi", "623", "RMCP+");
    println!("  {:<14} {:<14} {:<30}", "xmpp", "5222", "PLAIN, SCRAM");
    println!("  {:<14} {:<14} {:<30}", "irc", "6667", "PASS");
    println!("  {:<14} {:<14} {:<30}", "nntp", "119", "AUTHINFO");
    println!("  {:<14} {:<14} {:<30}", "cvs", "2401", "password");
    println!("  {:<14} {:<14} {:<30}", "svn", "3690", "password");
    println!("  {:<14} {:<14} {:<30}", "rexec", "512", "password");
    println!("  {:<14} {:<14} {:<30}", "rlogin", "513", "password");
    println!("  {:<14} {:<14} {:<30}", "squid", "3128", "basic, NTLM");
    println!("  {:<14} {:<14} {:<30}", "memcached", "11211", "SASL");
    println!();
}
