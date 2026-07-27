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
    version = "1.2.0",
    about = "\
VELTRIX v1.2 - Multi-Protocol Brute Force Toolkit - By AniipID

\u{26a0}  Authorized testing only. Unauthorized use is ILLEGAL.

47 protocols: ssh, ftp, telnet, smtp, pop3, imap, rdp, mysql, postgres,
ldap, redis, http, vnc, mongodb, mssql, smb, snmp, oracle, cassandra,
couchdb, elasticsearch, firebird, rabbitmq, activemq, kafka, sip, rtsp,
tomcat, jenkins, gitlab, sonarqube, docker, kubernetes, vault, consul,
vmware, ilo, ipmi, xmpp, irc, nntp, cvs, svn, rexec, rlogin, squid,
memcached + scan-ports, wordlist-gen, ML, distributed mode.",
    long_about = concat!(
        "VELTRIX v1.2 - Multi-Protocol Brute Force Toolkit - By AniipID\n",
        "=========================================================\n\n",
        "High-performance brute force & security auditing tool (47 protocols).\n\n",
        "  - 47 attack protocols (ssh, ftp, telnet, smtp, pop3, imap, rdp,\n",
        "    mysql, postgres, ldap, redis, http, vnc, mongodb, mssql, smb,\n",
        "    snmp, oracle, cassandra, couchdb, elasticsearch, firebird,\n",
        "    rabbitmq, activemq, kafka, sip, rtsp, tomcat, jenkins, gitlab,\n",
        "    sonarqube, docker, kubernetes, vault, consul, vmware, ilo, ipmi,\n",
        "    xmpp, irc, nntp, cvs, svn, rexec, rlogin, squid, memcached)\n",
        "  - TCP port scanner with banner grabbing\n",
        "  - Wordlist generation & ML password prediction\n",
        "  - Distributed mode across multiple nodes\n",
        "  - Proxy rotation & chaining (HTTP, SOCKS4/5)\n",
        "  - Plugin system, AES-256-GCM encryption, CIDR\n\n",
        "Examples:\n",
        "  veltrix ssh -t 192.168.1.1 -u admin -W passwords.txt\n",
        "  veltrix oracle -t 10.0.0.1:1521 -U users.txt -W pass.txt\n",
        "  veltrix kafka -t kafka.example.com:9092 -u admin -W pass.txt\n",
        "  veltrix kubernetes -t 10.0.0.1:6443 -U users.txt -W pass.txt\n",
        "  veltrix scan-ports -t 10.0.0.1 --ports 22,80,443\n\n",
        "CIDR & Range:\n",
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

    #[arg(short = 'f', long = "format", help = "Output format: plain, json, csv, html, yaml", default_value = "plain", value_name = "FMT", global = true)]
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
║                  VELTRIX v1.2                        ║
║           Multi-Protocol Brute Force Toolkit         ║
║            47 protocols · optimized · fast           ║
║                   By AniipID                         ║
╚══════════════════════════════════════════════════════╝
    "#;
    println!("{}", banner.yellow());
    println!("{}", "\u{26a0}  WARNING: Authorized testing only. Unauthorized use is ILLEGAL.".red().bold());
    println!();
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
