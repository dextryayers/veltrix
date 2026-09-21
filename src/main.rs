mod api;
mod cli;
mod core;
mod distributed;
mod protocols;
mod proxy;
mod scanner;
mod utils;

use std::path::PathBuf;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use clap::{CommandFactory, Parser};
use cli::{print_banner, print_protocols, print_manual, Cli, Commands, ProtocolArgs, CreateArgs};
use core::attack::AttackOrchestrator;
use crate::utils::wordlist_gen::{WordlistConfig, generate_wordlist};
use colored::Colorize;


/// Exit codes standar v2:
/// 0 = sukses ada temuan, 1 = tidak ada temuan atau runtime gagal,
/// 2 = config invalid, 130 = interrupted paksa.
pub const EXIT_FOUND: i32 = 0;
pub const EXIT_NOT_FOUND: i32 = 1;
pub const EXIT_CONFIG: i32 = 2;
pub const EXIT_INTERRUPTED: i32 = 130;

pub fn exit_config(msg: &str) -> ! {
    eprintln!("Config error: {}", msg);
    std::process::exit(EXIT_CONFIG);
}

#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    if cli.list_protocols {
        print_protocols();
        return;
    }

    if cli.list_plugin {
        let plugins = crate::core::plugin::list_plugins();
        if plugins.is_empty() {
            println!("No plugins registered.");
        } else {
            println!("Registered plugins:");
            for p in &plugins {
                println!("  {}", p);
            }
        }
        return;
    }

    if cli.gen_wordlist {
        let cfg = cli.to_wordlist_config();
        let words = crate::utils::wordlist_gen::generate_wordlist(&cfg);
        match cli.wl_output {
            Some(path) => {
                let content = words.iter().cloned().collect::<Vec<_>>().join("\n");
                std::fs::write(&path, &content).unwrap_or_else(|e| {
                    eprintln!("Failed to write wordlist: {}", e);
                    std::process::exit(1);
                });
                log::info!("Generated {} candidates -> {}", words.len(), path.display());
            }
            None => {
                for w in &words {
                    println!("{}", w);
                }
                eprintln!("[+] Generated {} candidates", words.len());
            }
        }
        return;
    }

    if let Some(ref train_path) = cli.ml_train {
        let data = std::fs::read_to_string(train_path).unwrap_or_else(|e| {
            eprintln!("Failed to read training file: {}", e);
            std::process::exit(1);
        });
        let passwords: Vec<String> = data.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
        let mut mc = crate::utils::ml_predict::MarkovChain::new(cli.ml_order);
        mc.train(&passwords);
        log::info!("Trained Markov model (order={}) on {} passwords", cli.ml_order, passwords.len());

        if let Some(count) = cli.ml_generate {
            let generated = mc.generate_many(count, cli.ml_max_len);
            match cli.ml_output {
                Some(ref path) => {
                    std::fs::write(path, generated.join("\n")).unwrap_or_else(|e| {
                        eprintln!("Failed to write ML output: {}", e);
                        std::process::exit(1);
                    });
                    log::info!("Generated {} passwords -> {}", generated.len(), path.display());
                }
                None => {
                    for w in &generated {
                        println!("{}", w);
                    }
                    eprintln!("[+] ML generated {} passwords", generated.len());
                }
            }
        }

        if let Some(ref score_path) = cli.ml_score {
            let data = std::fs::read_to_string(score_path).unwrap_or_else(|e| {
                eprintln!("Failed to read score file: {}", e);
                std::process::exit(1);
            });
            for line in data.lines() {
                let line = line.trim();
                if !line.is_empty() {
                    let score = mc.complexity_score(line);
                    println!("{}: {:.4}", line, score);
                }
            }
        }

        if cli.ml_generate.is_some() || cli.ml_score.is_some() {
            return;
        }
    }

    if let Some(ref decrypt_path) = cli.decrypt_file {
        let passphrase = match cli.encrypt_passphrase.as_deref() {
            Some(p) => p.to_string(),
            None => {
                eprint!("Enter decryption passphrase: ");
                std::io::stdout().flush().ok();
                rpassword::read_password().unwrap_or_default()
            }
        };
        match &cli.decrypt_output {
            Some(output_path) => {
                match crate::utils::encrypt::decrypt_to_file(decrypt_path, output_path, &passphrase) {
                    Ok(_) => {
                        log::info!("Decrypted {} -> {}", decrypt_path.display(), output_path.display());
                        std::process::exit(0);
                    }
                    Err(e) => {
                        eprintln!("Decryption failed: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            None => {
                match crate::utils::encrypt::read_decrypted(decrypt_path, &passphrase) {
                    Ok(data) => {
                        std::io::stdout().write_all(&data).ok();
                        std::process::exit(0);
                    }
                    Err(e) => {
                        eprintln!("Decryption failed: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        }
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        if r.load(Ordering::SeqCst) {
            eprintln!("\n[!] SIGINT received. Finishing current attempts and saving session...");
            r.store(false, Ordering::SeqCst);
        } else {
            eprintln!("\n[!] Forced exit.");
            std::process::exit(EXIT_INTERRUPTED);
        }
    }).expect("Failed to set SIGINT handler");

    match cli.command {
        Some(Commands::ScanPorts(ref args)) => run_scan(&cli, args, running).await,
        Some(Commands::Auto(ref args)) => run_auto(&cli, args, running).await,
        Some(Commands::Ssh(ref a)) => run_attack(&cli, "ssh", a, running).await,
        Some(Commands::Ftp(ref a)) => run_attack(&cli, "ftp", a, running).await,
        Some(Commands::Telnet(ref a)) => run_attack(&cli, "telnet", a, running).await,
        Some(Commands::Smtp(ref a)) => run_attack(&cli, "smtp", a, running).await,
        Some(Commands::Pop3(ref a)) => run_attack(&cli, "pop3", a, running).await,
        Some(Commands::Imap(ref a)) => run_attack(&cli, "imap", a, running).await,
        Some(Commands::Rdp(ref a)) => run_attack(&cli, "rdp", a, running).await,
        Some(Commands::Mysql(ref a)) => run_attack(&cli, "mysql", a, running).await,
        Some(Commands::Postgres(ref a)) => run_attack(&cli, "postgres", a, running).await,
        Some(Commands::Ldap(ref a)) => run_attack(&cli, "ldap", a, running).await,
        Some(Commands::Redis(ref a)) => run_attack(&cli, "redis", a, running).await,
        Some(Commands::Http(ref a)) => run_attack(&cli, "http", a, running).await,
        Some(Commands::Vnc(ref a)) => run_attack(&cli, "vnc", a, running).await,
        Some(Commands::Mongodb(ref a)) => run_attack(&cli, "mongodb", a, running).await,
        Some(Commands::Mssql(ref a)) => run_attack(&cli, "mssql", a, running).await,
        Some(Commands::Smb(ref a)) => run_attack(&cli, "smb", a, running).await,
        Some(Commands::Snmp(ref a)) => run_attack(&cli, "snmp", a, running).await,
        Some(Commands::Oracle(ref a)) => run_attack(&cli, "oracle", a, running).await,
        Some(Commands::Cassandra(ref a)) => run_attack(&cli, "cassandra", a, running).await,
        Some(Commands::Couchdb(ref a)) => run_attack(&cli, "couchdb", a, running).await,
        Some(Commands::Elasticsearch(ref a)) => run_attack(&cli, "elasticsearch", a, running).await,
        Some(Commands::Firebird(ref a)) => run_attack(&cli, "firebird", a, running).await,
        Some(Commands::Rabbitmq(ref a)) => run_attack(&cli, "rabbitmq", a, running).await,
        Some(Commands::Activemq(ref a)) => run_attack(&cli, "activemq", a, running).await,
        Some(Commands::Kafka(ref a)) => run_attack(&cli, "kafka", a, running).await,
        Some(Commands::Sip(ref a)) => run_attack(&cli, "sip", a, running).await,
        Some(Commands::Rtsp(ref a)) => run_attack(&cli, "rtsp", a, running).await,
        Some(Commands::Tomcat(ref a)) => run_attack(&cli, "tomcat", a, running).await,
        Some(Commands::Jenkins(ref a)) => run_attack(&cli, "jenkins", a, running).await,
        Some(Commands::Gitlab(ref a)) => run_attack(&cli, "gitlab", a, running).await,
        Some(Commands::Sonarqube(ref a)) => run_attack(&cli, "sonarqube", a, running).await,
        Some(Commands::Docker(ref a)) => run_attack(&cli, "docker", a, running).await,
        Some(Commands::Kubernetes(ref a)) => run_attack(&cli, "kubernetes", a, running).await,
        Some(Commands::Vault(ref a)) => run_attack(&cli, "vault", a, running).await,
        Some(Commands::Consul(ref a)) => run_attack(&cli, "consul", a, running).await,
        Some(Commands::Vmware(ref a)) => run_attack(&cli, "vmware", a, running).await,
        Some(Commands::Ilo(ref a)) => run_attack(&cli, "ilo", a, running).await,
        Some(Commands::Ipmi(ref a)) => run_attack(&cli, "ipmi", a, running).await,
        Some(Commands::Xmpp(ref a)) => run_attack(&cli, "xmpp", a, running).await,
        Some(Commands::Irc(ref a)) => run_attack(&cli, "irc", a, running).await,
        Some(Commands::Nntp(ref a)) => run_attack(&cli, "nntp", a, running).await,
        Some(Commands::Cvs(ref a)) => run_attack(&cli, "cvs", a, running).await,
        Some(Commands::Svn(ref a)) => run_attack(&cli, "svn", a, running).await,
        Some(Commands::Rexec(ref a)) => run_attack(&cli, "rexec", a, running).await,
        Some(Commands::Rlogin(ref a)) => run_attack(&cli, "rlogin", a, running).await,
        Some(Commands::Squid(ref a)) => run_attack(&cli, "squid", a, running).await,
        Some(Commands::Memcached(ref a)) => run_attack(&cli, "memcached", a, running).await,
        Some(Commands::Man) | Some(Commands::How) => print_manual(),
        Some(Commands::Create(ref a)) => run_create(a).await,
        Some(Commands::Validate(ref a)) => run_validate(a),
        Some(Commands::Completion(ref a)) => run_completion(a),
        None => {
            print_banner();
            println!("{}", "Use --help or -h for usage information.".dimmed());
        }
    }
}

async fn run_scan(cli: &Cli, args: &cli::ScanPortsArgs, running: Arc<AtomicBool>) {
    print_banner();

    let hosts = if !cli.targets.is_empty() {
        cli.targets.clone()
    } else if let Some(ref file) = cli.target_file {
        std::fs::read_to_string(file)
            .unwrap_or_else(|e| {
                eprintln!("Failed to read target file: {}", e);
                std::process::exit(1);
            })
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    } else {
        eprintln!("No targets specified. Use -t or --list.");
        std::process::exit(1);
    };

    let ports = match args.port_spec.as_deref() {
        Some("common") | None => crate::scanner::scanner::common_ports(),
        Some(spec) => match crate::scanner::scanner::parse_port_spec(spec) {
            Ok(p) => p,
            Err(e) => exit_config(&format!("invalid port specification: {}", e)),
        },
    };

    let config = crate::scanner::scanner::ScanConfig {
        hosts,
        ports,
        timeout_secs: args.scan_timeout,
        max_concurrent: args.scan_rate,
        banner_grab: !args.no_banner,
        retries: 0,
        show_progress: true,
    };

    let scanner = crate::scanner::Scanner::new(config, running.clone());
    let results = scanner.scan().await;

    crate::scanner::print_scan_results(&results);

    if let Some(ref path) = cli.output {
        let mut file = std::fs::File::create(path)
            .unwrap_or_else(|e| { eprintln!("Failed to create output file: {}", e); std::process::exit(1); });
        let open_count = results.iter().filter(|r| r.open).count();
        writeln!(file, "Veltrix Scan Results - {} hosts, {} open ports", results.len(), open_count).ok();
        for r in &results {
            if r.open {
                writeln!(file, "{}\t{}\t{}\t{:?}\t{:?}\t{}ms",
                    r.host, r.port, r.service, r.product, r.version, r.latency_ms).ok();
            }
        }
        log::info!("Scan results saved to {}", path.display());
    }

    let open_ports: Vec<_> = results.iter().filter(|r| r.open).collect();
    if open_ports.is_empty() {
        std::process::exit(1);
    } else {
        std::process::exit(0);
    }
}

#[derive(serde::Serialize)]
struct AutoFoundCred {
    host: String,
    port: u16,
    user: String,
    pass: String,
}

#[derive(serde::Serialize)]
struct AutoGroupReport {
    protocol: String,
    port: u16,
    targets: Vec<String>,
    confidence: u8,
    reason: String,
    attempts: u64,
    successes: u64,
    failures: u64,
    errors: u64,
    found: Vec<AutoFoundCred>,
}

#[derive(serde::Serialize)]
struct AutoReport {
    tool: String,
    version: String,
    scan_id: String,
    started_at: String,
    targets: Vec<String>,
    ports_scanned: usize,
    open_ports: usize,
    groups: Vec<AutoGroupReport>,
    total_successes: u64,
}

/// F5.2/F5.4: scan, fingerprint, attack hanya service terbuka yang didukung.
async fn run_auto(cli: &Cli, args: &cli::AutoArgs, running: Arc<AtomicBool>) {
    use std::collections::BTreeMap;
    print_banner();

    let scan_id = uuid::Uuid::new_v4().to_string();
    let started_at = chrono::Utc::now().to_rfc3339();

    // Target & port: logika sama seperti run_scan.
    let hosts = if !cli.targets.is_empty() {
        cli.targets.clone()
    } else if let Some(ref file) = cli.target_file {
        std::fs::read_to_string(file)
            .unwrap_or_else(|e| {
                eprintln!("Failed to read target file: {}", e);
                std::process::exit(1);
            })
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    } else {
        eprintln!("No targets specified. Use -t or --list.");
        std::process::exit(EXIT_CONFIG);
    };
    let ports = match args.scan.port_spec.as_deref() {
        Some("common") | None => crate::scanner::scanner::common_ports(),
        Some(spec) => match crate::scanner::scanner::parse_port_spec(spec) {
            Ok(p) => p,
            Err(e) => exit_config(&format!("invalid port specification: {}", e)),
        },
    };

    let policy = match args.policy.as_ref() {
        Some(p) => match crate::scanner::AutoPolicy::load(p) {
            Ok(pol) => pol,
            Err(e) => exit_config(&e.to_string()),
        },
        None => crate::scanner::AutoPolicy::default(),
    };
    let min_conf = args.min_confidence.unwrap_or_else(|| policy.min_confidence()).min(100);

    // 1. Scan.
    let scan_config = crate::scanner::scanner::ScanConfig {
        hosts: hosts.clone(),
        ports: ports.clone(),
        timeout_secs: args.scan.scan_timeout,
        max_concurrent: args.scan.scan_rate,
        banner_grab: !args.scan.no_banner,
        retries: 0,
        show_progress: true,
    };
    let scanner = crate::scanner::Scanner::new(scan_config, running.clone());
    let results = scanner.scan().await;
    crate::scanner::print_scan_results(&results);

    // 2. Fingerprint + grouping.
    let db = crate::scanner::ServiceDb::new();
    // (proto, port) -> (hosts, best_conf, reason)
    let mut groups: BTreeMap<(String, u16), (Vec<String>, u8, String)> = BTreeMap::new();
    let mut skipped = 0usize;
    for r in results.iter().filter(|r| r.open) {
        let ident = crate::scanner::service_db::identify_attack(
            &db,
            r.port,
            r.banner.as_deref().unwrap_or(""),
            r.product.as_deref(),
        );
        match ident {
            Some((proto, conf, reason)) if conf >= min_conf => {
                if !policy.allows_protocol(&proto) {
                    log::warn!("auto: {}:{} protocol {} blocked by policy", r.host, r.port, proto);
                    skipped += 1;
                    continue;
                }
                if !policy.allows_host(&r.host) {
                    log::warn!("auto: host {} blocked by policy subnets", r.host);
                    skipped += 1;
                    continue;
                }
                let e = groups
                    .entry((proto.clone(), r.port))
                    .or_insert_with(|| (Vec::new(), 0, reason.clone()));
                if !e.0.contains(&r.host) {
                    e.0.push(r.host.clone());
                }
                if conf > e.1 {
                    e.1 = conf;
                    e.2 = reason.clone();
                }
            }
            Some((proto, conf, _)) => {
                log::info!("auto: {}:{} {} confidence {} below minimum {}", r.host, r.port, proto, conf, min_conf);
                skipped += 1;
            }
            None => {
                log::info!("auto: {}:{} service '{}' has no attack module, skipped", r.host, r.port, r.service);
                skipped += 1;
            }
        }
    }

    if groups.is_empty() {
        eprintln!("auto: no attackable open services ({} skipped). Nothing to do.", skipped);
        std::process::exit(EXIT_NOT_FOUND);
    }

    println!("  {} {} attack group(s), {} skipped",
        "auto:".cyan().bold(),
        groups.len(),
        skipped,
    );
    for ((proto, port), (hosts, conf, reason)) in &groups {
        println!("    - {}:{} hosts={} conf={} ({})", proto, port, hosts.len(), conf, reason);
    }

    // 3. Attack per grup.
    let empty_proto = ProtocolArgs {
        rdp_domain: None,
        http_userfield: None,
        http_passfield: None,
        http_success: None,
    };
    let mut group_reports = Vec::new();
    for ((proto, port), (hosts, conf, reason)) in groups {
        let mut config = cli.build_attack_config(&proto, &empty_proto);
        if let Some(m) = policy.max_threads {
            if config.threads > m {
                log::info!("auto: clamping threads {} -> {} per policy", config.threads, m);
                config.threads = m;
            }
        }
        config.targets = hosts.iter().map(|h| format!("{}:{}", h, port)).collect();
        config.protocols = vec![proto.clone()];
        config.output_file = None; // laporan gabungan ditulis sekali di akhir
        if let Err(e) = config.validate() {
            eprintln!("auto: skipping group {}:{}: {}", proto, port, e);
            continue;
        }
        for w in config.risk_warnings() {
            eprintln!("warning: {}", w);
        }
        let mut orch = match AttackOrchestrator::new(config, running.clone()).await {
            Ok(o) => o,
            Err(e) => {
                eprintln!("auto: cannot start group {}:{}: {}", proto, port, e);
                continue;
            }
        };
        let summary = orch.run().await;
        group_reports.push(AutoGroupReport {
            protocol: proto.clone(),
            port,
            targets: hosts.clone(),
            confidence: conf,
            reason: reason.clone(),
            attempts: summary.attempts,
            successes: summary.successes,
            failures: summary.failures,
            errors: summary.errors,
            found: summary
                .results
                .iter()
                .filter(|r| r.success)
                .map(|r| AutoFoundCred {
                    host: r.target_host.clone(),
                    port: r.target_port,
                    user: r.username.clone(),
                    pass: r.password.clone(),
                })
                .collect(),
        });
        if !running.load(Ordering::SeqCst) {
            eprintln!("auto: interrupted, stopping after current group.");
            break;
        }
    }

    // 4. Laporan gabungan (F5.4).
    let total_successes: u64 = group_reports.iter().map(|g| g.successes).sum();
    let open_ports = results.iter().filter(|r| r.open).count();
    let report = AutoReport {
        tool: "veltrix-auto".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        scan_id,
        started_at,
        targets: hosts,
        ports_scanned: ports.len(),
        open_ports,
        groups: group_reports,
        total_successes,
    };
    write_auto_report(cli, &report);

    if cli.dry_run {
        std::process::exit(EXIT_FOUND);
    }
    if total_successes > 0 {
        std::process::exit(EXIT_FOUND);
    } else {
        std::process::exit(EXIT_NOT_FOUND);
    }
}

fn write_auto_report(cli: &Cli, report: &AutoReport) {
    let as_json = cli.format.eq_ignore_ascii_case("json")
        || cli
            .output
            .as_ref()
            .and_then(|p| p.extension())
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("json"))
            .unwrap_or(false);
    let body = if as_json {
        serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".into())
    } else {
        let mut s = format!(
            "Veltrix Auto Report v{} scan={} groups={} successes={}\n",
            report.version, report.scan_id, report.groups.len(), report.total_successes
        );
        for g in &report.groups {
            s.push_str(&format!(
                "- {}:{} hosts={} conf={} attempts={} found={} ({})\n",
                g.protocol, g.port, g.targets.len(), g.confidence, g.attempts, g.successes, g.reason
            ));
            for f in &g.found {
                s.push_str(&format!("    FOUND {}:{} [{}:{}]\n", f.host, f.port, f.user, f.pass));
            }
        }
        s
    };
    match cli.output.as_ref() {
        Some(path) => {
            if let Err(e) = std::fs::write(path, &body) {
                eprintln!("Failed to write auto report: {}", e);
            } else {
                log::info!("Auto report saved to {}", path.display());
            }
        }
        None => println!("{}", body),
    }
}

async fn run_attack(cli: &Cli, protocol: &str, args: &ProtocolArgs, running: Arc<AtomicBool>) {    if cli.should_show_banner() {
        print_banner();
    }

    let encrypt_passphrase = if cli.encrypt {
        match cli.encrypt_passphrase.as_deref() {
            Some(p) => Some(p.to_string()),
            None => {
                eprint!("Enter encryption passphrase: ");
                std::io::stdout().flush().ok();
                let p1 = rpassword::read_password().unwrap_or_default();
                eprint!("Confirm passphrase: ");
                std::io::stdout().flush().ok();
                let p2 = rpassword::read_password().unwrap_or_default();
                if p1 != p2 || p1.is_empty() {
                    eprintln!("Passphrases do not match or are empty");
                    std::process::exit(1);
                }
                Some(p1)
            }
        }
    } else {
        None
    };

    let output_file = cli.output.clone();

    for plugin_path in &cli.plugins {
        match crate::core::plugin::validate_plugin_binary(plugin_path) {
            Ok(entry) => {
                crate::core::plugin::register_plugin(&entry.name, &entry.path, entry.default_port);
                log::info!("Loaded plugin: {} ({})", entry.name, entry.path);
            }
            Err(e) => {
                eprintln!("Plugin error: {}", e);
                std::process::exit(1);
            }
        }
    }

    let mut config = cli.build_attack_config(protocol, args);

    // F2.2: file config dengan prioritas CLI > file > default.
    if cli.config_file.is_some() {
        if let Err(e) = cli.apply_config_file(&mut config) {
            exit_config(&e);
        }
        log::info!("Loaded base config from file (CLI flags take priority)");
    }

    // F2.3: validasi keras + peringatan risiko lockout.
    if let Err(e) = config.validate() {
        exit_config(&e.to_string());
    }
    for w in config.risk_warnings() {
        eprintln!("warning: {}", w);
        log::warn!("{}", w);
    }

    let mut orchestrator = match AttackOrchestrator::new(config, running).await {
        Ok(o) => o,
        Err(e) => exit_config(&e.to_string()),
    };

    let summary = orchestrator.run().await;

    if cli.dry_run {
        // Dry run bukan kegagalan: plan tampil, tidak ada traffic.
        std::process::exit(EXIT_FOUND);
    }

    if let Some(ref passphrase) = encrypt_passphrase {
        encrypt_output_file(&output_file, passphrase);
    }

    if summary.successes > 0 {
        std::process::exit(EXIT_FOUND);
    } else {
        std::process::exit(EXIT_NOT_FOUND);
    }
}

fn encrypt_output_file(output_file: &Option<std::path::PathBuf>, passphrase: &str) {
    if let Some(ref path) = output_file {
        if path.exists() {
            let data = match std::fs::read(path) {
                Ok(d) => d,
                Err(e) => {
                    log::error!("Cannot read output for encryption: {}", e);
                    return;
                }
            };
            let encrypted_path = path.with_extension("enc");
            match crate::utils::encrypt::write_encrypted(&encrypted_path, &data, passphrase) {
                Ok(_) => {
                    log::info!("Encrypted output saved to {}", encrypted_path.display());
                    let _ = std::fs::remove_file(path);
                }
                Err(e) => log::error!("Encryption failed: {}", e),
            }
        }
    }
}

async fn run_create(args: &CreateArgs) {
    let cfg = WordlistConfig {
        name: args.name.clone(),
        company: args.company.clone(),
        dob: args.dob.clone(),
        keywords: args.keywords.clone(),
        min_len: args.min_len,
        max_len: args.max_len,
        leet: !args.no_leet,
    };
    let words = generate_wordlist(&cfg);

    let out_path = match args.output {
        Some(ref path) => Some(path.clone()),
        None if args.dir.is_some() || args.filename.is_some() => {
            let dir = args.dir.clone().unwrap_or_else(|| PathBuf::from("wordlists"));
            std::fs::create_dir_all(&dir).unwrap_or_else(|e| {
                eprintln!("Failed to create directory: {}", e);
                std::process::exit(1);
            });
            let stem = args.filename.clone().unwrap_or_else(|| {
                let parts: Vec<&str> = [
                    args.name.as_deref().unwrap_or(""),
                    args.company.as_deref().unwrap_or(""),
                ].iter().filter(|s| !s.is_empty()).copied().collect();
                if parts.is_empty() { "wordlist".to_string() } else { parts.join("_").replace(' ', "_") }
            });
            let filename = format!("{}_{}.txt", stem, chrono::Local::now().format("%Y%m%d_%H%M%S"));
            Some(dir.join(filename))
        }
        None => None,
    };

    match out_path {
        Some(ref path) => {
            let content = words.iter().cloned().collect::<Vec<_>>().join("\n");
            std::fs::write(path, &content).unwrap_or_else(|e| {
                eprintln!("Failed to write wordlist: {}", e);
                std::process::exit(1);
            });
            println!("  {} Generated {} candidates -> {}",
                "+".green(), words.len(), path.display());
        }
        None => {
            for w in &words {
                println!("{}", w);
            }
            eprintln!("[+] Generated {} candidates", words.len());
        }
    }
}

fn run_validate(args: &cli::ValidateArgs) {
    let ext = args
        .file
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    let loader = Cli {
        config_file: Some(args.file.clone()),
        ..default_cli_for_validate()
    };
    let mut base = default_cli_for_validate().build_attack_config(
        "ssh",
        &ProtocolArgs {
            rdp_domain: None,
            http_userfield: None,
            http_passfield: None,
            http_success: None,
        },
    );
    base.protocols.clear();
    if let Err(e) = loader.apply_config_file(&mut base) {
        exit_config(&e);
    }
    // Kembalikan protokol placeholder jika file tidak menyebutkannya,
    // agar validate fokus ke struktur file, bukan ke protokol CLI.
    if base.protocols.is_empty() {
        base.protocols = vec!["ssh".into()];
    }
    match base.validate() {
        Ok(()) => {
            println!("Config {} is valid ({} format).", args.file.display(), if ext == "toml" { "TOML" } else { "JSON" });
            for w in base.risk_warnings() {
                println!("warning: {}", w);
            }
        }
        Err(e) => exit_config(&e.to_string()),
    }
}

fn default_cli_for_validate() -> Cli {
    Cli {
        command: None,
        targets: vec![],
        target_file: None,
        ports: vec![],
        list_protocols: false,
        users: vec![],
        user_file: None,
        passwords: vec![],
        password_file: None,
        combo_file: None,
        threads: 10,
        timeout: 10,
        delay: 0,
        rate_limit: None,
        retries: 2,
        stop_on_first: false,
        spray: false,
        single_user: false,
        resume: None,
        config_file: None,
        rule_file: None,
        max_mutations: 500,
        checkpoint: 100,
        api_bind: None,
        fp_check: false,
        spray_interval: "0".into(),
        spray_jitter: 20,
        target_rate_limit: None,
        user_cooldown: "0".into(),
        lockout_cooldown: 600,
        rate_cooldown: 60,
        lockout_pause: false,
        user_agent: None,
        safe_profile: false,
        aggressive_lab: false,
        i_understand_risk: false,
        only_open: None,
        max_password_len: None,
        proxy: None,
        proxy_file: None,
        proxy_chain: None,
        output: None,
        format: "plain".into(),
        plugins: vec![],
        list_plugin: false,
        encrypt: false,
        encrypt_passphrase: None,
        decrypt_file: None,
        decrypt_output: None,
        gen_wordlist: false,
        wl_name: None,
        wl_company: None,
        wl_dob: None,
        wl_keywords: vec![],
        wl_min_len: 4,
        wl_max_len: 32,
        wl_no_leet: false,
        wl_output: None,
        ml_train: None,
        ml_generate: None,
        ml_order: 3,
        ml_max_len: 24,
        ml_score: None,
        ml_output: None,
        verbose: 0,
        dry_run: false,
    }
}

fn run_completion(args: &cli::CompletionArgs) {
    use clap_complete::{generate, shells::{Bash, Fish, PowerShell, Zsh}};
    use std::io::stdout;
    let mut cmd = Cli::command();
    match args.shell.to_lowercase().as_str() {
        "bash" => generate(Bash, &mut cmd, "veltrix", &mut stdout()),
        "zsh" => generate(Zsh, &mut cmd, "veltrix", &mut stdout()),
        "fish" => generate(Fish, &mut cmd, "veltrix", &mut stdout()),
        "powershell" | "pwsh" => generate(PowerShell, &mut cmd, "veltrix", &mut stdout()),
        other => exit_config(&format!("unknown shell '{}'. Use bash, zsh, fish, or powershell.", other)),
    }
}
