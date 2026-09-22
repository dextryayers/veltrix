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
        Some(Commands::Man) => print_manual(),
        Some(Commands::CheckIp(ref a)) => run_check_ip(&cli, a).await,
        Some(Commands::Create(ref a)) => run_create(a).await,
        Some(Commands::Wordlist(ref w)) => match &w.command {
            cli::WordlistCommand::Rank(ref a) => run_wordlist_rank(a),
            cli::WordlistCommand::Eval(ref a) => run_wordlist_eval(a),
        },
        Some(Commands::Validate(ref a)) => run_validate(a),
        Some(Commands::Completion(ref a)) => run_completion(a),
        Some(Commands::Serve(ref a)) => run_serve(a, running).await,
        Some(Commands::DistCoordinator(ref a)) => run_dist_coordinator(&cli, a, running).await,
        Some(Commands::DistWorker(ref a)) => run_dist_worker(a, running).await,
        None => {
            print_banner();
            println!("{}", "Use --help or -h for usage information.".dimmed());
        }
    }
}

async fn run_scan(cli: &Cli, args: &cli::ScanPortsArgs, running: Arc<AtomicBool>) {
    print_banner();
    // ANON: source bind juga berlaku untuk probe scanner.
    match cli::parse_source_ip(&cli.source_ip) {
        Ok(ip) => {
            crate::protocols::tcp::set_source_ip(ip);
            if let Some(ip) = ip {
                log::info!("Egress source IP bound to {}", ip);
            }
        }
        Err(e) => exit_config(&e),
    }

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
        shuffle: args.shuffle,
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
    // ANON: source bind untuk fase scan maupun attack berikutnya.
    match cli::parse_source_ip(&cli.source_ip) {
        Ok(ip) => crate::protocols::tcp::set_source_ip(ip),
        Err(e) => exit_config(&e),
    }

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
        shuffle: args.scan.shuffle,
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
                    // F6.3: JSON auto report juga masked kecuali --show-secrets.
                    pass: if cli.show_secrets {
                        r.password.clone()
                    } else {
                        crate::core::result::mask_password(&r.password)
                    },
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
                // F6.3: mask password di laporan teks kecuali --show-secrets.
                let pw = if cli.show_secrets {
                    f.pass.clone()
                } else {
                    crate::core::result::mask_password(&f.pass)
                };
                s.push_str(&format!("    FOUND {}:{} [{}:{}]\n", f.host, f.port, f.user, pw));
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

/// F8.5: `veltrix wordlist rank --input CANDS --model TRAIN --top N -o OUT`.
/// Mengurutkan kandidat probable-first agar password paling mungkin dicoba dulu.
fn run_wordlist_rank(args: &cli::RankArgs) {
    use crate::utils::ml_predict::MarkovChain;
    let read_lines = |p: &std::path::Path| -> Vec<String> {
        std::fs::read_to_string(p)
            .unwrap_or_else(|e| {
                eprintln!("Failed to read {}: {}", p.display(), e);
                std::process::exit(EXIT_CONFIG);
            })
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    };
    let train_path = args.model.clone().unwrap_or_else(|| args.input.clone());
    let train = read_lines(&train_path);
    if train.is_empty() {
        eprintln!("Config error: training file is empty");
        std::process::exit(EXIT_CONFIG);
    }
    let candidates = read_lines(&args.input);
    if candidates.is_empty() {
        eprintln!("Config error: input file is empty");
        std::process::exit(EXIT_CONFIG);
    }
    let mut mc = MarkovChain::new(args.order.max(1));
    mc.train(&train);
    let top = if args.top == 0 { None } else { Some(args.top) };
    let mut ranked = mc.rank(&candidates, top);
    if let Some(ms) = args.min_score {
        ranked.retain(|(_, s)| *s <= ms);
    }
    let lines: Vec<String> = ranked.iter().map(|(p, s)| format!("{}\t{:.4}", p, s)).collect();
    match args.output.as_ref() {
        Some(path) => {
            std::fs::write(path, lines.join("\n")).unwrap_or_else(|e| {
                eprintln!("Failed to write {}: {}", path.display(), e);
                std::process::exit(EXIT_CONFIG);
            });
            eprintln!("[+] Ranked {} candidates (train={}, order={}) -> {}",
                lines.len(), train.len(), args.order, path.display());
        }
        None => {
            for l in &lines {
                println!("{}", l);
            }
            eprintln!("[+] Ranked {} candidates (train={})", lines.len(), train.len());
        }
    }
}

/// F8.4: `veltrix wordlist eval --ranked RANKED --relevant HELDOUT --k 10,20,50`.
/// Menghitung precision@K agar klaim "ML menaikkan hit rate" ada angkanya.
/// Format RANKED: baris `password<TAB>skor` (output `wordlist rank`, sudah
/// terurut probable-first). RELEVANT: satu password per baris (held-out).
fn run_wordlist_eval(args: &cli::EvalArgs) {
    use crate::utils::ml_predict::{parse_k_list, MarkovChain};
    use std::collections::HashSet;
    let ks = match parse_k_list(&args.k) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Config error: {}", e);
            std::process::exit(EXIT_CONFIG);
        }
    };
    let ranked_raw = std::fs::read_to_string(&args.ranked).unwrap_or_else(|e| {
        eprintln!("Failed to read {}: {}", args.ranked.display(), e);
        std::process::exit(EXIT_CONFIG);
    });
    let mut ranked: Vec<(String, f64)> =
        crate::utils::ml_predict::parse_ranked_lines(&ranked_raw);
    if ranked.is_empty() {
        eprintln!("Config error: ranked file is empty");
        std::process::exit(EXIT_CONFIG);
    }
    let rel_raw = std::fs::read_to_string(&args.relevant).unwrap_or_else(|e| {
        eprintln!("Failed to read {}: {}", args.relevant.display(), e);
        std::process::exit(EXIT_CONFIG);
    });
    let relevant: HashSet<String> = rel_raw
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    if relevant.is_empty() {
        eprintln!("Config error: relevant file is empty");
        std::process::exit(EXIT_CONFIG);
    }
    println!("ranked={} relevant={} K={:?}", ranked.len(), relevant.len(), ks);
    for k in ks {
        let p = MarkovChain::precision_at_k(&ranked, &relevant, k);
        let hits = ranked.iter().take(k.min(ranked.len()))
            .filter(|(w, _)| relevant.contains(w)).count();
        println!("precision@{:<6} {:.4}  ({}/{} hits in top {})",
            k, p, hits, k.min(ranked.len()), k.min(ranked.len()));
    }
}

/// ANON A4: `veltrix check-ip [--proxy ...]` — verifikasi egress cover
/// SEBELUM menyerang. Keluar 0 bila IP terlihat sesuai harapan (via proxy),
/// 1 bila gagal, 2 bila tanpa proxy (operator harus sadar IP asli terekspos).
async fn run_check_ip(cli: &Cli, args: &cli::CheckIpArgs) {
    use crate::proxy::ProxyConfig;
    print_banner();
    // Kumpulkan proxy dari flag global (sama seperti path attack).
    let mut proxies = Vec::new();
    if let Some(ref pf) = cli.proxy_file {
        match crate::proxy::load_proxy_list(pf) {
            Ok(mut v) => proxies.append(&mut v),
            Err(e) => exit_config(&format!("cannot load --proxy-file: {}", e)),
        }
    }
    if let Some(ref single) = cli.proxy {
        match ProxyConfig::parse(single) {
            Ok(p) => proxies.push(p),
            Err(e) => exit_config(&format!("invalid --proxy: {}", e)),
        }
    }
    if let Some(ref chain) = cli.proxy_chain {
        let hops: Vec<ProxyConfig> = chain
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .filter_map(|s| ProxyConfig::parse(s).ok())
            .collect();
        if hops.is_empty() {
            exit_config("invalid --proxy-chain: no parsable hops");
        }
        // check-ip hanya memakai hop pertama (reqwest single-hop, jujur).
        if hops.len() > 1 {
            eprintln!("note: check-ip uses the first chain hop only (HTTP single-hop limit)");
        }
        proxies.push(hops.into_iter().next().unwrap());
    }

    let proxy_opt: Option<ProxyConfig> = proxies.into_iter().next();
    match proxy_opt.as_ref() {
        Some(p) => println!("  egress via {}", p.display()),
        None => {
            eprintln!("  [!] NO PROXY — this will expose your real IP.");
            eprintln!("      Continue only for lab-local targets you own.");
        }
    }
    let timeout = std::time::Duration::from_secs(args.timeout.max(1));
    let ua = crate::protocols::transport::next_user_agent();
    let (client, warning) =
        crate::protocols::transport::build_reqwest_client(timeout, &proxy_opt, &ua);
    if let Some(w) = warning {
        eprintln!("  note: {}", w);
    }
    let client = match client {
        Ok(c) => c,
        Err(e) => exit_config(&e),
    };
    match tokio::time::timeout(timeout, client.get(&args.url).send()).await {
        Ok(Ok(resp)) => match resp.text().await {
            Ok(ip) => {
                let ip = ip.trim().to_string();
                println!("  egress IP: {}", ip);
                if proxy_opt.is_none() {
                    std::process::exit(EXIT_CONFIG);
                }
            }
            Err(e) => {
                eprintln!("check-ip: cannot read echo response: {}", e);
                std::process::exit(EXIT_NOT_FOUND);
            }
        },
        Ok(Err(e)) => {
            eprintln!("check-ip: egress request failed: {}", e);
            std::process::exit(EXIT_NOT_FOUND);
        }
        Err(_) => {
            eprintln!("check-ip: timed out after {}s", args.timeout);
            std::process::exit(EXIT_NOT_FOUND);
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
        leet_level: args.leet_level.min(3),
        seasons: !args.no_seasons,
        keyboard: !args.no_keyboard,
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
        show_secrets: false,
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
        proxy_required: false,
        rotate_proxy_every: 0,
        random_delay: 100,
        check_proxy: false,
        source_ip: None,
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
        wl_leet_level: 2,
        wl_no_seasons: false,
        wl_no_keyboard: false,
        wl_output: None,
        ml_train: None,
        ml_generate: None,
        ml_order: 3,
        ml_max_len: 24,
        ml_score: None,
        ml_output: None,
        verbose: 0,
        quiet: false,
        dry_run: false,
    }
}

/// F7: coordinator terdistribusi. Kredensial dan target dari flag global.
async fn run_dist_coordinator(cli: &Cli, args: &cli::DistCoordinatorArgs, running: Arc<AtomicBool>) {
    use crate::distributed::coordinator::{Coordinator, CoordinatorConfig};
    print_banner();
    let token = args
        .dist_token
        .clone()
        .or_else(|| std::env::var("VELTRIX_DIST_TOKEN").ok())
        .filter(|t| !t.trim().is_empty())
        .unwrap_or_else(|| {
            eprintln!("Config error: --dist-token or VELTRIX_DIST_TOKEN is required");
            std::process::exit(EXIT_CONFIG);
        });
    // Bangun config via path CLI standar agar validasi + preset konsisten.
    let empty_proto = ProtocolArgs {
        rdp_domain: None,
        http_userfield: None,
        http_passfield: None,
        http_success: None,
    };
    let mut config = cli.build_attack_config("ssh", &empty_proto);
    config.protocols = args.protocols.clone();
    if let Err(e) = config.validate() {
        exit_config(&e.to_string());
    }
    let targets =
        match crate::core::attack::AttackOrchestrator::load_targets_for_distributed(&config).await {
            Ok(t) => t,
            Err(e) => exit_config(&e.to_string()),
        };
    let creds =
        match crate::core::attack::AttackOrchestrator::load_credentials_for_distributed(&config).await {
            Ok(c) => c,
            Err(e) => exit_config(&e.to_string()),
        };
    println!(
        "  {} run with {} targets x {} credentials, chunk size {}",
        "Distributing".bold().cyan(),
        targets.len(),
        creds.len(),
        args.chunk_size
    );
    println!("  {} tokens expire in {}s. Workers: veltrix dist-worker --connect <this-host> --dist-token <TOKEN>", "Auth:".bold().cyan(), args.token_ttl);
    let mut coord = Coordinator::new(
        CoordinatorConfig {
            bind: args.bind.clone(),
            run_token: token,
            token_ttl_secs: args.token_ttl,
            chunk_size: args.chunk_size,
            chunk_timeout_secs: args.chunk_timeout,
            heartbeat_timeout_secs: args.heartbeat_timeout,
            max_chunk_attempts: args.max_attempts,
        },
        targets,
        creds,
        config.timeout.as_secs(),
        running,
    );
    let results = coord.run().await;
    let found = results.iter().filter(|r| r.success).count();
    // Tulis -o bila diminta (format sama seperti mode attack).
    if let Some(ref out_path) = config.output_file {
        write_dist_output(out_path, &config, coord.run_id(), &results);
    }
    println!("  {} {} results, {} successes", "Distributed done:".green().bold(), results.len(), found);
    if found > 0 {
        std::process::exit(EXIT_FOUND);
    } else {
        std::process::exit(EXIT_NOT_FOUND);
    }
}

/// Tulis output dist-coordinator sesuai -f (json v2 / html / plain).
fn write_dist_output(
    path: &std::path::Path,
    config: &crate::core::config::AttackConfig,
    run_id: &str,
    results: &[crate::core::result::AuthResult],
) {
    use crate::core::config::OutputFormat;
    use crate::core::result::FindingV2;
    let started = chrono::Utc::now().to_rfc3339();
    match config.output_format {
        OutputFormat::Json => {
            let mut out = String::new();
            for (i, r) in results.iter().enumerate() {
                let f = FindingV2::from_result(r, run_id, i as u64, &started);
                out.push_str(&serde_json::to_string(&f).unwrap_or_default());
                out.push('\n');
            }
            if let Err(e) = std::fs::write(path, out) {
                log::error!("Failed to write dist output: {}", e);
            }
        }
        OutputFormat::Html => {
            let summary = crate::core::result::AttackSummary {
                run_id: run_id.to_string(),
                start_time: chrono::Utc::now(),
                end_time: Some(chrono::Utc::now()),
                total_targets: 0,
                total_credentials: 0,
                attempts: results.len() as u64,
                successes: results.iter().filter(|r| r.success).count() as u64,
                failures: 0,
                errors: 0,
                results: results.to_vec(),
                total_duration: None,
            };
            if let Err(e) =
                crate::utils::report::save_html_report(path, &summary, config.show_secrets)
            {
                log::error!("Failed to write dist HTML report: {}", e);
            }
        }
        _ => {
            let mut out = String::new();
            for r in results {
                let line = if config.show_secrets { r.display_full() } else { r.display() };
                out.push_str(&format!("{}\n", line));
            }
            if let Err(e) = std::fs::write(path, out) {
                log::error!("Failed to write dist output: {}", e);
            }
        }
    }
}

/// F7: worker terdistribusi.
async fn run_dist_worker(args: &cli::DistWorkerArgs, running: Arc<AtomicBool>) {
    use crate::distributed::worker::DistributedWorker;
    print_banner();
    if args.connect.trim().is_empty() {
        exit_config("--connect ADDR is required");
    }
    let token = args
        .dist_token
        .clone()
        .or_else(|| std::env::var("VELTRIX_DIST_TOKEN").ok())
        .filter(|t| !t.trim().is_empty())
        .unwrap_or_else(|| {
            eprintln!("Config error: --dist-token or VELTRIX_DIST_TOKEN is required");
            std::process::exit(EXIT_CONFIG);
        });
    let mut w = DistributedWorker::new(
        args.connect.clone(),
        token,
        args.name.clone(),
        args.threads.clamp(1, 100),
        running,
    );
    w.checkpoint_path = args.checkpoint_file.clone();
    let results = w.run().await;
    let found = results.iter().filter(|r| r.success).count();
    println!("  {} {} tasks executed, {} successes", "Worker done:".green().bold(), results.len(), found);
}

/// F6.4: jalankan REST API v2 + Web UI.
async fn run_serve(args: &cli::ServeArgs, running: Arc<AtomicBool>) {
    print_banner();
    let token = args
        .api_token
        .clone()
        .or_else(|| std::env::var("VELTRIX_API_TOKEN").ok())
        .filter(|t| !t.trim().is_empty());
    let (server, shown) = crate::api::server::ApiServer::new(
        args.bind.clone(),
        running,
        token,
        args.rate_per_min,
    );
    println!("  {} http://{}/", "Web UI:".bold().cyan(), args.bind);
    println!("  {} POST /api/v2/login {{\"token\": <API-TOKEN>}}", "Login:".bold().cyan());
    match shown {
        Some(t) => {
            eprintln!("  [!] Ephemeral API token (shown once, valid for this process): {}", t);
            log::warn!("Ephemeral API token generated; use --api-token or VELTRIX_API_TOKEN for stable ops");
        }
        None => {
            println!("  {} using configured API token", "Auth:".bold().cyan());
        }
    }
    server.run().await;
}

fn run_completion(args: &cli::CompletionArgs) {    use clap_complete::{generate, shells::{Bash, Fish, PowerShell, Zsh}};
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
