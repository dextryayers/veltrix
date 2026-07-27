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
use clap::Parser;
use cli::{print_banner, print_protocols, Cli, Commands, ProtocolArgs, CreateArgs};
use core::attack::AttackOrchestrator;
use crate::utils::wordlist_gen::{WordlistConfig, generate_wordlist};
use colored::Colorize;


#[tokio::main]
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
            std::process::exit(1);
        }
    }).expect("Failed to set SIGINT handler");

    match cli.command {
        Commands::ScanPorts(ref args) => run_scan(&cli, args, running).await,
        Commands::Ssh(ref a) => run_attack(&cli, "ssh", a, running).await,
        Commands::Ftp(ref a) => run_attack(&cli, "ftp", a, running).await,
        Commands::Telnet(ref a) => run_attack(&cli, "telnet", a, running).await,
        Commands::Smtp(ref a) => run_attack(&cli, "smtp", a, running).await,
        Commands::Pop3(ref a) => run_attack(&cli, "pop3", a, running).await,
        Commands::Imap(ref a) => run_attack(&cli, "imap", a, running).await,
        Commands::Rdp(ref a) => run_attack(&cli, "rdp", a, running).await,
        Commands::Mysql(ref a) => run_attack(&cli, "mysql", a, running).await,
        Commands::Postgres(ref a) => run_attack(&cli, "postgres", a, running).await,
        Commands::Ldap(ref a) => run_attack(&cli, "ldap", a, running).await,
        Commands::Redis(ref a) => run_attack(&cli, "redis", a, running).await,
        Commands::Http(ref a) => run_attack(&cli, "http", a, running).await,
        Commands::Vnc(ref a) => run_attack(&cli, "vnc", a, running).await,
        Commands::Mongodb(ref a) => run_attack(&cli, "mongodb", a, running).await,
        Commands::Mssql(ref a) => run_attack(&cli, "mssql", a, running).await,
        Commands::Smb(ref a) => run_attack(&cli, "smb", a, running).await,
        Commands::Snmp(ref a) => run_attack(&cli, "snmp", a, running).await,
        Commands::Create(ref a) => run_create(a).await,
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
            Err(e) => {
                eprintln!("Invalid port specification: {}", e);
                std::process::exit(1);
            }
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

async fn run_attack(cli: &Cli, protocol: &str, args: &ProtocolArgs, running: Arc<AtomicBool>) {
    if cli.should_show_banner() {
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

    let config = cli.build_attack_config(protocol, args);

    let mut orchestrator = match AttackOrchestrator::new(config, running).await {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Failed to initialize attack: {}", e);
            std::process::exit(1);
        }
    };

    let summary = orchestrator.run().await;

    if let Some(ref passphrase) = encrypt_passphrase {
        encrypt_output_file(&output_file, passphrase);
    }

    if summary.successes > 0 {
        std::process::exit(0);
    } else {
        std::process::exit(1);
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
                "✓".green(), words.len(), path.display());
        }
        None => {
            for w in &words {
                println!("{}", w);
            }
            eprintln!("[+] Generated {} candidates", words.len());
        }
    }
}
