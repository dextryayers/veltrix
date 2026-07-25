mod api;
mod cli;
mod core;
mod distributed;
mod protocols;
mod proxy;
mod scanner;
mod utils;

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use clap::Parser;
use cli::{print_banner, print_protocols, CliArgs};
use core::attack::AttackOrchestrator;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = CliArgs::parse();

    if args.list_protocols {
        print_protocols();
        return;
    }

    // Handle wordlist generation mode
    if args.gen_wordlist {
        let cfg = args.to_wordlist_config();
        let words = crate::utils::wordlist_gen::generate_wordlist(&cfg);
        match args.wl_output {
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

    // Handle ML prediction mode
    let ml_train_path = args.ml_train.clone();
    let ml_generate_count = args.ml_generate;
    let ml_score_path = args.ml_score.clone();
    let ml_order = args.ml_order;
    let ml_max_len = args.ml_max_len;
    let ml_output_path = args.ml_output.clone();

    if let Some(ref train_path) = ml_train_path {
        let data = std::fs::read_to_string(train_path).unwrap_or_else(|e| {
            eprintln!("Failed to read training file: {}", e);
            std::process::exit(1);
        });
        let passwords: Vec<String> = data.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
        let mut mc = crate::utils::ml_predict::MarkovChain::new(ml_order);
        mc.train(&passwords);
        log::info!("Trained Markov model (order={}) on {} passwords", ml_order, passwords.len());

        if let Some(count) = ml_generate_count {
            let generated = mc.generate_many(count, ml_max_len);
            match ml_output_path {
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

        if let Some(ref score_path) = ml_score_path {
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

        if ml_generate_count.is_some() || ml_score_path.is_some() {
            return;
        }
    }

    // Handle port scan mode
    if args.scan {
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        }).expect("Failed to set SIGINT handler");

        let hosts = if !args.targets.is_empty() {
            args.targets.clone()
        } else if let Some(ref file) = args.target_file {
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
            eprintln!("No targets specified. Use -t or --target-file.");
            std::process::exit(1);
        };

        let ports = match args.scan_ports.as_deref() {
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
            max_rate: 1000,
            banner_grab: !args.scan_no_banner,
            retries: 1,
        };

        let scanner = crate::scanner::Scanner::new(config, running.clone());
        let results = scanner.scan().await;

        let open: Vec<_> = results.iter().filter(|r| r.open).collect();
        println!("\n┌─────────────────────────────────────────────────────────────┐");
        println!("│ Scan Results: {} host(s), {} open ports                     │", results.len(), open.len());
        println!("└─────────────────────────────────────────────────────────────┘");
        for r in &results {
            if r.open {
                let service_info = match (&r.product, &r.version) {
                    (Some(p), Some(v)) => format!("{} {}", p, v),
                    (Some(p), None) => p.clone(),
                    (None, None) if !r.banner.is_some() => r.service.clone(),
                    _ => r.service.clone(),
                };
                println!(
                    "  {:21} {}/open  {:12}  {:35}  {}ms",
                    r.host,
                    r.port,
                    r.service,
                    r.banner.as_deref().unwrap_or(&service_info).trim(),
                    r.latency_ms,
                );
            }
        }
        if open.is_empty() {
            println!("  (no open ports found)");
        }
        println!();
        return;
    }

    if args.should_show_banner() {
        print_banner();
    }

    let config = match args.into_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Configuration error: {}", e);
            std::process::exit(1);
        }
    };

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

    // Handle distributed mode
    if let Some(ref mode) = config.distributed {
        let (successes, total) = match mode {
            crate::core::config::DistributedMode::Coordinator { bind } => {
                log::info!("Starting coordinator on {}", bind);

                let targets = match AttackOrchestrator::load_targets_for_distributed(&config).await {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!("Failed to load targets: {}", e);
                        std::process::exit(1);
                    }
                };

                let credentials = match AttackOrchestrator::load_credentials_for_distributed(&config).await {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("Failed to load credentials: {}", e);
                        std::process::exit(1);
                    }
                };

                let token = config.distributed_token.clone().unwrap_or_default();

                let mut coord = distributed::coordinator::Coordinator::new(
                    bind.clone(),
                    token,
                    targets,
                    credentials,
                    running,
                );

                let results = coord.run().await;
                let success_count = results.iter().filter(|r| r.success).count();
                (success_count, results.len())
            }
            crate::core::config::DistributedMode::Worker { connect } => {
                log::info!("Starting worker, connecting to {}", connect);

                let token = config.distributed_token.clone().unwrap_or_default();
                let hostname = config.distributed_name.clone()
                    .unwrap_or_else(|| {
                        std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".into())
                    });

                let worker = distributed::worker::DistributedWorker::new(
                    connect.clone(),
                    token,
                    hostname,
                    config.threads,
                    running,
                );

                let results = worker.run().await;
                let success_count = results.iter().filter(|r| r.success).count();
                (success_count, results.len())
            }
        };
        log::info!("Distributed mode finished: {} successes out of {} results", successes, total);
        if successes > 0 {
            std::process::exit(0);
        } else {
            std::process::exit(1);
        }
    }

    // Handle decrypt mode
    if let Some(ref decrypt_path) = config.decrypt_file {
        let passphrase = match config.encrypt_passphrase.as_deref() {
            Some(p) => p.to_string(),
            None => {
                eprint!("Enter decryption passphrase: ");
                std::io::stdout().flush().ok();
                rpassword::read_password().unwrap_or_default()
            }
        };
        match &config.decrypt_output {
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

    // Handle encrypt passphrase prompt
    let encrypt_passphrase = if config.encrypt {
        match config.encrypt_passphrase.as_deref() {
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

    // Save output file path before config is moved
    let output_file = config.output_file.clone();

    // Register external plugins
    for plugin_path in &config.plugins {
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

    // Start REST API server if configured
    if let Some(ref bind) = config.api_bind {
        let api_server = api::server::ApiServer::new(bind.clone(), Arc::clone(&running));
        let api_handle = tokio::spawn(async move {
            api_server.run().await;
        });
        log::info!("REST API server started on {}", bind);

        // If only API mode (no targets provided), keep running
        let has_targets = !config.targets.is_empty() || config.target_file.is_some();
        if !has_targets {
            log::info!("API-only mode. Press Ctrl+C to stop.");
            api_handle.await.ok();
            return;
        }

        // Normal mode with API server running in background
        let mut orchestrator = match AttackOrchestrator::new(config, running).await {
            Ok(o) => o,
            Err(e) => {
                eprintln!("Failed to initialize attack: {}", e);
                std::process::exit(1);
            }
        };

        let summary = orchestrator.run().await;
        api_handle.abort();

        // Encrypt output if requested
        if let Some(ref passphrase) = encrypt_passphrase {
            encrypt_output_file(&output_file, passphrase);
        }

        if summary.successes > 0 {
            std::process::exit(0);
        } else {
            std::process::exit(1);
        }
    } else {
        // Normal (non-distributed) mode without API
        let mut orchestrator = match AttackOrchestrator::new(config, running).await {
            Ok(o) => o,
            Err(e) => {
                eprintln!("Failed to initialize attack: {}", e);
                std::process::exit(1);
            }
        };

        let summary = orchestrator.run().await;

        // Encrypt output if requested
        if let Some(ref passphrase) = encrypt_passphrase {
            encrypt_output_file(&output_file, passphrase);
        }

        if summary.successes > 0 {
            std::process::exit(0);
        } else {
            std::process::exit(1);
        }
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
