mod api;
mod cli;
mod core;
mod distributed;
mod protocols;
mod proxy;
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
