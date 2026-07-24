mod cli;
mod core;
mod protocols;
mod proxy;
mod utils;

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

    let mut orchestrator = match AttackOrchestrator::new(config, running).await {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Failed to initialize attack: {}", e);
            std::process::exit(1);
        }
    };

    let summary = orchestrator.run().await;

    if summary.successes > 0 {
        std::process::exit(0);
    } else {
        std::process::exit(1);
    }
}
