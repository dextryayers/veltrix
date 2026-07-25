pub mod banner;
pub mod scanner;
pub mod service_db;

pub use scanner::Scanner;
pub use banner::BannerGrabber;
pub use service_db::ServiceDb;

use std::fmt;
use colored::*;

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub host: String,
    pub port: u16,
    pub open: bool,
    pub service: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub latency_ms: u64,
}

impl fmt::Display for ScanResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.open {
            let service_str = if let Some(ref prod) = self.product {
                if let Some(ref ver) = self.version {
                    format!("{} {}", prod, ver)
                } else {
                    prod.clone()
                }
            } else {
                self.service.clone()
            };

            let latency_color = if self.latency_ms < 50 {
                "fast"
            } else if self.latency_ms < 200 {
                "medium"
            } else {
                "slow"
            };

            write!(
                f,
                "{}{} {:>5}/open  {:<14}  {}  {}ms{}",
                "  ".bold(),
                self.host.bold(),
                self.port,
                self.service.green(),
                service_str,
                self.latency_ms,
                latency_color,
            )
        } else {
            write!(f, "{:21} {}/filtered", self.host, self.port)
        }
    }
}

pub fn print_scan_results(results: &[ScanResult]) {
    let open: Vec<_> = results.iter().filter(|r| r.open).collect();
    let hosts: std::collections::BTreeSet<_> = results.iter().map(|r| r.host.as_str()).collect();

    println!();
    println!("  {} {}", "═══ SCAN COMPLETE ═══".cyan().bold(),
        format!("{} host{}, {} port{} open",
            hosts.len(),
            if hosts.len() == 1 { "" } else { "s" },
            open.len(),
            if open.len() == 1 { "" } else { "s" },
        ).white()
    );

    if open.is_empty() {
        println!("  {}", "No open ports found.".yellow());
        println!();
        return;
    }

    for (i, r) in open.iter().enumerate() {
        let service_str = if let Some(ref prod) = r.product {
            if let Some(ref ver) = r.version {
                format!("{} {}", prod.cyan(), ver.yellow())
            } else {
                prod.cyan().to_string()
            }
        } else {
            r.service.green().to_string()
        };

        let latency_color = if r.latency_ms < 50 {
            r.latency_ms.to_string().green()
        } else if r.latency_ms < 200 {
            r.latency_ms.to_string().yellow()
        } else {
            r.latency_ms.to_string().red()
        };

        println!();
        println!("  {} {}:{}/open  {}",
            format!("{}.", i + 1).bold(),
            r.host.bold(),
            r.port.to_string().bold(),
            format!("[{}]", service_str).white(),
        );
        println!("  {}  {}  {}ms",
            "service:".dimmed(),
            r.service,
            latency_color,
        );

        if let Some(ref banner) = r.banner {
            let lines: Vec<&str> = banner.lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty())
                .collect();
            if !lines.is_empty() {
                let preview = lines[0];
                if preview.len() < 120 {
                    println!("  {}  {}", "banner:".dimmed(), preview.dimmed());
                }
                if lines.len() > 1 && lines[1].len() < 120 {
                    println!("  {}  {}", "       ".dimmed(), lines[1].dimmed());
                }
            }
        }
    }
    println!();
}
