use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle, MultiProgress, ProgressState};

use crate::core::config::OutputFormat;
use crate::core::error::AttackError;
use crate::core::result::{AttackSummary, AuthResult};

pub fn protocol_color(proto: &str) -> Color {
    match proto.to_lowercase().as_str() {
        "ssh" => Color::Green,
        "ftp" => Color::Yellow,
        "telnet" => Color::Cyan,
        "smtp" => Color::Magenta,
        "pop3" => Color::Blue,
        "imap" => Color::BrightBlue,
        "rdp" => Color::Red,
        "mysql" => Color::BrightYellow,
        "postgres" => Color::BrightCyan,
        "ldap" => Color::BrightMagenta,
        "redis" => Color::BrightRed,
        "http" | "http-basic" | "http-form" | "http-digest" => Color::BrightGreen,
        "vnc" => Color::BrightWhite,
        "mongodb" => Color::BrightGreen,
        "mssql" => Color::Cyan,
        "smb" => Color::BrightYellow,
        "snmp" => Color::Magenta,
        _ => Color::White,
    }
}

pub struct LiveDashboard {
    multi: MultiProgress,
    progress: ProgressBar,
    status_bar: ProgressBar,
    stats_bar: ProgressBar,
    format: OutputFormat,
    file: Option<std::fs::File>,
    writer: Option<csv::Writer<std::fs::File>>,
    verbose: u8,
    pub success_count: u64,
    pub fail_count: u64,
    pub error_count: u64,
    pub lockout_count: u64,
    pub rate_limit_count: u64,
    pub total_attempts: u64,
    start_time: Instant,
    last_rate_check: Instant,
    last_rate_count: u64,
    pub current_rate: f64,
    protocol: String,
    target_count: usize,
    cred_count: usize,
}

impl LiveDashboard {
    pub fn new(
        format: OutputFormat,
        output_path: Option<&Path>,
        verbose: u8,
        protocol: &str,
        target_count: usize,
        cred_count: usize,
    ) -> Result<Self, AttackError> {
        let (file, writer) = if let Some(path) = output_path {
            let f = std::fs::File::create(path)
                .map_err(|e| AttackError::io("output", format!("Cannot create: {}", e)))?;
            let w = match format {
                OutputFormat::Csv => Some(csv::Writer::from_writer(
                    f.try_clone().map_err(|e| AttackError::io("output", e.to_string()))?
                )),
                _ => None,
            };
            (Some(f), w)
        } else {
            (None, None)
        };

        let multi = MultiProgress::new();

        let total = (target_count * cred_count) as u64;

        let progress = multi.add(ProgressBar::new(total));
        progress.set_style(
            ProgressStyle::with_template(&format!(
                "{} {{spinner:.cyan}} {{wide_bar:.cyan/blue}} {{pos}}/{{len}} ({{eta}})",
                format!("{} {}:", "⚡".bright_yellow(), protocol.to_uppercase().color(protocol_color(protocol)))
            ))
            .unwrap()
            .with_key("eta", |state: &ProgressState, w: &mut dyn std::fmt::Write| {
                let rate = state.per_sec();
                if rate > 0.0 {
                    let len = state.len().unwrap_or(0);
                    let remaining = len.saturating_sub(state.pos());
                    let secs = remaining as f64 / rate;
                    if secs < 60.0 {
                        let _ = write!(w, "{:.0}s", secs);
                    } else {
                        let _ = write!(w, "{:.0}m {:.0}s", secs / 60.0, secs % 60.0);
                    }
                } else {
                    let _ = write!(w, "--");
                }
            })
            .progress_chars("█▓▒░ "),
        );
        progress.enable_steady_tick(Duration::from_millis(100));

        let total_attempts = total;
        let stats_bar = multi.add(ProgressBar::new(0));
        stats_bar.set_style(
            ProgressStyle::with_template("  {msg}").unwrap()
        );
        stats_bar.set_message(format!(
            "{} {} {} {}",
            format!("󰔄 0/{} attempts", total_attempts).white(),
            format!("󰄲 0 found").green(),
            format!("󰅖 --:--").cyan(),
            format!("󰑥 0/s").yellow(),
        ));

        let status_bar = multi.add(ProgressBar::new(0));
        status_bar.set_style(
            ProgressStyle::with_template("  {msg}").unwrap()
        );
        if verbose > 0 {
            status_bar.set_message(format!("{} {}:{}",
                "▶".cyan(),
                "Starting attack...".white().italic(),
                "".dimmed(),
            ));
        }

        Ok(LiveDashboard {
            multi,
            progress,
            status_bar,
            stats_bar,
            format,
            file,
            writer,
            verbose,
            success_count: 0,
            fail_count: 0,
            error_count: 0,
            lockout_count: 0,
            rate_limit_count: 0,
            total_attempts: 0,
            start_time: Instant::now(),
            last_rate_check: Instant::now(),
            last_rate_count: 0,
            current_rate: 0.0,
            protocol: protocol.to_string(),
            target_count,
            cred_count,
        })
    }

    pub fn inc_progress(&mut self) {
        self.progress.inc(1);
        self.total_attempts += 1;

        let now = Instant::now();
        let elapsed = now.duration_since(self.last_rate_check);
        if elapsed >= Duration::from_secs(1) {
            let attempted = self.total_attempts - self.last_rate_count;
            self.current_rate = attempted as f64 / elapsed.as_secs_f64();
            self.last_rate_check = now;
            self.last_rate_count = self.total_attempts;
        }

        let elapsed_total = now.duration_since(self.start_time);
        let elapsed_str = if elapsed_total.as_secs() < 60 {
            format!("{:02}:{:02}", 0, elapsed_total.as_secs())
        } else {
            format!("{:02}:{:02}", elapsed_total.as_secs() / 60, elapsed_total.as_secs() % 60)
        };

        let total = self.target_count * self.cred_count;
        self.stats_bar.set_message(format!(
            "{} {} {} {}",
            format!("󰔄 {}/{} attempts", self.total_attempts, total).white(),
            format!("󰄲 {} found", self.success_count).green(),
            format!("󰅖 {}", elapsed_str).cyan(),
            format!("󰑥 {:.0}/s", self.current_rate).yellow(),
        ));
    }

    pub fn on_result(&mut self, result: &AuthResult) {
        if result.success {
            self.success_count += 1;
            if self.verbose > 0 || !self.verbose_mode() {
                let msg = format!("{} {}",
                    "[✓]".green().bold(),
                    result.display(),
                );
                if self.verbose > 0 {
                    self.status_bar.println(msg);
                } else {
                    self.progress.println(msg);
                }
            }
        } else if result.error.is_some() {
            self.error_count += 1;
            if self.verbose >= 2 {
                let msg = format!("{} {}",
                    "[!]".yellow(),
                    result.display(),
                );
                self.status_bar.println(msg);
            }
        } else {
            self.fail_count += 1;
            if self.verbose >= 2 {
                let msg = format!("{} {}",
                    "[x]".dimmed(),
                    result.display(),
                );
                self.status_bar.println(msg);
            } else if self.verbose == 1 {
                self.status_bar.set_message(format!("{} {}",
                    "⊳".cyan(),
                    format!("{:<20} {:<12} {}",
                        format!("{}:{}", result.target_host, result.target_port),
                        result.protocol,
                        format!("{}:{}", result.username, result.password).dimmed(),
                    ).dimmed(),
                ));
            }
        }

        if let Some(ref mut file) = self.file {
            self.write_to_file(file, result);
        }
    }

    pub fn set_status(&self, msg: String) {
        if self.verbose > 0 {
            self.status_bar.set_message(format!("{} {}", "▶".cyan(), msg));
        }
    }

    fn verbose_mode(&self) -> bool {
        self.verbose > 0
    }

    fn write_to_file_impl(format: &OutputFormat, writer: &Option<csv::Writer<std::fs::File>>, file: &mut std::fs::File, result: &AuthResult) {
        match self.format {
            OutputFormat::Json => {
                if let Ok(json) = serde_json::to_string(result) {
                    let _ = writeln!(file, "{}", json);
                }
            }
            OutputFormat::Csv => {
                if let Some(ref writer) = self.writer {
                    let mut w = writer.clone();
                    let _ = w.write_record(&[
                        &result.target_host,
                        &result.target_port.to_string(),
                        &result.protocol,
                        &result.username,
                        &result.password,
                        &result.success.to_string(),
                        &result.timestamp.to_rfc3339(),
                        &result.duration_ms.to_string(),
                        result.error.as_deref().unwrap_or(""),
                    ]);
                    let _ = w.flush();
                }
            }
            _ => {
                let _ = writeln!(file, "{}", result.display());
            }
        }
    }

    pub fn finish(&mut self, summary: &AttackSummary) {
        self.progress.finish_and_clear();
        self.status_bar.finish_and_clear();
        self.stats_bar.finish_and_clear();

        let total_seconds = self.start_time.elapsed().as_secs_f64();

        println!();
        println!("{}", "═══════════════════════════════════════════".cyan());
        println!("{}", "           🔥 ATTACK COMPLETE".green().bold());
        println!("{}", "═══════════════════════════════════════════".cyan());
        println!("  {}  {}", "Started:      ".bold(), summary.start_time.format("%Y-%m-%d %H:%M:%S"));
        println!("  {}  {}", "Duration:     ".bold(), format!("{:.2}s", total_seconds));
        println!("  {}  {}", "Targets:      ".bold(), summary.total_targets);
        println!("  {}  {}", "Credentials:  ".bold(), summary.total_credentials);
        println!("  {}  {}", "Attempts:     ".bold(), self.total_attempts);
        println!("  {}  {}", "Rate:         ".bold(), format!("{:.0}/s", self.total_attempts as f64 / total_seconds.max(0.01)).yellow());
        println!("  {}  {}", "Successes:    ".bold(), self.success_count.to_string().green().bold());
        println!("  {}  {}", "Failures:     ".bold(), self.fail_count.to_string().red());
        println!("  {}  {}", "Errors:       ".bold(), self.error_count.to_string().yellow());
        if self.lockout_count > 0 {
            println!("  {}  {}", "Lockouts:     ".bold(), self.lockout_count.to_string().red());
        }
        if self.rate_limit_count > 0 {
            println!("  {}  {}", "Rate Limits:  ".bold(), self.rate_limit_count.to_string().yellow());
        }

        let successes: Vec<_> = summary.results.iter().filter(|r| r.success).collect();
        if !successes.is_empty() {
            println!();
            println!("{}", "───────────────────────────────────────".cyan());
            println!("{}", "         🏆 FOUND CREDENTIALS".green().bold());
            println!("{}", "───────────────────────────────────────".cyan());
            for r in &successes {
                println!("  {}", r.display().green().bold());
            }
        }
        println!();
    }
}

impl Drop for LiveDashboard {
    fn drop(&mut self) {
        self.progress.finish_and_clear();
        self.status_bar.finish_and_clear();
        self.stats_bar.finish_and_clear();
    }
}

pub struct OutputHandler {
    pub dashboard: Option<LiveDashboard>,
    format: OutputFormat,
    file: Option<std::fs::File>,
    writer: Option<csv::Writer<std::fs::File>>,
    verbose: u8,
    start_time: Instant,
    pub success_count: u64,
    pub fail_count: u64,
    pub error_count: u64,
}

impl OutputHandler {
    pub fn new(format: OutputFormat, output_path: Option<&Path>, verbose: u8) -> Result<Self, AttackError> {
        let (file, writer) = if let Some(path) = output_path {
            let f = std::fs::File::create(path)
                .map_err(|e| AttackError::io("output", format!("Cannot create: {}", e)))?;
            let w = match format {
                OutputFormat::Csv => Some(csv::Writer::from_writer(
                    f.try_clone().map_err(|e| AttackError::io("output", e.to_string()))?
                )),
                _ => None,
            };
            (Some(f), w)
        } else {
            (None, None)
        };

        Ok(OutputHandler {
            dashboard: None,
            format,
            file,
            writer,
            verbose,
            start_time: Instant::now(),
            success_count: 0,
            fail_count: 0,
            error_count: 0,
        })
    }

    pub fn init_dashboard(&mut self, protocol: &str, target_count: usize, cred_count: usize) {
        match LiveDashboard::new(
            self.format.clone(),
            None,
            self.verbose,
            protocol,
            target_count,
            cred_count,
        ) {
            Ok(d) => self.dashboard = Some(d),
            Err(_) => {}
        }
    }

    pub fn inc_progress(&mut self) {
        if let Some(ref mut d) = self.dashboard {
            d.inc_progress();
        }
    }

    pub fn on_result(&mut self, result: &AuthResult) {
        if result.success {
            self.success_count += 1;
        } else if result.error.is_some() {
            self.error_count += 1;
        } else {
            self.fail_count += 1;
        }

        if let Some(ref mut d) = self.dashboard {
            d.on_result(result);
        }

        if let Some(ref mut file) = self.file {
            self.write_to_file(file, result);
        }
    }

    pub fn set_status(&self, msg: String) {
        if let Some(ref d) = self.dashboard {
            d.set_status(msg);
        }
    }

    fn write_to_file_impl(format: &OutputFormat, writer: &Option<csv::Writer<std::fs::File>>, file: &mut std::fs::File, result: &AuthResult) {
        match self.format {
            OutputFormat::Json => {
                if let Ok(json) = serde_json::to_string(result) {
                    let _ = writeln!(file, "{}", json);
                }
            }
            OutputFormat::Csv => {
                if let Some(ref writer) = self.writer {
                    let mut w = writer.clone();
                    let _ = w.write_record(&[
                        &result.target_host,
                        &result.target_port.to_string(),
                        &result.protocol,
                        &result.username,
                        &result.password,
                        &result.success.to_string(),
                        &result.timestamp.to_rfc3339(),
                        &result.duration_ms.to_string(),
                        result.error.as_deref().unwrap_or(""),
                    ]);
                    let _ = w.flush();
                }
            }
            _ => {
                let _ = writeln!(file, "{}", result.display());
            }
        }
    }

    pub fn finish(&mut self, summary: &AttackSummary) {
        if let Some(ref mut d) = self.dashboard {
            d.finish(summary);
        } else {
            self.print_summary(summary);
        }
    }

    fn print_summary(&self, summary: &AttackSummary) {
        println!("\n{}", "═══════════════════════════════════════".cyan());
        println!("{}", "           ATTACK COMPLETE".green().bold());
        println!("{}", "═══════════════════════════════════════".cyan());

        if let (Some(start), Some(end), Some(dur)) =
            (Some(summary.start_time), summary.end_time, summary.total_duration)
        {
            println!("  {}  {}", "Started:      ".bold(), start.format("%Y-%m-%d %H:%M:%S"));
            println!("  {}  {}", "Ended:        ".bold(), end.format("%Y-%m-%d %H:%M:%S"));
            println!("  {}  {:.2}s", "Duration:     ".bold(), dur.as_secs_f64());
        }
        println!("  {}  {}", "Targets:      ".bold(), summary.total_targets);
        println!("  {}  {}", "Credentials:  ".bold(), summary.total_credentials);
        println!("  {}  {}", "Attempts:     ".bold(), summary.attempts);
        println!("  {}  {}", "Successes:    ".bold(), summary.successes.to_string().green());
        println!("  {}  {}", "Failures:     ".bold(), summary.failures.to_string().red());
        println!("  {}  {}", "Errors:       ".bold(), summary.errors.to_string().yellow());

        if !summary.results.is_empty() {
            println!("\n{}", "───────────────────────────────────".cyan());
            println!("{}", "         FOUND CREDENTIALS".green().bold());
            println!("{}", "───────────────────────────────────".cyan());
            for r in &summary.results {
                if r.success {
                    println!("  {}", r.display());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::result::AttackSummary;
    use chrono::Utc;
    use std::time::Duration;

    #[test]
    fn test_new_no_file() {
        let h = OutputHandler::new(OutputFormat::Plain, None, 0).unwrap();
        assert!(h.file.is_none());
        assert!(h.writer.is_none());
    }

    #[test]
    fn test_new_with_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_output.txt");
        let h = OutputHandler::new(OutputFormat::Plain, Some(&path), 0).unwrap();
        assert!(h.file.is_some());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_protocol_color() {
        assert_eq!(protocol_color("ssh"), Color::Green);
        assert_eq!(protocol_color("rdp"), Color::Red);
        assert_eq!(protocol_color("unknown"), Color::White);
    }
}
