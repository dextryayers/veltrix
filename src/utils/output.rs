use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle, MultiProgress};

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

fn fmt_dur(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{:02}s", secs)
    } else if secs < 3600 {
        format!("{:02}m {:02}s", secs / 60, secs % 60)
    } else {
        format!("{:02}h {:02}m", secs / 3600, (secs % 3600) / 60)
    }
}

pub struct LiveDashboard {
    _multi: MultiProgress,
    spinner: ProgressBar,
    progress: ProgressBar,
    status_bar: ProgressBar,
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
    last_rate: Instant,
    last_rate_count: u64,
    pub current_rate: f64,
    rate_history: [f64; 10],
    rate_idx: usize,
    _target_count: usize,
    _cred_count: usize,
    spinner_tag: String,
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

        let _multi = MultiProgress::new();
        let pcolor = protocol_color(protocol);
        let tag = format!(" {} ", protocol.to_uppercase()).color(pcolor).bold();

        let total = (target_count * cred_count) as u64;

        let spinner = _multi.add(ProgressBar::new(total));
        spinner.set_style(
            ProgressStyle::with_template("{spinner:.green} {msg}")
            .unwrap()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
        );
        spinner.set_message(format!("{} initializing...", tag));
        spinner.enable_steady_tick(Duration::from_millis(80));

        let progress = _multi.add(ProgressBar::new(total));
        progress.set_style(
            ProgressStyle::with_template("  {msg}")
            .unwrap()
        );
        progress.disable_steady_tick();

        let status_bar = _multi.add(ProgressBar::new(0));
        status_bar.set_style(ProgressStyle::with_template("  {msg}").unwrap());
        status_bar.set_message(format!(
            "{} {}",
            ">>".bright_green(),
            "initialized".white().italic()
        ));

        Ok(LiveDashboard {
            _multi,
            spinner,
            progress,
            status_bar,
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
            last_rate: Instant::now(),
            last_rate_count: 0,
            current_rate: 0.0,
            rate_history: [0.0; 10],
            rate_idx: 0,
            _target_count: target_count,
            _cred_count: cred_count,
            spinner_tag: tag.to_string(),
        })
    }

    fn update_progress(&self) {
        let total = (self._target_count * self._cred_count) as u64;
        self.progress.set_position(self.total_attempts);
        let elapsed = self.start_time.elapsed();
        let elapsed_str = if elapsed.as_secs() == 0 { "--".into() } else { fmt_dur(elapsed) };

        self.spinner.set_message(format!(
            "{}  {}  {}  {}  {}",
            self.spinner_message_tag(),
            format!("{}/{}", self.total_attempts, total).dimmed(),
            format!("found:{}", self.success_count).green(),
            format!("fail:{}", self.fail_count).red(),
            format!("{}", elapsed_str).cyan(),
        ));

        if self.verbose >= 2 {
            let rate_str = if self.current_rate > 0.0 {
                format!("{:.0}/s", self.current_rate)
            } else {
                "--/s".into()
            };
            self.progress.set_message(format!(
                "attempts={} found={} fail={} errors={} elapsed={} rate={}",
                self.total_attempts,
                self.success_count,
                self.fail_count,
                self.error_count,
                elapsed_str,
                rate_str,
            ));
        } else {
            self.progress.set_message(format!(
                "found={}  fail={}  elapsed={}",
                self.success_count,
                self.fail_count,
                elapsed_str,
            ));
        }
    }

    fn spinner_message_tag(&self) -> &str {
        &self.spinner_tag
    }

    pub fn inc_progress(&mut self) {
        self.spinner.inc(1);
        self.total_attempts += 1;

        let now = Instant::now();
        let dt = now.duration_since(self.last_rate);
        if dt >= Duration::from_millis(800) {
            let attempted = self.total_attempts - self.last_rate_count;
            let rate = if dt.as_secs_f64() > 0.0 { attempted as f64 / dt.as_secs_f64() } else { 0.0 };
            self.rate_history[self.rate_idx % 10] = rate;
            self.rate_idx += 1;
            let n = self.rate_history.iter().filter(|&&v| v > 0.0).count().max(1);
            self.current_rate = self.rate_history.iter().sum::<f64>() / n as f64;
            self.last_rate = now;
            self.last_rate_count = self.total_attempts;
        }

        self.update_progress();
    }

    fn println_stdout(&self, msg: String) {
        use std::io::Write;
        let _ = writeln!(std::io::stdout(), "{}", msg);
    }

    pub fn on_result(&mut self, result: &AuthResult) {
        let show_all = self.verbose >= 1;

        if result.success {
            self.success_count += 1;
            let msg = format!(
                "{} {} {} [{}:{}]",
                "+".green().bold(),
                format!("{}:{}", result.target_host, result.target_port).white(),
                result.protocol.cyan(),
                result.username.green().bold(),
                result.password.green().bold(),
            );
            self.println_stdout(msg);
        } else if result.error.is_some() {
            self.error_count += 1;
            let brief = result.error.as_ref().unwrap();
            let brief = brief.split(&['\r', '\n'][..]).next().unwrap_or(brief);
            let msg = if self.verbose >= 2 {
                format!(
                    "! {} {} [{}:{}] {}",
                    format!("{}:{}", result.target_host, result.target_port).dimmed(),
                    result.protocol.dimmed(),
                    result.username.yellow(),
                    result.password.dimmed(),
                    brief.dimmed(),
                )
            } else if show_all {
                format!(
                    "! {} [{}:{}]",
                    format!("{}:{}", result.target_host, result.target_port).dimmed(),
                    result.username.dimmed(),
                    result.password.dimmed(),
                )
            } else {
                String::new()
            };
            if !msg.is_empty() {
                self.println_stdout(msg);
            }
        } else {
            self.fail_count += 1;
            if show_all {
                let msg = format!(
                    "- {} [{}:{}]",
                    format!("{}:{}", result.target_host, result.target_port).dimmed(),
                    result.username.dimmed(),
                    result.password.dimmed(),
                );
                self.println_stdout(msg);
            }
        }

        self.set_status(format!(
            "{}:{} [{}:{}] ({})",
            result.target_host, result.target_port,
            result.username, result.password,
            if result.success { "OK" } else { "FAIL" },
        ));

        if let Some(ref mut file) = self.file {
            write_output(&self.format, self.writer.as_mut(), file, result);
        }

        self.update_progress();
        let _ = std::io::stdout().flush();
    }

    pub fn set_status(&self, msg: String) {
        self.status_bar.set_message(format!("{} {}",
            ">".cyan(),
            msg.white(),
        ));
        let _ = std::io::stdout().flush();
    }

    pub fn finish(&mut self, summary: &AttackSummary) {
        self.spinner.finish_and_clear();
        self.progress.finish_and_clear();
        self.status_bar.finish_and_clear();

        let total_secs = self.start_time.elapsed().as_secs_f64();

        println!();
        println!("{}", "┌──────────────────────────────────────┐".cyan().bold());
        println!("{}", "│           ATTACK COMPLETE             │".green().bold());
        println!("{}", "└──────────────────────────────────────┘".cyan().bold());
        println!();

        let mut lines: Vec<(String, String)> = vec![
            ("Started".into(), format!("{}", summary.start_time.format("%Y-%m-%d %H:%M:%S"))),
            ("Duration".into(), format!("{:.2}s", total_secs)),
            ("Targets".into(), summary.total_targets.to_string()),
            ("Credentials".into(), summary.total_credentials.to_string()),
            ("Attempts".into(), self.total_attempts.to_string()),
            ("Avg Rate".into(), format!("{:.0}/s", self.total_attempts as f64 / total_secs.max(0.01))),
            ("Successes".into(), self.success_count.to_string()),
            ("Failures".into(), self.fail_count.to_string()),
            ("Errors".into(), self.error_count.to_string()),
        ];

        if self.lockout_count > 0 {
            lines.push(("Lockouts".into(), self.lockout_count.to_string()));
        }
        if self.rate_limit_count > 0 {
            lines.push(("Rate Limit".into(), self.rate_limit_count.to_string()));
        }

        let max_label = lines.iter().map(|(l, _)| l.len()).max().unwrap_or(10);
        for (label, value) in &lines {
            let color = match label.as_str() {
                "Duration" | "Started" | "Targets" | "Credentials" | "Attempts" => Color::White,
                "Avg Rate" => Color::Yellow,
                "Successes" => Color::Green,
                "Failures" => Color::Red,
                "Errors" | "Lockouts" | "Rate Limit" => Color::Yellow,
                _ => Color::White,
            };
            println!("  {:>width$}  {}",
                label.bold().cyan(),
                value.color(color),
                width = max_label,
            );
        }

        let successes: Vec<_> = summary.results.iter().filter(|r| r.success).collect();
        if !successes.is_empty() {
            println!();
            println!("{}", "┌──────────────────────────────────────┐".green().bold());
            println!("{}", "│          FOUND CREDENTIALS            │".green().bold());
            println!("{}", "└──────────────────────────────────────┘".green().bold());
            for r in &successes {
                println!("  {}", r.display().green().bold());
            }
        }
        println!();
    }
}

impl Drop for LiveDashboard {
    fn drop(&mut self) {
        self.spinner.finish_and_clear();
        self.progress.finish_and_clear();
        self.status_bar.finish_and_clear();
    }
}

fn write_output(format: &OutputFormat, csv_writer: Option<&mut csv::Writer<std::fs::File>>, file: &mut std::fs::File, result: &AuthResult) {
    match format {
        OutputFormat::Json => {
            if let Ok(json) = serde_json::to_string(result) {
                let _ = writeln!(file, "{}", json);
            }
        }
        OutputFormat::Csv => {
            if let Some(w) = csv_writer {
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

pub struct OutputHandler {
    pub dashboard: Option<LiveDashboard>,
    format: OutputFormat,
    file: Option<std::fs::File>,
    writer: Option<csv::Writer<std::fs::File>>,
    verbose: u8,
    _start_time: Instant,
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
            _start_time: Instant::now(),
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
            write_output(&self.format, self.writer.as_mut(), file, result);
        }
    }

    pub fn set_status(&self, msg: String) {
        if let Some(ref d) = self.dashboard {
            d.set_status(msg);
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
        println!();
        println!("{}", "┌──────────────────────────────────────┐".cyan().bold());
        println!("{}", "│           ATTACK COMPLETE             │".green().bold());
        println!("{}", "└──────────────────────────────────────┘".cyan().bold());
        println!();

        let mut lines: Vec<(String, String)> = vec![];

        if let (Some(start), Some(_end), Some(dur)) =
            (Some(summary.start_time), summary.end_time, summary.total_duration)
        {
            lines.push(("Started".into(), format!("{}", start.format("%Y-%m-%d %H:%M:%S"))));
            lines.push(("Duration".into(), format!("{:.2}s", dur.as_secs_f64())));
        }
        lines.push(("Targets".into(), summary.total_targets.to_string()));
        lines.push(("Credentials".into(), summary.total_credentials.to_string()));
        lines.push(("Attempts".into(), summary.attempts.to_string()));
        lines.push(("Successes".into(), summary.successes.to_string()));
        lines.push(("Failures".into(), summary.failures.to_string()));
        lines.push(("Errors".into(), summary.errors.to_string()));

        let max_label = lines.iter().map(|(l, _)| l.len()).max().unwrap_or(10);
        for (label, value) in &lines {
            let color = match label.as_str() {
                "Successes" => Color::Green,
                "Failures" => Color::Red,
                "Errors" => Color::Yellow,
                _ => Color::White,
            };
            println!("  {:>width$}  {}",
                label.bold().cyan(),
                value.color(color),
                width = max_label,
            );
        }

        let successes: Vec<_> = summary.results.iter().filter(|r| r.success).collect();
        if !successes.is_empty() {
            println!();
            println!("{}", "┌──────────────────────────────────────┐".green().bold());
            println!("{}", "│          FOUND CREDENTIALS            │".green().bold());
            println!("{}", "└──────────────────────────────────────┘".green().bold());
            for r in &successes {
                println!("  {}", r.display().green().bold());
            }
        }
        println!();
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

    #[test]
    fn test_fmt_dur() {
        assert_eq!(fmt_dur(Duration::from_secs(5)), "05s");
        assert_eq!(fmt_dur(Duration::from_secs(125)), "02m 05s");
        assert_eq!(fmt_dur(Duration::from_secs(3661)), "01h 01m");
    }
}
