use std::io::Write;
use std::path::Path;
use std::time::Instant;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};

use crate::core::config::OutputFormat;
use crate::core::result::{AttackSummary, AuthResult};

pub struct OutputHandler {
    format: OutputFormat,
    file: Option<std::fs::File>,
    writer: Option<csv::Writer<std::fs::File>>,
    progress: Option<ProgressBar>,
    start_time: Instant,
    success_count: u64,
    fail_count: u64,
    #[allow(dead_code)]
    quiet: bool,
    verbose: bool,
}

impl OutputHandler {
    pub fn new(format: OutputFormat, output_path: Option<&Path>, quiet: bool, verbose: bool) -> Result<Self, String> {
        let (file, writer) = if let Some(path) = output_path {
            let f = std::fs::File::create(path)
                .map_err(|e| format!("Cannot create output file: {}", e))?;
            let w = match format {
                OutputFormat::Csv => Some(csv::Writer::from_writer(f.try_clone().map_err(|_| "Cannot clone file".to_string())?)),
                _ => None,
            };
            (Some(f), w)
        } else {
            (None, None)
        };

        Ok(OutputHandler {
            format, file, writer, progress: None,
            start_time: Instant::now(),
            success_count: 0,
            fail_count: 0,
            quiet,
            verbose,
        })
    }

    pub fn init_progress(&mut self, total: u64) {
        let pb = ProgressBar::new(total);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
                .unwrap()
                .progress_chars("##-"),
        );
        self.progress = Some(pb);
    }

    pub fn inc_progress(&self) {
        if let Some(pb) = &self.progress {
            pb.inc(1);
        }
    }

    pub fn finish_progress(&self) {
        if let Some(pb) = &self.progress {
            let rate = if self.start_time.elapsed().as_secs() > 0 {
                let total = self.success_count + self.fail_count;
                total as f64 / self.start_time.elapsed().as_secs_f64()
            } else {
                0.0
            };
            pb.finish_with_message(
                format!("{} found | {:.0} att/s", self.success_count, rate)
            );
        }
    }

    pub fn write_result(&mut self, result: &AuthResult) {
        if result.success {
            self.success_count += 1;
            println!("{}", result.display());
        } else {
            self.fail_count += 1;
            if self.verbose {
                eprintln!("{}", result.display());
            }
        }

        if let Some(file) = &mut self.file {
            match self.format {
                OutputFormat::Json => {
                    if let Ok(json) = serde_json::to_string(result) {
                        let _ = writeln!(file, "{}", json);
                    }
                }
                OutputFormat::Csv => {
                    if let Some(writer) = &mut self.writer {
                        let _ = writer.write_record(&[
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
                        let _ = writer.flush();
                    }
                }
                OutputFormat::Plain => {
                    let _ = writeln!(file, "{}", result.display());
                }
            }
        }
    }

    pub fn write_summary(&mut self, summary: &AttackSummary) {
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
