use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct AttackConfig {
    pub targets: Vec<String>,
    pub target_file: Option<PathBuf>,
    pub users: Vec<String>,
    pub passwords: Vec<String>,
    pub user_file: Option<PathBuf>,
    pub password_file: Option<PathBuf>,
    pub combo_file: Option<PathBuf>,
    pub protocols: Vec<String>,
    pub ports: Vec<u16>,
    pub threads: usize,
    pub timeout: Duration,
    pub delay: Duration,
    pub rate_limit: Option<u64>,
    pub proxy: Option<String>,
    pub proxy_file: Option<PathBuf>,
    pub output_file: Option<PathBuf>,
    pub output_format: OutputFormat,
    pub resume_file: Option<PathBuf>,
    #[allow(dead_code)]
    pub verbose: bool,
    #[allow(dead_code)]
    pub quiet: bool,
    #[allow(dead_code)]
    pub no_banner: bool,
    pub single_user_mode: bool,
    pub spray_mode: bool,
    pub stop_on_first: bool,
    pub retries: u32,
    pub rule_file: Option<PathBuf>,
    pub max_mutations: usize,
}

#[derive(Clone, Debug)]
pub enum OutputFormat {
    Json,
    Csv,
    Plain,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "json" => OutputFormat::Json,
            "csv" => OutputFormat::Csv,
            _ => OutputFormat::Plain,
        }
    }
}

impl AttackConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.targets.is_empty() && self.target_file.is_none() {
            return Err("No targets specified. Use --target or --target-file.".into());
        }
        if self.protocols.is_empty() {
            return Err("No protocols specified. Use --protocol.".into());
        }
        if self.combo_file.is_none() {
            if self.users.is_empty() && self.user_file.is_none() {
                return Err("No users specified. Use --user, --user-file, or --combo.".into());
            }
            if self.passwords.is_empty() && self.password_file.is_none() {
                return Err("No passwords specified. Use --password, --password-file, or --combo."
                    .into());
            }
        }
        if self.threads == 0 {
            return Err("Thread count must be > 0".into());
        }
        if self.max_mutations == 0 {
            return Err("Max mutations must be > 0".into());
        }
        Ok(())
    }
}
