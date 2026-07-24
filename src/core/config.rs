use std::path::PathBuf;
use std::time::Duration;

use super::error::AttackError;

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
    pub proxy_chain: Option<String>,
    pub output_file: Option<PathBuf>,
    pub output_format: OutputFormat,
    pub resume_file: Option<PathBuf>,
    #[allow(dead_code)]
    pub config_file: Option<PathBuf>,
    pub checkpoint_interval: u64,
    pub verbose: bool,
    pub quiet: bool,
    pub no_banner: bool,
    pub single_user_mode: bool,
    pub spray_mode: bool,
    pub stop_on_first: bool,
    pub retries: u32,
    pub rule_file: Option<PathBuf>,
    pub max_mutations: usize,
    pub max_password_len: Option<usize>,
}

#[derive(Clone, Debug)]
pub enum OutputFormat {
    Json,
    Csv,
    Plain,
    Html,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "json" => OutputFormat::Json,
            "csv" => OutputFormat::Csv,
            "html" => OutputFormat::Html,
            _ => OutputFormat::Plain,
        }
    }
}

impl AttackConfig {
    pub fn validate(&self) -> Result<(), AttackError> {
        if self.targets.is_empty() && self.target_file.is_none() {
            return Err(AttackError::config(
                "No targets specified. Use --target or --target-file.",
            ));
        }
        if self.protocols.is_empty() {
            return Err(AttackError::config(
                "No protocols specified. Use --protocol.",
            ));
        }
        if self.combo_file.is_none() {
            if self.users.is_empty() && self.user_file.is_none() {
                return Err(AttackError::config(
                    "No users specified. Use --user, --user-file, or --combo.",
                ));
            }
            if self.passwords.is_empty() && self.password_file.is_none() {
                return Err(AttackError::config(
                    "No passwords specified. Use --password, --password-file, or --combo.",
                ));
            }
        }
        if self.threads == 0 {
            return Err(AttackError::config("Thread count must be > 0"));
        }
        if self.max_mutations == 0 {
            return Err(AttackError::config("Max mutations must be > 0"));
        }
        if self.checkpoint_interval == 0 {
            return Err(AttackError::config("Checkpoint interval must be > 0"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_config() -> AttackConfig {
        AttackConfig {
            targets: vec!["10.0.0.1".into()],
            target_file: None,
            users: vec!["admin".into()],
            passwords: vec!["pass".into()],
            user_file: None,
            password_file: None,
            combo_file: None,
            protocols: vec!["ssh".into()],
            ports: vec![22],
            threads: 10,
            timeout: Duration::from_secs(5),
            delay: Duration::ZERO,
            rate_limit: None,
            proxy: None,
            proxy_file: None,
            proxy_chain: None,
            output_file: None,
            output_format: OutputFormat::Plain,
            resume_file: None,
            config_file: None,
            checkpoint_interval: 100,
            verbose: false,
            quiet: false,
            no_banner: false,
            single_user_mode: false,
            spray_mode: false,
            stop_on_first: false,
            retries: 1,
            rule_file: None,
            max_mutations: 500,
            max_password_len: None,
        }
    }

    #[test]
    fn test_validate_ok() {
        let cfg = make_config();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_validate_no_targets() {
        let mut cfg = make_config();
        cfg.targets.clear();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_no_protocols() {
        let mut cfg = make_config();
        cfg.protocols.clear();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_no_users() {
        let mut cfg = make_config();
        cfg.users.clear();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_no_passwords() {
        let mut cfg = make_config();
        cfg.passwords.clear();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_zero_threads() {
        let mut cfg = make_config();
        cfg.threads = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_output_format_from_str() {
        assert!(matches!(OutputFormat::from_str("json"), OutputFormat::Json));
        assert!(matches!(OutputFormat::from_str("csv"), OutputFormat::Csv));
        assert!(matches!(OutputFormat::from_str("html"), OutputFormat::Html));
        assert!(matches!(OutputFormat::from_str("plain"), OutputFormat::Plain));
        assert!(matches!(OutputFormat::from_str("unknown"), OutputFormat::Plain));
        assert!(matches!(OutputFormat::from_str("JSON"), OutputFormat::Json));
    }

    #[test]
    fn test_with_combo_file_skips_user_pass_check() {
        let mut cfg = make_config();
        cfg.users.clear();
        cfg.passwords.clear();
        cfg.combo_file = Some(PathBuf::from("combos.txt"));
        assert!(cfg.validate().is_ok());
    }
}
