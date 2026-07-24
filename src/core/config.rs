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
    pub proxy_file: Option<PathBuf>,
    pub output_file: Option<PathBuf>,
    pub output_format: OutputFormat,
    pub resume_file: Option<PathBuf>,
    #[allow(dead_code)]
    pub verbose: bool,
    pub single_user_mode: bool,
    pub spray_mode: bool,
    pub stop_on_first: bool,
    pub retries: u32,
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_no_targets() {
        let config = AttackConfig {
            targets: vec![],
            target_file: None,
            users: vec!["admin".into()],
            passwords: vec!["pass".into()],
            protocols: vec!["ssh".into()],
            ..create_dummy_config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_no_protocols() {
        let config = AttackConfig {
            protocols: vec![],
            ..create_valid_config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_no_credentials() {
        let config = AttackConfig {
            users: vec![],
            user_file: None,
            combo_file: None,
            ..create_valid_config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_combo_ok() {
        let config = AttackConfig {
            combo_file: Some(PathBuf::from("combos.txt")),
            users: vec![],
            user_file: None,
            passwords: vec![],
            password_file: None,
            ..create_valid_config()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_valid_config() {
        let config = create_valid_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_output_format_from_str() {
        assert!(matches!(OutputFormat::from_str("json"), OutputFormat::Json));
        assert!(matches!(OutputFormat::from_str("csv"), OutputFormat::Csv));
        assert!(matches!(OutputFormat::from_str("plain"), OutputFormat::Plain));
        assert!(matches!(OutputFormat::from_str("unknown"), OutputFormat::Plain));
    }

    fn create_valid_config() -> AttackConfig {
        AttackConfig {
            targets: vec!["192.168.1.1:22".into()],
            target_file: None,
            users: vec!["admin".into()],
            passwords: vec!["password".into()],
            user_file: None,
            password_file: None,
            combo_file: None,
            protocols: vec!["ssh".into()],
            ports: vec![],
            threads: 10,
            timeout: Duration::from_secs(10),
            delay: Duration::from_millis(0),
            rate_limit: None,
            proxy_file: None,
            output_file: None,
            output_format: OutputFormat::Plain,
            resume_file: None,
            verbose: false,
            single_user_mode: false,
            spray_mode: false,
            stop_on_first: false,
            retries: 1,
        }
    }

    fn create_dummy_config() -> AttackConfig {
        AttackConfig {
            targets: vec![],
            target_file: None,
            users: vec![],
            passwords: vec![],
            user_file: None,
            password_file: None,
            combo_file: None,
            protocols: vec![],
            ports: vec![],
            threads: 10,
            timeout: Duration::from_secs(10),
            delay: Duration::from_millis(0),
            rate_limit: None,
            proxy_file: None,
            output_file: None,
            output_format: OutputFormat::Plain,
            resume_file: None,
            verbose: false,
            single_user_mode: false,
            spray_mode: false,
            stop_on_first: false,
            retries: 1,
        }
    }
}
