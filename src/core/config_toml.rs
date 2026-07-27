use std::path::Path;
use serde::Deserialize;
use super::config::AttackConfig;
use super::error::AttackError;

#[derive(Debug, Clone, Deserialize)]
pub struct TomlConfig {
    pub attack: Option<TomlAttackSection>,
    pub credentials: Option<TomlCredentialsSection>,
    pub hybrid: Option<TomlHybridSection>,
    pub performance: Option<TomlPerformanceSection>,
    pub proxy: Option<TomlProxySection>,
    pub output: Option<TomlOutputSection>,
    pub behavior: Option<TomlBehaviorSection>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TomlAttackSection {
    pub targets: Option<Vec<String>>,
    pub target_file: Option<String>,
    pub protocols: Option<Vec<String>>,
    pub ports: Option<Vec<u16>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TomlCredentialsSection {
    pub users: Option<Vec<String>>,
    pub passwords: Option<Vec<String>>,
    pub user_file: Option<String>,
    pub password_file: Option<String>,
    pub combo_file: Option<String>,
    pub single_user: Option<bool>,
    pub spray: Option<bool>,
    pub max_password_len: Option<usize>,
    pub rdp_domain: Option<String>,
    pub http_userfield: Option<String>,
    pub http_passfield: Option<String>,
    pub http_success: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TomlHybridSection {
    pub rules: Option<String>,
    pub max_mutations: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TomlPerformanceSection {
    pub threads: Option<usize>,
    pub timeout: Option<u64>,
    pub delay: Option<u64>,
    pub rate_limit: Option<u64>,
    pub retries: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TomlProxySection {
    pub proxy: Option<String>,
    pub proxy_file: Option<String>,
    pub proxy_chain: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TomlOutputSection {
    pub file: Option<String>,
    pub format: Option<String>,
    pub resume: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TomlBehaviorSection {
    pub stop_on_first: Option<bool>,
    pub verbose: Option<bool>,
    pub quiet: Option<bool>,
    pub no_banner: Option<bool>,
}

impl TomlConfig {
    pub fn load(path: &Path) -> Result<Self, AttackError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| AttackError::io("config", format!("Failed to read '{}': {}", path.display(), e)))?;
        toml::from_str(&content)
            .map_err(|e| AttackError::config(format!("Failed to parse TOML config '{}': {}", path.display(), e)))
    }

    pub fn merge_into(self, config: &mut AttackConfig) {
        if let Some(a) = self.attack {
            if let Some(t) = a.targets { if !t.is_empty() { config.targets = t; } }
            if let Some(f) = a.target_file { config.target_file = Some(std::path::PathBuf::from(f)); }
            if let Some(p) = a.protocols { if !p.is_empty() { config.protocols = p; } }
            if let Some(p) = a.ports { if !p.is_empty() { config.ports = p; } }
        }

        if let Some(c) = self.credentials {
            if let Some(u) = c.users { if !u.is_empty() { config.users = u; } }
            if let Some(p) = c.passwords { if !p.is_empty() { config.passwords = p; } }
            if let Some(f) = c.user_file { config.user_file = Some(std::path::PathBuf::from(f)); }
            if let Some(f) = c.password_file { config.password_file = Some(std::path::PathBuf::from(f)); }
            if let Some(f) = c.combo_file { config.combo_file = Some(std::path::PathBuf::from(f)); }
            if let Some(v) = c.single_user { config.single_user_mode = v; }
            if let Some(v) = c.spray { config.spray_mode = v; }
            if let Some(n) = c.max_password_len { config.max_password_len = Some(n); }
            if let Some(d) = c.rdp_domain { config.rdp_domain = Some(d); }
            if let Some(v) = c.http_userfield { config.http_userfield = Some(v); }
            if let Some(v) = c.http_passfield { config.http_passfield = Some(v); }
            if let Some(v) = c.http_success { config.http_success = Some(v); }
        }

        if let Some(h) = self.hybrid {
            if let Some(f) = h.rules { config.rule_file = Some(std::path::PathBuf::from(f)); }
            if let Some(n) = h.max_mutations { config.max_mutations = n; }
        }

        if let Some(p) = self.performance {
            if let Some(n) = p.threads { config.threads = n; }
            if let Some(n) = p.timeout { config.timeout = std::time::Duration::from_secs(n); }
            if let Some(n) = p.delay { config.delay = std::time::Duration::from_millis(n); }
            if let Some(n) = p.rate_limit { config.rate_limit = Some(n); }
            if let Some(n) = p.retries { config.retries = n; }
        }

        if let Some(p) = self.proxy {
            if let Some(s) = p.proxy { config.proxy = Some(s); }
            if let Some(f) = p.proxy_file { config.proxy_file = Some(std::path::PathBuf::from(f)); }
            if let Some(c) = p.proxy_chain { config.proxy_chain = Some(c); }
        }

        if let Some(o) = self.output {
            if let Some(f) = o.file { config.output_file = Some(std::path::PathBuf::from(f)); }
            if let Some(f) = o.format { config.output_format = super::config::OutputFormat::from_str(&f); }
            if let Some(f) = o.resume { config.resume_file = Some(std::path::PathBuf::from(f)); }
        }

        if let Some(b) = self.behavior {
            if let Some(v) = b.stop_on_first { config.stop_on_first = v; }
            if let Some(v) = b.verbose { config.verbose = if v { 1 } else { 0 }; }
            if let Some(v) = b.quiet { config.quiet = v; }
            if let Some(v) = b.no_banner { config.no_banner = v; }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_toml(content: &str, name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir();
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    fn base_config() -> AttackConfig {
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
            timeout: std::time::Duration::from_secs(5),
            delay: std::time::Duration::ZERO,
            rate_limit: None,
            proxy: None,
            proxy_file: None,
            proxy_chain: None,
            output_file: None,
            output_format: crate::core::config::OutputFormat::Plain,
            resume_file: None,
            config_file: None,
            checkpoint_interval: 100,
            verbose: 0,
            quiet: false,
            no_banner: false,
            single_user_mode: false,
            rdp_domain: None,
            http_userfield: None,
            http_passfield: None,
            http_success: None,
            spray_mode: false,
            stop_on_first: false,
            retries: 1,
            rule_file: None,
            max_mutations: 500,
            max_password_len: None,
            distributed: None,
            distributed_token: None,
            distributed_name: None,
            plugins: vec![],
            api_bind: None,
            encrypt: false,
            encrypt_passphrase: None,
            decrypt_file: None,
            decrypt_output: None,
        }
    }

    #[test]
    fn test_load_toml_valid() {
        let toml_str = r#"
[attack]
targets = ["10.0.0.1:22"]
protocols = ["ssh"]

[credentials]
users = ["admin"]
passwords = ["pass"]
"#;
        let path = write_toml(toml_str, "test_toml_valid.toml");
        let tc = TomlConfig::load(&path).unwrap();
        let a = tc.attack.unwrap();
        assert_eq!(a.targets.unwrap(), vec!["10.0.0.1:22"]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_load_toml_invalid() {
        let path = write_toml("not valid toml {{", "test_toml_invalid.toml");
        assert!(TomlConfig::load(&path).is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_toml_merge_targets() {
        let toml_str = r#"
[attack]
targets = ["10.0.0.1:22"]
protocols = ["ssh"]

[credentials]
users = ["admin"]
passwords = ["pass"]
"#;
        let path = write_toml(toml_str, "test_toml_merge.toml");
        let tc = TomlConfig::load(&path).unwrap();
        let mut cfg = base_config();
        tc.merge_into(&mut cfg);
        assert_eq!(cfg.targets, vec!["10.0.0.1:22"]);
        assert_eq!(cfg.users, vec!["admin"]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_toml_merge_performance() {
        let toml_str = r#"
[performance]
threads = 50
timeout = 30
retries = 3
"#;
        let path = write_toml(toml_str, "test_toml_perf.toml");
        let tc = TomlConfig::load(&path).unwrap();
        let mut cfg = base_config();
        tc.merge_into(&mut cfg);
        assert_eq!(cfg.threads, 50);
        assert_eq!(cfg.timeout.as_secs(), 30);
        assert_eq!(cfg.retries, 3);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_toml_empty() {
        let toml_str = "";
        let path = write_toml(toml_str, "test_toml_empty.toml");
        let tc = TomlConfig::load(&path).unwrap();
        assert!(tc.attack.is_none());
        std::fs::remove_file(&path).ok();
    }
}
