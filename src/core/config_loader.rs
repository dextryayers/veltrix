use std::path::{Path, PathBuf};
use serde::Deserialize;
use super::config::AttackConfig;
use super::error::AttackError;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    #[serde(default)]
    pub attack: AttackSection,
    #[serde(default)]
    pub credentials: CredentialsSection,
    #[serde(default)]
    pub hybrid: HybridSection,
    #[serde(default)]
    pub performance: PerformanceSection,
    #[serde(default)]
    pub proxy: ProxySection,
    #[serde(default)]
    pub output: OutputSection,
    #[serde(default)]
    pub behavior: BehaviorSection,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AttackSection {
    pub targets: Vec<String>,
    pub target_file: Option<String>,
    pub protocols: Vec<String>,
    pub ports: Vec<u16>,
}

impl Default for AttackSection {
    fn default() -> Self {
        AttackSection {
            targets: Vec::new(),
            target_file: None,
            protocols: Vec::new(),
            ports: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CredentialsSection {
    pub users: Vec<String>,
    pub passwords: Vec<String>,
    pub user_file: Option<String>,
    pub password_file: Option<String>,
    pub combo_file: Option<String>,
    pub single_user: bool,
    pub spray: bool,
    pub max_password_len: Option<usize>,
    pub rdp_domain: Option<String>,
    pub http_userfield: Option<String>,
    pub http_passfield: Option<String>,
    pub http_success: Option<String>,
}

impl Default for CredentialsSection {
    fn default() -> Self {
        CredentialsSection {
            users: Vec::new(),
            passwords: Vec::new(),
            user_file: None,
            password_file: None,
            combo_file: None,
            single_user: false,
            spray: false,
            max_password_len: None,
            rdp_domain: None,
            http_userfield: None,
            http_passfield: None,
            http_success: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HybridSection {
    pub rules: Option<String>,
    pub max_mutations: Option<usize>,
}

impl Default for HybridSection {
    fn default() -> Self {
        HybridSection {
            rules: None,
            max_mutations: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PerformanceSection {
    pub threads: Option<usize>,
    pub timeout: Option<u64>,
    pub delay: Option<u64>,
    pub rate_limit: Option<u64>,
    pub retries: Option<u32>,
}

impl Default for PerformanceSection {
    fn default() -> Self {
        PerformanceSection {
            threads: None,
            timeout: None,
            delay: None,
            rate_limit: None,
            retries: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ProxySection {
    pub proxy: Option<String>,
    pub proxy_file: Option<String>,
    pub proxy_chain: Option<String>,
}

impl Default for ProxySection {
    fn default() -> Self {
        ProxySection {
            proxy: None,
            proxy_file: None,
            proxy_chain: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct OutputSection {
    pub file: Option<String>,
    pub format: Option<String>,
    pub resume: Option<String>,
}

impl Default for OutputSection {
    fn default() -> Self {
        OutputSection {
            file: None,
            format: None,
            resume: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BehaviorSection {
    pub stop_on_first: Option<bool>,
    pub verbose: Option<bool>,
    pub quiet: Option<bool>,
    pub no_banner: Option<bool>,
}

impl Default for BehaviorSection {
    fn default() -> Self {
        BehaviorSection {
            stop_on_first: None,
            verbose: None,
            quiet: None,
            no_banner: None,
        }
    }
}

impl ConfigFile {
    pub fn load(path: &Path) -> Result<Self, AttackError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| AttackError::io("config", format!("Failed to read '{}': {}", path.display(), e)))?;
        serde_json::from_str(&content)
            .map_err(|e| AttackError::config(format!("Failed to parse config '{}': {}", path.display(), e)))
    }

    pub fn merge_into(self, config: &mut AttackConfig) {
        let a = self.attack;
        if !a.targets.is_empty() {
            config.targets = a.targets;
        }
        if let Some(f) = a.target_file {
            config.target_file = Some(PathBuf::from(f));
        }
        if !a.protocols.is_empty() {
            config.protocols = a.protocols;
        }
        if !a.ports.is_empty() {
            config.ports = a.ports;
        }

        let c = self.credentials;
        if !c.users.is_empty() {
            config.users = c.users;
        }
        if !c.passwords.is_empty() {
            config.passwords = c.passwords;
        }
        if let Some(f) = c.user_file {
            config.user_file = Some(PathBuf::from(f));
        }
        if let Some(f) = c.password_file {
            config.password_file = Some(PathBuf::from(f));
        }
        if let Some(f) = c.combo_file {
            config.combo_file = Some(PathBuf::from(f));
        }
        if c.single_user {
            config.single_user_mode = true;
        }
        if c.spray {
            config.spray_mode = true;
        }
        if let Some(n) = c.max_password_len {
            config.max_password_len = Some(n);
        }
        if let Some(d) = c.rdp_domain {
            config.rdp_domain = Some(d);
        }
        if let Some(v) = c.http_userfield {
            config.http_userfield = Some(v);
        }
        if let Some(v) = c.http_passfield {
            config.http_passfield = Some(v);
        }
        if let Some(v) = c.http_success {
            config.http_success = Some(v);
        }

        let h = self.hybrid;
        if let Some(f) = h.rules {
            config.rule_file = Some(PathBuf::from(f));
        }
        if let Some(n) = h.max_mutations {
            config.max_mutations = n;
        }

        let p = self.performance;
        if let Some(n) = p.threads {
            config.threads = n;
        }
        if let Some(n) = p.timeout {
            config.timeout = std::time::Duration::from_secs(n);
        }
        if let Some(n) = p.delay {
            config.delay = std::time::Duration::from_millis(n);
        }
        if let Some(n) = p.rate_limit {
            config.rate_limit = Some(n);
        }
        if let Some(n) = p.retries {
            config.retries = n;
        }

        let pr = self.proxy;
        if let Some(s) = pr.proxy {
            config.proxy = Some(s);
        }
        if let Some(f) = pr.proxy_file {
            config.proxy_file = Some(PathBuf::from(f));
        }
        if let Some(c) = pr.proxy_chain {
            config.proxy_chain = Some(c);
        }

        let o = self.output;
        if let Some(f) = o.file {
            config.output_file = Some(PathBuf::from(f));
        }
        if let Some(f) = o.format {
            config.output_format = super::config::OutputFormat::from_str(&f);
        }
        if let Some(f) = o.resume {
            config.resume_file = Some(PathBuf::from(f));
        }

        let b = self.behavior;
        if let Some(v) = b.stop_on_first {
            config.stop_on_first = v;
        }
        if let Some(v) = b.verbose {
            config.verbose = if v { 1 } else { 0 };
        }
        if let Some(v) = b.quiet {
            config.quiet = v;
        }
        if let Some(v) = b.no_banner {
            config.no_banner = v;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_config(content: &str, name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir();
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn test_load_valid_config() {
        let json = r#"{"attack":{"targets":["10.0.0.1:22"],"protocols":["ssh"]},"credentials":{"users":["admin"],"passwords":["pass"]}}"#;
        let path = write_config(json, "test_valid_config.json");
        let cf = ConfigFile::load(&path).unwrap();
        assert_eq!(cf.attack.targets, vec!["10.0.0.1:22"]);
        assert_eq!(cf.attack.protocols, vec!["ssh"]);
        assert_eq!(cf.credentials.users, vec!["admin"]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_load_invalid_config_fails() {
        let path = write_config("not valid json", "test_invalid_config.json");
        assert!(ConfigFile::load(&path).is_err());
        std::fs::remove_file(&path).ok();
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
    fn test_merge_into_targets() {
        let mut cfg = base_config();
        let cf = ConfigFile {
            attack: AttackSection {
                targets: vec!["10.0.0.1:22".into()],
                target_file: None,
                protocols: vec!["ssh".into()],
                ports: vec![],
            },
            credentials: CredentialsSection {
                users: vec!["admin".into()],
                passwords: vec!["pass".into()],
                user_file: None,
                password_file: None,
                combo_file: None,
                single_user: false,
                spray: false,
                max_password_len: None,
                rdp_domain: None,
                http_userfield: None,
                http_passfield: None,
                http_success: None,
            },
            hybrid: HybridSection { rules: None, max_mutations: None },
            performance: PerformanceSection {
                threads: None, timeout: None, delay: None,
                rate_limit: None, retries: None,
            },
            proxy: ProxySection { proxy: None, proxy_file: None, proxy_chain: None },
            output: OutputSection { file: None, format: None, resume: None },
            behavior: BehaviorSection {
                stop_on_first: None, verbose: None,
                quiet: None, no_banner: None,
            },
        };
        cf.merge_into(&mut cfg);
        assert_eq!(cfg.targets, vec!["10.0.0.1:22"]);
        assert_eq!(cfg.protocols, vec!["ssh"]);
        assert_eq!(cfg.users, vec!["admin"]);
        assert_eq!(cfg.passwords, vec!["pass"]);
    }

    #[test]
    fn test_merge_into_performance_overrides() {
        let json = r#"{"performance":{"threads":50,"timeout":30,"retries":3}}"#;
        let path = write_config(json, "test_perf_config.json");
        let cf = ConfigFile::load(&path).unwrap();
        let mut cfg = base_config();
        cfg.targets = vec!["10.0.0.1:22".into()];
        cfg.users = vec!["admin".into()];
        cfg.passwords = vec!["pass".into()];
        cfg.protocols = vec!["ssh".into()];
        cf.merge_into(&mut cfg);
        assert_eq!(cfg.threads, 50);
        assert_eq!(cfg.timeout.as_secs(), 30);
        assert_eq!(cfg.retries, 3);
        std::fs::remove_file(&path).ok();
    }
}
