use std::path::{Path, PathBuf};
use serde::Deserialize;
use super::config::AttackConfig;

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
}

impl Default for ProxySection {
    fn default() -> Self {
        ProxySection {
            proxy: None,
            proxy_file: None,
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
    pub fn load(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file '{}': {}", path.display(), e))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse config file '{}': {}", path.display(), e))
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
            config.verbose = v;
        }
        if let Some(v) = b.quiet {
            config.quiet = v;
        }
        if let Some(v) = b.no_banner {
            config.no_banner = v;
        }
    }
}
