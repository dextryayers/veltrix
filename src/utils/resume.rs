use std::collections::HashSet;
use std::path::Path;
use serde::{Deserialize, Serialize};
use crate::core::error::AttackError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub version: u32,
    pub targets: Vec<String>,
    pub protocols: Vec<String>,
    pub users_tested: HashSet<String>,
    pub passwords_tested: HashSet<String>,
    pub combos_tested: HashSet<String>,
    pub successes: Vec<session::SessionResult>,
    pub total_attempts: u64,
    pub checkpoint_interval: u64,
}

pub mod session {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SessionResult {
        pub target: String,
        pub protocol: String,
        pub username: String,
        pub password: String,
    }
}

impl SessionState {
    #[allow(dead_code)]
    pub fn new(targets: Vec<String>, protocols: Vec<String>, checkpoint_interval: u64) -> Self {
        SessionState {
            version: 1,
            targets,
            protocols,
            users_tested: HashSet::new(),
            passwords_tested: HashSet::new(),
            combos_tested: HashSet::new(),
            successes: Vec::new(),
            total_attempts: 0,
            checkpoint_interval,
        }
    }

    pub fn is_tested(&self, username: &str, password: &str) -> bool {
        let combo = format!("{}:{}", username, password);
        self.combos_tested.contains(&combo)
    }

    pub fn mark_tested(&mut self, username: &str, password: &str) {
        let combo = format!("{}:{}", username, password);
        self.combos_tested.insert(combo);
        self.users_tested.insert(username.to_string());
        self.passwords_tested.insert(password.to_string());
        self.total_attempts += 1;
    }

    pub fn add_success(&mut self, target: &str, protocol: &str, username: &str, password: &str) {
        self.successes.push(session::SessionResult {
            target: target.to_string(),
            protocol: protocol.to_string(),
            username: username.to_string(),
            password: password.to_string(),
        });
    }

    pub fn save(&self, path: &Path) -> Result<(), AttackError> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| AttackError::session(format!("Serialization: {}", e)))?;
        std::fs::write(path, json)
            .map_err(|e| AttackError::session(format!("Write failed: {}", e)))
    }

    pub fn load(path: &Path) -> Result<Self, AttackError> {
        let json = std::fs::read_to_string(path)
            .map_err(|e| AttackError::session(format!("Read failed: {}", e)))?;
        serde_json::from_str(&json)
            .map_err(|e| AttackError::session(format!("Parse failed: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_mark_and_check() {
        let mut session = SessionState {
            version: 1,
            targets: vec!["10.0.0.1:22".into()],
            protocols: vec!["ssh".into()],
            users_tested: HashSet::new(),
            passwords_tested: HashSet::new(),
            combos_tested: HashSet::new(),
            successes: Vec::new(),
            total_attempts: 0,
            checkpoint_interval: 100,
        };

        assert!(!session.is_tested("admin", "pass123"));
        session.mark_tested("admin", "pass123");
        assert!(session.is_tested("admin", "pass123"));
        assert_eq!(session.total_attempts, 1);
    }

    #[test]
    fn test_session_add_success() {
        let mut session = SessionState {
            version: 1,
            targets: vec![],
            protocols: vec![],
            users_tested: HashSet::new(),
            passwords_tested: HashSet::new(),
            combos_tested: HashSet::new(),
            successes: Vec::new(),
            total_attempts: 0,
            checkpoint_interval: 100,
        };

        session.add_success("10.0.0.1:22", "ssh", "admin", "pass");
        assert_eq!(session.successes.len(), 1);
        assert_eq!(session.successes[0].username, "admin");
        assert_eq!(session.successes[0].password, "pass");
    }

    #[test]
    fn test_session_save_and_load() {
        let mut session = SessionState {
            version: 1,
            targets: vec!["target:22".into()],
            protocols: vec!["ssh".into()],
            users_tested: HashSet::new(),
            passwords_tested: HashSet::new(),
            combos_tested: HashSet::new(),
            successes: Vec::new(),
            total_attempts: 0,
            checkpoint_interval: 100,
        };
        session.mark_tested("admin", "pass");

        let dir = std::env::temp_dir();
        let path = dir.join("test_session.json");
        session.save(&path).unwrap();

        let loaded = SessionState::load(&path).unwrap();
        assert_eq!(loaded.version, 1);
        assert!(loaded.is_tested("admin", "pass"));
        assert!(!loaded.is_tested("other", "pass"));

        std::fs::remove_file(&path).ok();
    }
}
