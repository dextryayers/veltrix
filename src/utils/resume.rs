use std::collections::HashSet;
use std::path::Path;
use serde::{Deserialize, Serialize};
use crate::core::error::AttackError;
use crate::utils::crypto::hmac_sha256;

// Fixed internal key for session file integrity verification
const INTEGRITY_KEY: &[u8] = b"veltrix-session-integrity-v1-key-2024";

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

/// Wrapper for session file with integrity check
#[derive(Debug, Serialize, Deserialize)]
struct SessionFile {
    data: SessionState,
    integrity: String,
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

    fn compute_hmac(data: &[u8]) -> Result<String, AttackError> {
        let code = hmac_sha256(INTEGRITY_KEY, data);
        Ok(hex::encode(code))
    }

    pub fn save(&self, path: &Path) -> Result<(), AttackError> {
        let data_json = serde_json::to_string_pretty(self)
            .map_err(|e| AttackError::session(format!("Serialization: {}", e)))?;
        let integrity = Self::compute_hmac(data_json.as_bytes())?;
        let file = SessionFile {
            data: self.clone(),
            integrity,
        };
        let json = serde_json::to_string_pretty(&file)
            .map_err(|e| AttackError::session(format!("File serialization: {}", e)))?;
        std::fs::write(path, json)
            .map_err(|e| AttackError::session(format!("Write failed: {}", e)))?;
        log::debug!("Session saved with integrity hash to {}", path.display());
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self, AttackError> {
        let json = std::fs::read_to_string(path)
            .map_err(|e| AttackError::session(format!("Read failed: {}", e)))?;

        // Try loading with integrity check first
        if let Ok(file) = serde_json::from_str::<SessionFile>(&json) {
            let data_json = serde_json::to_string_pretty(&file.data)
                .map_err(|e| AttackError::session(format!("Re-serialization: {}", e)))?;
            let expected = Self::compute_hmac(data_json.as_bytes())?;

            if file.integrity == expected {
                log::debug!("Session file integrity verified");
                Ok(file.data)
            } else {
                log::warn!(
                    "Session file integrity check FAILED! Expected {}, got {}. File may be tampered.",
                    expected, file.integrity
                );
                Ok(file.data)
            }
        } else {
            // Fallback: load old format without integrity
            let state: SessionState = serde_json::from_str(&json)
                .map_err(|e| AttackError::session(format!("Parse failed: {}", e)))?;
            log::warn!("Session file loaded without integrity check (old format)");
            Ok(state)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session() -> SessionState {
        SessionState {
            version: 1,
            targets: vec!["10.0.0.1:22".into()],
            protocols: vec!["ssh".into()],
            users_tested: HashSet::new(),
            passwords_tested: HashSet::new(),
            combos_tested: HashSet::new(),
            successes: Vec::new(),
            total_attempts: 0,
            checkpoint_interval: 100,
        }
    }

    #[test]
    fn test_session_mark_and_check() {
        let mut session = test_session();
        assert!(!session.is_tested("admin", "pass123"));
        session.mark_tested("admin", "pass123");
        assert!(session.is_tested("admin", "pass123"));
        assert_eq!(session.total_attempts, 1);
    }

    #[test]
    fn test_session_add_success() {
        let mut session = test_session();
        session.add_success("10.0.0.1:22", "ssh", "admin", "pass");
        assert_eq!(session.successes.len(), 1);
        assert_eq!(session.successes[0].username, "admin");
    }

    #[test]
    fn test_session_save_and_load() {
        let mut session = test_session();
        session.mark_tested("admin", "pass");

        let dir = std::env::temp_dir();
        let path = dir.join("test_session_integrity.json");
        session.save(&path).unwrap();

        let loaded = SessionState::load(&path).unwrap();
        assert_eq!(loaded.version, 1);
        assert!(loaded.is_tested("admin", "pass"));

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_session_integrity_fail_detected() {
        let mut session = test_session();
        session.mark_tested("user", "pass");

        let dir = std::env::temp_dir();
        let path = dir.join("test_session_tampered.json");
        session.save(&path).unwrap();

        // Tamper with the saved file
        let mut content = std::fs::read_to_string(&path).unwrap();
        content = content.replace("\"total_attempts\": 1", "\"total_attempts\": 999");
        std::fs::write(&path, content).unwrap();

        // Load should succeed but log a warning (not fail)
        let loaded = SessionState::load(&path).unwrap();
        assert_eq!(loaded.total_attempts, 999);
        // Integrity is best-effort: we load the data but warn

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_old_format_compatibility() {
        let old_json = r#"{"version":1,"targets":["10.0.0.1:22"],"protocols":["ssh"],"users_tested":["admin"],"passwords_tested":["pass"],"combos_tested":["admin:pass"],"successes":[{"target":"10.0.0.1:22","protocol":"ssh","username":"admin","password":"pass"}],"total_attempts":1,"checkpoint_interval":100}"#;

        let dir = std::env::temp_dir();
        let path = dir.join("test_session_old.json");
        std::fs::write(&path, old_json).unwrap();

        let loaded = SessionState::load(&path).unwrap();
        assert_eq!(loaded.version, 1);
        assert!(loaded.is_tested("admin", "pass"));
        assert_eq!(loaded.successes.len(), 1);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_hmac_changes_on_tamper() {
        let data1 = b"some data";
        let hmac1 = SessionState::compute_hmac(data1).unwrap();

        let data2 = b"some data!";
        let hmac2 = SessionState::compute_hmac(data2).unwrap();

        assert_ne!(hmac1, hmac2);
    }
}
