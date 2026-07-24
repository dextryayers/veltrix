use std::time::Duration;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use colored::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    pub target_host: String,
    pub target_port: u16,
    pub protocol: String,
    pub username: String,
    pub password: String,
    pub success: bool,
    pub timestamp: DateTime<Utc>,
    pub duration_ms: u64,
    pub error: Option<String>,
    pub r#type: String,
}

impl AuthResult {
    pub fn new(
        target_host: String,
        target_port: u16,
        protocol: &str,
        username: String,
        password: String,
        success: bool,
        duration: Duration,
        error: Option<String>,
    ) -> Self {
        AuthResult {
            target_host,
            target_port,
            protocol: protocol.to_string(),
            username,
            password,
            success,
            timestamp: Utc::now(),
            duration_ms: duration.as_millis() as u64,
            error,
            r#type: String::new(),
        }
    }

    pub fn display(&self) -> String {
        let status = if self.success {
            "SUCCESS".green().bold()
        } else {
            "FAILED".red()
        };
        format!(
            "[{}] {}:{} [{}] {}:{} ({})",
            status,
            self.target_host,
            self.target_port,
            self.protocol,
            self.username,
            self.password,
            self.duration_ms,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSummary {
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub total_targets: usize,
    pub total_credentials: usize,
    pub attempts: u64,
    pub successes: u64,
    pub failures: u64,
    pub errors: u64,
    pub results: Vec<AuthResult>,
    pub total_duration: Option<Duration>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_auth_result_new_success() {
        let r = AuthResult::new(
            "10.0.0.1".into(), 22, "ssh",
            "admin".into(), "pass".into(),
            true, Duration::from_millis(100), None,
        );
        assert_eq!(r.target_host, "10.0.0.1");
        assert_eq!(r.target_port, 22);
        assert_eq!(r.protocol, "ssh");
        assert_eq!(r.username, "admin");
        assert_eq!(r.password, "pass");
        assert!(r.success);
        assert!(r.error.is_none());
        assert_eq!(r.duration_ms, 100);
    }

    #[test]
    fn test_auth_result_new_failure() {
        let r = AuthResult::new(
            "10.0.0.1".into(), 22, "ssh",
            "admin".into(), "wrong".into(),
            false, Duration::from_millis(50),
            Some("Auth failed".into()),
        );
        assert!(!r.success);
        assert_eq!(r.error.unwrap(), "Auth failed");
    }

    #[test]
    fn test_auth_result_display_success() {
        let r = AuthResult::new(
            "10.0.0.1".into(), 22, "ssh",
            "admin".into(), "pass".into(),
            true, Duration::from_millis(100), None,
        );
        let display = r.display();
        assert!(display.contains("SUCCESS"));
        assert!(display.contains("10.0.0.1"));
        assert!(display.contains("ssh"));
    }

    #[test]
    fn test_auth_result_display_failure() {
        let r = AuthResult::new(
            "10.0.0.1".into(), 22, "ssh",
            "admin".into(), "wrong".into(),
            false, Duration::from_millis(50), None,
        );
        let display = r.display();
        assert!(display.contains("FAILED"));
    }

    #[test]
    fn test_attack_summary_defaults() {
        let now = Utc::now();
        let s = AttackSummary {
            start_time: now,
            end_time: None,
            total_targets: 5,
            total_credentials: 100,
            attempts: 500,
            successes: 3,
            failures: 497,
            errors: 0,
            results: vec![],
            total_duration: None,
        };
        assert_eq!(s.attempts, 500);
        assert_eq!(s.successes, 3);
        assert_eq!(s.failures, 497);
    }
}
