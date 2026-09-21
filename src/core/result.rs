use std::time::Duration;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use colored::*;

/// Masker password default (F6.3): hanya tampil penuh dengan --show-secrets.
pub fn mask_password(p: &str) -> String {
    if p.is_empty() {
        return "***".to_string();
    }
    let first = p.chars().next().unwrap_or('*');
    format!("{}***", first)
}

/// Referensi kredensial tanpa password plaintext (F6.1).
/// Format: `user@host:port#hash8` dengan hash8 = 8 hex pertama SHA-256 "user:pass".
pub fn credential_ref(username: &str, password: &str, host: &str, port: u16) -> String {
    use sha2::{Sha256, Digest};
    let mut h = Sha256::new();
    h.update(username.as_bytes());
    h.update(b":");
    h.update(password.as_bytes());
    let digest = h.finalize();
    let hex: String = digest.iter().take(4).map(|b| format!("{:02x}", b)).collect();
    format!("{}@{}:{}#{}", username, host, port, hex)
}

/// Severity temuan untuk laporan (F6.1).
pub fn severity_for(success: bool, error: Option<&str>) -> &'static str {
    if success {
        return "high";
    }
    match crate::utils::patterns::classify_error(error, false).category {
        crate::utils::patterns::ResponseCategory::AccountLocked
        | crate::utils::patterns::ResponseCategory::RateLimited => "medium",
        _ => "info",
    }
}

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
            r#type: "password".to_string(),
        }
    }

    pub fn display(&self) -> String {
        // F6.3: default masked. Lihat display_full() untuk plaintext.
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
            mask_password(&self.password),
            self.duration_ms,
        )
    }

    pub fn display_full(&self) -> String {
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

    /// Proyeksi redaksi untuk output file human-readable.
    pub fn redacted(&self, show_secrets: bool) -> AuthResult {
        if show_secrets {
            return self.clone();
        }
        let mut r = self.clone();
        r.password = mask_password(&self.password);
        r
    }

    /// Bukti aman untuk laporan: error dipotong 200 char, tanpa password.
    pub fn safe_evidence(&self) -> String {
        let e = self.error.as_deref().unwrap_or("Auth failed");
        let flat: String = e.split_whitespace().collect::<Vec<_>>().join(" ");
        if flat.len() > 200 {
            format!("{}...", &flat[..200])
        } else {
            flat
        }
    }
}

/// F6.1: skema JSON v2 per temuan (JSONL satu objek per baris).
/// Tidak pernah memuat password plaintext, hanya credential_ref.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingV2 {
    pub schema: String,
    pub run_id: String,
    pub seq: u64,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub target_host: String,
    pub target_port: u16,
    pub protocol: String,
    pub username: String,
    pub credential_ref: String,
    pub success: bool,
    pub severity: String,
    pub duration_ms: u64,
    pub timestamp: DateTime<Utc>,
    pub evidence: String,
}

impl FindingV2 {
    pub fn from_result(
        r: &AuthResult,
        run_id: &str,
        seq: u64,
        started_at: &str,
    ) -> Self {
        FindingV2 {
            schema: "veltrix-finding/v2".into(),
            run_id: run_id.to_string(),
            seq,
            started_at: started_at.to_string(),
            finished_at: None,
            target_host: r.target_host.clone(),
            target_port: r.target_port,
            protocol: r.protocol.clone(),
            username: r.username.clone(),
            credential_ref: credential_ref(&r.username, &r.password, &r.target_host, r.target_port),
            success: r.success,
            severity: severity_for(r.success, r.error.as_deref()).into(),
            duration_ms: r.duration_ms,
            timestamp: r.timestamp,
            evidence: r.safe_evidence(),
        }
    }
}

/// Tick progres untuk job queue non-blocking API (F6.4).
#[derive(Debug, Clone)]
pub struct ProgressTick {
    pub attempts: u64,
    pub successes: u64,
    pub failures: u64,
    pub errors: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSummary {
    pub run_id: String,
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
            run_id: "test-run".into(),
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

    #[test]
    fn test_mask_password() {
        assert_eq!(mask_password(""), "***");
        assert_eq!(mask_password("a"), "a***");
        assert_eq!(mask_password("P@ssw0rd"), "P***");
    }

    #[test]
    fn test_credential_ref_no_plaintext() {
        let r = credential_ref("admin", "s3cret!", "10.0.0.1", 22);
        assert!(r.starts_with("admin@10.0.0.1:22#"));
        assert!(!r.contains("s3cret"));
        assert_eq!(r.len(), "admin@10.0.0.1:22#".len() + 8);
        // Deterministik.
        assert_eq!(r, credential_ref("admin", "s3cret!", "10.0.0.1", 22));
    }

    #[test]
    fn test_finding_v2_schema() {
        let r = AuthResult::new(
            "10.0.0.1".into(), 22, "ssh",
            "admin".into(), "s3cret!".into(),
            true, Duration::from_millis(100), None,
        );
        let f = FindingV2::from_result(&r, "run-1", 7, "2026-01-01T00:00:00Z");
        assert_eq!(f.schema, "veltrix-finding/v2");
        assert_eq!(f.seq, 7);
        assert_eq!(f.severity, "high");
        assert!(f.success);
        let json = serde_json::to_string(&f).unwrap();
        assert!(!json.contains("s3cret"), "v2 JSON must never leak password");
        assert!(json.contains("run-1"));
    }

    #[test]
    fn test_severity_mapping() {
        assert_eq!(severity_for(true, None), "high");
        assert_eq!(severity_for(false, Some("Account locked out")), "medium");
        assert_eq!(severity_for(false, Some("Too many requests")), "medium");
        assert_eq!(severity_for(false, Some("Access denied")), "info");
    }

    #[test]
    fn test_safe_evidence_truncates() {
        let long = "x".repeat(500);
        let r = AuthResult::new(
            "h".into(), 22, "ssh", "u".into(), "p".into(),
            false, Duration::from_millis(1), Some(long),
        );
        assert!(r.safe_evidence().len() <= 203);
    }
}
