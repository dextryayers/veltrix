use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
pub enum ResponseCategory {
    AuthFailure,
    AccountLocked,
    RateLimited,
    ConnectionError,
    ProtocolError,
    Success,
    Timeout,
}

#[derive(Debug, Clone)]
pub struct ClassifiedError {
    pub category: ResponseCategory,
    pub message: String,
    #[allow(dead_code)]
    pub retryable: bool,
    #[allow(dead_code)]
    pub should_backoff: bool,
    pub should_rotate_proxy: bool,
}

const AUTH_FAIL_PATTERNS: &[&str] = &[
    "access denied",
    "authentication failed",
    "login incorrect",
    "invalid credentials",
    "permission denied",
    "not authenticated",
    "authorization failed",
    "login failed",
    "incorrect",
    "bad auth",
    "auth fail",
    "wrong password",
    "invalid username",
    "user unknown",
    "unknown user",
];

const LOCKOUT_PATTERNS: &[&str] = &[
    "account locked",
    "account disabled",
    "account blocked",
    "too many failed",
    "account temporarily",
    "account suspended",
    "account is locked",
    "maximum login attempts",
];

const RATE_LIMIT_PATTERNS: &[&str] = &[
    "rate limit",
    "too many requests",
    "slow down",
    "try again later",
    "exceeded",
    "too many connections",
    "too many authentication failures",
    "please wait",
    "throttl",
];

fn matches_any(text: &str, patterns: &[&str]) -> bool {
    let lower = text.to_lowercase();
    patterns.iter().any(|p| lower.contains(p))
}

pub fn classify_error(error: Option<&str>, success: bool) -> ClassifiedError {
    if success {
        return ClassifiedError {
            category: ResponseCategory::Success,
            message: String::new(),
            retryable: false,
            should_backoff: false,
            should_rotate_proxy: false,
        };
    }

    let msg = error.unwrap_or("Unknown error");

    if matches_any(msg, LOCKOUT_PATTERNS) {
        return ClassifiedError {
            category: ResponseCategory::AccountLocked,
            message: msg.to_string(),
            retryable: false,
            should_backoff: true,
            should_rotate_proxy: true,
        };
    }

    if matches_any(msg, RATE_LIMIT_PATTERNS) {
        return ClassifiedError {
            category: ResponseCategory::RateLimited,
            message: msg.to_string(),
            retryable: true,
            should_backoff: true,
            should_rotate_proxy: true,
        };
    }

    if matches_any(msg, AUTH_FAIL_PATTERNS) || error.is_none() {
        return ClassifiedError {
            category: ResponseCategory::AuthFailure,
            message: msg.to_string(),
            retryable: false,
            should_backoff: false,
            should_rotate_proxy: false,
        };
    }

    if msg.contains("timed out") || msg.contains("Timeout") || msg.contains("timeout") {
        return ClassifiedError {
            category: ResponseCategory::Timeout,
            message: msg.to_string(),
            retryable: true,
            should_backoff: true,
            should_rotate_proxy: false,
        };
    }

    if msg.contains("refused") || msg.contains("reset") || msg.contains("unreachable")
        || msg.contains("dns") || msg.contains("resolve")
    {
        return ClassifiedError {
            category: ResponseCategory::ConnectionError,
            message: msg.to_string(),
            retryable: true,
            should_backoff: true,
            should_rotate_proxy: false,
        };
    }

    ClassifiedError {
        category: ResponseCategory::ProtocolError,
        message: msg.to_string(),
        retryable: true,
        should_backoff: false,
        should_rotate_proxy: false,
    }
}

pub fn compute_backoff(attempt: u32) -> Duration {
    let ms = 500u64 * 2u64.pow(attempt);
    Duration::from_millis(ms.min(30_000))
}

pub fn should_skip_user(classified: &ClassifiedError) -> bool {
    classified.category == ResponseCategory::AccountLocked
}

pub fn should_rotate_proxy(classified: &ClassifiedError) -> bool {
    classified.should_rotate_proxy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_success() {
        let c = classify_error(None, true);
        assert_eq!(c.category, ResponseCategory::Success);
        assert!(!c.retryable);
    }

    #[test]
    fn test_classify_auth_failure() {
        let c = classify_error(Some("Access denied"), false);
        assert_eq!(c.category, ResponseCategory::AuthFailure);
        assert!(!c.retryable);
    }

    #[test]
    fn test_classify_auth_failure_incorrect() {
        let c = classify_error(Some("login incorrect"), false);
        assert_eq!(c.category, ResponseCategory::AuthFailure);
    }

    #[test]
    fn test_classify_account_locked() {
        let c = classify_error(Some("Account locked"), false);
        assert_eq!(c.category, ResponseCategory::AccountLocked);
        assert!(c.should_rotate_proxy);
    }

    #[test]
    fn test_classify_rate_limited() {
        let c = classify_error(Some("Rate limit exceeded"), false);
        assert_eq!(c.category, ResponseCategory::RateLimited);
        assert!(c.should_backoff);
        assert!(c.should_rotate_proxy);
    }

    #[test]
    fn test_classify_connection_error() {
        let c = classify_error(Some("Connection refused"), false);
        assert_eq!(c.category, ResponseCategory::ConnectionError);
        assert!(c.retryable);
    }

    #[test]
    fn test_classify_timeout() {
        let c = classify_error(Some("timed out"), false);
        assert_eq!(c.category, ResponseCategory::Timeout);
    }

    #[test]
    fn test_classify_protocol_error() {
        let c = classify_error(Some("unexpected response: 0xFF"), false);
        assert_eq!(c.category, ResponseCategory::ProtocolError);
    }

    #[test]
    fn test_compute_backoff() {
        assert_eq!(compute_backoff(0), Duration::from_millis(500));
        assert_eq!(compute_backoff(1), Duration::from_millis(1000));
        assert_eq!(compute_backoff(2), Duration::from_millis(2000));
        assert_eq!(compute_backoff(3), Duration::from_millis(4000));
    }

    #[test]
    fn test_compute_backoff_capped() {
        let b = compute_backoff(10);
        assert!(b <= Duration::from_millis(30_000));
    }

    #[test]
    fn test_should_skip_user() {
        let c = ClassifiedError {
            category: ResponseCategory::AccountLocked,
            message: "locked".into(),
            retryable: false,
            should_backoff: true,
            should_rotate_proxy: true,
        };
        assert!(should_skip_user(&c));
    }

    #[test]
    fn test_should_not_skip_user() {
        let c = ClassifiedError {
            category: ResponseCategory::AuthFailure,
            message: "bad pass".into(),
            retryable: false,
            should_backoff: false,
            should_rotate_proxy: false,
        };
        assert!(!should_skip_user(&c));
    }
}
