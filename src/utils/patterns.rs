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
    pub _retryable: bool,
    pub _should_backoff: bool,
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
    "does not have access",
    "name or password is incorrect",
    "username or password",
    "logon failure",
    "logon failed",
    "authentication rejected",
];

const TRANSIENT_PATTERNS: &[&str] = &[
    "broken pipe",
    "connection reset",
    "connection closed",
    "eof",
    "end of file",
    "stream error",
    "i/o error",
    "session closed",
    "channel failure",
    "would block",
    "interrupted",
    "socket error",
    "method not allowed",
    "method not supported",
    "connection aborted",
    "connection refused",
    "no route",
    "network unreachable",
    "host unreachable",
    "shutdown",
    "not connected",
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
    "login attempts exceeded",
    "account locked out",
    "password expired",
    "account expired",
    "account has been locked",
    "this account is locked",
    "access denied..locked",
    "user locked",
    "temporarily unavailable",
];

const RATE_LIMIT_PATTERNS: &[&str] = &[
    "rate limit",
    "too many requests",
    "slow down",
    "try again later",
    "too many connections",
    "too many authentication failures",
    "please wait",
    "throttl",
    "busy",
    "service unavailable",
    "max connections",
    "overloaded",
    "server too busy",
];

const PROTO_PREFIXES: &[(ResponseCategory, &[&str])] = &[
    (ResponseCategory::AccountLocked, &[
        "530 account", "535 account", "550 account",
        "530 user", "535 user",
    ]),
    (ResponseCategory::RateLimited, &[
        "421 ", "421-", // FTP too many connections
        "452 ", "452-", // SMTP rate limited
        "450 ", // SMTP mailbox unavailable (temp)
        "451 ", // local error
        "too many bad",
    ]),
    (ResponseCategory::AuthFailure, &[
        "530 ", "530-", "530\t", // FTP not logged in
        "535 ", "535-", // SMTP auth failure
        "-ERR", " -ERR", // POP3 generic error
        "NO ", "NO\t", " NO ", // IMAP auth denied
        "a001 no ", "a002 no ", "a003 no ", "a004 no ", // IMAP tagged NO
        "a001 bad ", "a002 bad ", "a003 bad ", "a004 bad ", // IMAP tagged BAD
        "28000", "28P01", // PostgreSQL auth failure
        "1045", // MySQL access denied
        "504 5.7.4", // SMTP auth method mismatch
    ]),
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
            _retryable: false,
            _should_backoff: false,
            should_rotate_proxy: false,
        };
    }

    let msg = error.unwrap_or("Unknown error");

    if matches_any(msg, TRANSIENT_PATTERNS) {
        return ClassifiedError {
            category: ResponseCategory::ConnectionError,
            message: msg.to_string(),
            _retryable: true,
            _should_backoff: true,
            should_rotate_proxy: true,
        };
    }

    if msg.contains("timed out") || msg.contains("Timeout") || msg.contains("timeout") {
        return ClassifiedError {
            category: ResponseCategory::Timeout,
            message: msg.to_string(),
            _retryable: true,
            _should_backoff: true,
            should_rotate_proxy: false,
        };
    }

    if msg.contains("refused") || msg.contains("unreachable")
        || msg.contains("dns") || msg.contains("resolve")
        || msg.contains("server error")
        || msg.contains("http 5")
    {
        return ClassifiedError {
            category: ResponseCategory::ConnectionError,
            message: msg.to_string(),
            _retryable: true,
            _should_backoff: true,
            should_rotate_proxy: true,
        };
    }

    let lower_msg = msg.to_lowercase();
    for &(ref cat, ref prefixes) in PROTO_PREFIXES {
        if prefixes.iter().any(|p| lower_msg.contains(p)) {
            let lockout = *cat == ResponseCategory::AccountLocked;
            let rate = *cat == ResponseCategory::RateLimited;
            return ClassifiedError {
                category: cat.clone(),
                message: msg.to_string(),
                _retryable: rate || *cat == ResponseCategory::ProtocolError,
                _should_backoff: lockout || rate,
                should_rotate_proxy: lockout || rate,
            };
        }
    }

    if matches_any(msg, LOCKOUT_PATTERNS) {
        return ClassifiedError {
            category: ResponseCategory::AccountLocked,
            message: msg.to_string(),
            _retryable: false,
            _should_backoff: true,
            should_rotate_proxy: true,
        };
    }

    if matches_any(msg, RATE_LIMIT_PATTERNS) {
        return ClassifiedError {
            category: ResponseCategory::RateLimited,
            message: msg.to_string(),
            _retryable: true,
            _should_backoff: true,
            should_rotate_proxy: true,
        };
    }

    if matches_any(msg, AUTH_FAIL_PATTERNS) || error.is_none() {
        return ClassifiedError {
            category: ResponseCategory::AuthFailure,
            message: msg.to_string(),
            _retryable: false,
            _should_backoff: false,
            should_rotate_proxy: false,
        };
    }

    ClassifiedError {
        category: ResponseCategory::ProtocolError,
        message: msg.to_string(),
        _retryable: true,
        _should_backoff: false,
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
        assert!(!c._retryable);
    }

    #[test]
    fn test_classify_auth_failure() {
        let c = classify_error(Some("Access denied"), false);
        assert_eq!(c.category, ResponseCategory::AuthFailure);
        assert!(!c._retryable);
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
        assert!(c._should_backoff);
        assert!(c.should_rotate_proxy);
    }

    #[test]
    fn test_classify_connection_error() {
        let c = classify_error(Some("Connection refused"), false);
        assert_eq!(c.category, ResponseCategory::ConnectionError);
        assert!(c._retryable);
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
            _retryable: false,
            _should_backoff: true,
            should_rotate_proxy: true,
        };
        assert!(should_skip_user(&c));
    }

    #[test]
    fn test_should_not_skip_user() {
        let c = ClassifiedError {
            category: ResponseCategory::AuthFailure,
            message: "bad pass".into(),
            _retryable: false,
            _should_backoff: false,
            should_rotate_proxy: false,
        };
        assert!(!should_skip_user(&c));
    }
}
