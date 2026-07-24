use std::fmt;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum AttackError {
    Config(String),
    Io { context: String, detail: String },
    Dns { host: String, detail: String },
    Protocol { protocol: String, detail: String },
    Auth { reason: String },
    Lockout { user: String },
    RateLimited,
    Timeout { ms: u64 },
    Wordlist { path: String, detail: String },
    Session { detail: String },
    Internal { detail: String },
}

impl fmt::Display for AttackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttackError::Config(msg) => write!(f, "Config error: {}", msg),
            AttackError::Io { context, detail } => write!(f, "I/O error {}: {}", context, detail),
            AttackError::Dns { host, detail } => write!(f, "DNS error for {}: {}", host, detail),
            AttackError::Protocol { protocol, detail } => write!(f, "{} protocol error: {}", protocol, detail),
            AttackError::Auth { reason } => write!(f, "Auth error: {}", reason),
            AttackError::Lockout { user } => write!(f, "Account locked: {}", user),
            AttackError::RateLimited => write!(f, "Rate limited"),
            AttackError::Timeout { ms } => write!(f, "Timeout after {}ms", ms),
            AttackError::Wordlist { path, detail } => write!(f, "Wordlist '{}': {}", path, detail),
            AttackError::Session { detail } => write!(f, "Session error: {}", detail),
            AttackError::Internal { detail } => write!(f, "Internal error: {}", detail),
        }
    }
}

impl std::error::Error for AttackError {}

impl From<String> for AttackError {
    fn from(s: String) -> Self {
        AttackError::Internal { detail: s }
    }
}

impl From<&str> for AttackError {
    fn from(s: &str) -> Self {
        AttackError::Internal { detail: s.to_string() }
    }
}
