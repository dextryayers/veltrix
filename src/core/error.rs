use std::fmt;
use std::path::PathBuf;

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
    Wordlist { path: PathBuf, detail: String },
    Session { detail: String },
    Internal { detail: String },
}

impl fmt::Display for AttackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttackError::Config(msg) => write!(f, "Config error: {}", msg),
            AttackError::Io { context, detail } => write!(f, "I/O error {}: {}", context, detail),
            AttackError::Dns { host, detail } => write!(f, "DNS error for {}: {}", host, detail),
            AttackError::Protocol { protocol, detail } => {
                write!(f, "{} protocol error: {}", protocol, detail)
            }
            AttackError::Auth { reason } => write!(f, "Auth error: {}", reason),
            AttackError::Lockout { user } => write!(f, "Account locked: {}", user),
            AttackError::RateLimited => write!(f, "Rate limited"),
            AttackError::Timeout { ms } => write!(f, "Timeout after {}ms", ms),
            AttackError::Wordlist { path, detail } => {
                write!(f, "Wordlist '{}': {}", path.display(), detail)
            }
            AttackError::Session { detail } => write!(f, "Session error: {}", detail),
            AttackError::Internal { detail } => write!(f, "Internal error: {}", detail),
        }
    }
}

impl std::error::Error for AttackError {}

impl AttackError {
    pub fn io(context: impl Into<String>, detail: impl Into<String>) -> Self {
        AttackError::Io {
            context: context.into(),
            detail: detail.into(),
        }
    }

    pub fn config(msg: impl Into<String>) -> Self {
        AttackError::Config(msg.into())
    }

    pub fn dns(host: impl Into<String>, detail: impl Into<String>) -> Self {
        AttackError::Dns {
            host: host.into(),
            detail: detail.into(),
        }
    }

    pub fn protocol(protocol: impl Into<String>, detail: impl Into<String>) -> Self {
        AttackError::Protocol {
            protocol: protocol.into(),
            detail: detail.into(),
        }
    }

    pub fn wordlist(path: PathBuf, detail: impl Into<String>) -> Self {
        AttackError::Wordlist {
            path,
            detail: detail.into(),
        }
    }

    pub fn session(detail: impl Into<String>) -> Self {
        AttackError::Session {
            detail: detail.into(),
        }
    }

    pub fn internal(detail: impl Into<String>) -> Self {
        AttackError::Internal {
            detail: detail.into(),
        }
    }
}

impl From<String> for AttackError {
    fn from(s: String) -> Self {
        AttackError::Internal { detail: s }
    }
}

impl From<&str> for AttackError {
    fn from(s: &str) -> Self {
        AttackError::Internal {
            detail: s.to_string(),
        }
    }
}

impl From<std::io::Error> for AttackError {
    fn from(e: std::io::Error) -> Self {
        AttackError::Io {
            context: "io".into(),
            detail: e.to_string(),
        }
    }
}

impl From<serde_json::Error> for AttackError {
    fn from(e: serde_json::Error) -> Self {
        AttackError::Internal {
            detail: format!("JSON error: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config() {
        let e = AttackError::config("missing field");
        assert!(e.to_string().contains("missing field"));
    }

    #[test]
    fn test_io() {
        let e = AttackError::io("read", "permission denied");
        assert!(e.to_string().contains("read"));
        assert!(e.to_string().contains("permission denied"));
    }

    #[test]
    fn test_dns() {
        let e = AttackError::dns("example.com", "not found");
        assert!(e.to_string().contains("example.com"));
    }

    #[test]
    fn test_protocol() {
        let e = AttackError::protocol("ssh", "handshake failed");
        assert!(e.to_string().contains("ssh"));
    }

    #[test]
    fn test_wordlist() {
        let e = AttackError::wordlist(PathBuf::from("/tmp/test.txt"), "not found");
        assert!(e.to_string().contains("test.txt"));
    }

    #[test]
    fn test_session() {
        let e = AttackError::session("corrupted");
        assert!(e.to_string().contains("corrupted"));
    }

    #[test]
    fn test_internal() {
        let e = AttackError::internal("bad state");
        assert!(e.to_string().contains("bad state"));
    }

    #[test]
    fn test_from_string() {
        let e: AttackError = "oops".into();
        assert!(e.to_string().contains("oops"));
    }

    #[test]
    fn test_from_io_error() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let e: AttackError = io.into();
        assert!(e.to_string().contains("file missing"));
    }
}
