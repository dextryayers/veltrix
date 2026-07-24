use std::net::{SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use colored::Colorize;
use super::error::AttackError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub address: Option<SocketAddr>,
}

impl Target {
    pub fn new(host: String, port: u16, protocol: &str) -> Self {
        Target {
            host,
            port,
            protocol: protocol.to_string(),
            address: None,
        }
    }

    #[allow(dead_code)]
    pub fn display(&self) -> String {
        format!("{}:{} [{}]", self.host.cyan(), self.port.to_string().yellow(), self.protocol.green())
    }

    pub async fn resolve(&mut self, timeout: Duration) -> Result<(), AttackError> {
        let addr_str = format!("{}:{}", self.host, self.port);
        let host_clone = self.host.clone();
        match tokio::time::timeout(timeout, async {
            tokio::task::spawn_blocking(move || {
                addr_str.to_socket_addrs()
            }).await
                .map_err(|e| AttackError::internal(format!("Join error: {}", e)))?                .map_err(|e| AttackError::dns(&host_clone, format!("DNS error: {}", e)))
        }).await {
            Ok(Ok(mut addrs)) => {
                self.address = addrs.next();
                Ok(())
            }
            Ok(Err(e)) => Err(AttackError::dns(&host_clone, e.to_string())),
            Err(_) => Err(AttackError::dns(&host_clone, format!("Timeout resolving {}", host_clone))),
        }
    }

    pub fn addr_string(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    pub fn is_resolved(&self) -> bool {
        self.address.is_some()
    }
}

impl FromStr for Target {
    type Err = AttackError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() < 2 {
            return Err(AttackError::config("Invalid target format. Use host:port"));
        }
        let port = parts.last()
            .and_then(|p| p.parse::<u16>().ok())
            .ok_or_else(|| AttackError::config("Invalid port number"))?;
        let host = parts[..parts.len()-1].join(":");
        Ok(Target::new(host, port, ""))
    }
}

pub fn parse_targets(targets: &[String], protocols: &[String], ports: &[u16]) -> Vec<Target> {
    let mut result = Vec::new();
    for target_str in targets {
        let parts: Vec<&str> = target_str.split(':').collect();
        let (host, explicit_port) = if parts.len() >= 2 {
            let port = parts.last().and_then(|p| p.parse::<u16>().ok());
            match port {
                Some(p) => (parts[..parts.len()-1].join(":"), Some(p)),
                None => (target_str.clone(), None),
            }
        } else {
            (target_str.clone(), None)
        };

        if let Some(port) = explicit_port {
            for proto in protocols {
                result.push(Target::new(host.clone(), port, proto));
            }
        } else {
            for proto in protocols {
                for port in ports {
                    result.push(Target::new(host.clone(), *port, proto));
                }
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_new() {
        let t = Target::new("192.168.1.1".into(), 22, "ssh");
        assert_eq!(t.host, "192.168.1.1");
        assert_eq!(t.port, 22);
        assert_eq!(t.protocol, "ssh");
        assert!(t.address.is_none());
    }

    #[test]
    fn test_target_addr_string() {
        let t = Target::new("10.0.0.1".into(), 3389, "rdp");
        assert_eq!(t.addr_string(), "10.0.0.1:3389");
    }

    #[test]
    fn test_target_is_resolved() {
        let t = Target::new("10.0.0.1".into(), 80, "http");
        assert!(!t.is_resolved());
    }

    #[test]
    fn test_target_parse_valid() {
        let t: Target = "192.168.1.1:22".parse().unwrap();
        assert_eq!(t.host, "192.168.1.1");
        assert_eq!(t.port, 22);
    }

    #[test]
    fn test_target_parse_ipv6() {
        let t: Target = "[::1]:8080".parse().unwrap();
        assert_eq!(t.host, "[::1]");
        assert_eq!(t.port, 8080);
    }

    #[test]
    fn test_target_parse_invalid_no_port() {
        let result: Result<Target, AttackError> = "192.168.1.1".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_target_parse_invalid_port() {
        let result: Result<Target, AttackError> = "host:abc".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_targets_explicit_port() {
        let targets = parse_targets(
            &["10.0.0.1:2222".into()],
            &["ssh".into(), "ftp".into()],
            &[],
        );
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].port, 2222);
        assert_eq!(targets[0].protocol, "ssh");
        assert_eq!(targets[1].port, 2222);
        assert_eq!(targets[1].protocol, "ftp");
    }

    #[test]
    fn test_parse_targets_default_port() {
        let targets = parse_targets(
            &["10.0.0.1".into()],
            &["ssh".into()],
            &[22],
        );
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].host, "10.0.0.1");
        assert_eq!(targets[0].port, 22);
    }
}
