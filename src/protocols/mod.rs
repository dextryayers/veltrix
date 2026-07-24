pub mod ftp;
pub mod http;
pub mod ldap;
pub mod mysql;
pub mod pop3;
pub mod postgres;
pub mod rdp;
pub mod redis;
pub mod smtp;
pub mod ssh;
pub mod telnet;

use std::collections::HashSet;
use async_trait::async_trait;
use std::time::Duration;
use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;

#[async_trait]
#[allow(dead_code)]
pub trait Protocol: Send + Sync {
    fn name(&self) -> &'static str;
    fn default_port(&self) -> u16;

    async fn authenticate(
        &self,
        target: &Target,
        credential: &Credential,
        timeout: Duration,
        proxy: &Option<crate::proxy::ProxyConfig>,
    ) -> AuthResult;
}

pub fn get_protocol(name: &str) -> Option<Box<dyn Protocol>> {
    match name.to_lowercase().as_str() {
        "ssh" => Some(Box::new(ssh::SshProtocol)),
        "ftp" => Some(Box::new(ftp::FtpProtocol)),
        "telnet" => Some(Box::new(telnet::TelnetProtocol)),
        "smtp" => Some(Box::new(smtp::SmtpProtocol)),
        "pop3" => Some(Box::new(pop3::Pop3Protocol)),
        "rdp" => Some(Box::new(rdp::RdpProtocol)),
        "mysql" => Some(Box::new(mysql::MySqlProtocol)),
        "postgres" | "postgresql" => Some(Box::new(postgres::PostgresProtocol)),
        "ldap" => Some(Box::new(ldap::LdapProtocol)),
        "redis" => Some(Box::new(redis::RedisProtocol)),
        "http" | "http-basic" | "http-digest" | "http-form" | "http-form-login" => Some(Box::new(http::HttpProtocol)),
        _ => None,
    }
}

pub fn default_ports_for_protocols(protocols: &[String]) -> Vec<u16> {
    let mut seen = HashSet::new();
    let mut ports = Vec::new();
    for name in protocols {
        if let Some(proto) = get_protocol(name) {
            let port = proto.default_port();
            if seen.insert(port) {
                ports.push(port);
            }
        }
    }
    ports
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_protocol_ssh() {
        let p = get_protocol("ssh");
        assert!(p.is_some());
        assert_eq!(p.unwrap().name(), "ssh");
    }

    #[test]
    fn test_get_protocol_ftp() {
        let p = get_protocol("ftp");
        assert!(p.is_some());
        assert_eq!(p.unwrap().default_port(), 21);
    }

    #[test]
    fn test_get_protocol_telnet() {
        let p = get_protocol("telnet");
        assert!(p.is_some());
    }

    #[test]
    fn test_get_protocol_smtp() {
        let p = get_protocol("smtp");
        assert!(p.is_some());
    }

    #[test]
    fn test_get_protocol_pop3() {
        let p = get_protocol("pop3");
        assert!(p.is_some());
    }

    #[test]
    fn test_get_protocol_rdp() {
        let p = get_protocol("rdp");
        assert!(p.is_some());
    }

    #[test]
    fn test_get_protocol_mysql() {
        let p = get_protocol("mysql");
        assert!(p.is_some());
    }

    #[test]
    fn test_get_protocol_http() {
        let p = get_protocol("http");
        assert!(p.is_some());
    }

    #[test]
    fn test_get_protocol_case_insensitive() {
        assert!(get_protocol("SSH").is_some());
        assert!(get_protocol("FTP").is_some());
        assert!(get_protocol("HTTP-BASIC").is_some());
        assert!(get_protocol("http-digest").is_some());
        assert!(get_protocol("HTTP-DIGEST").is_some());
        assert!(get_protocol("http-form-login").is_some());
        assert!(get_protocol("PostgreSQL").is_some());
        assert!(get_protocol("LDAP").is_some());
        assert!(get_protocol("REDIS").is_some());
    }

    #[test]
    fn test_get_protocol_unknown() {
        assert!(get_protocol("unknown").is_none());
        assert!(get_protocol("smb").is_none());
    }

    #[test]
    fn test_get_protocol_postgres() {
        let p = get_protocol("postgres");
        assert!(p.is_some());
        assert_eq!(p.unwrap().default_port(), 5432);
    }

    #[test]
    fn test_get_protocol_ldap() {
        let p = get_protocol("ldap");
        assert!(p.is_some());
        assert_eq!(p.unwrap().default_port(), 389);
    }

    #[test]
    fn test_get_protocol_redis() {
        let p = get_protocol("redis");
        assert!(p.is_some());
        assert_eq!(p.unwrap().default_port(), 6379);
    }

    #[test]
    fn test_list_protocols() {
        let protocols = vec!["ssh", "ftp", "telnet", "smtp", "pop3", "rdp", "mysql", "postgres", "ldap", "redis", "http"];
        assert_eq!(list_protocols(), protocols);
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn list_protocols() -> Vec<&'static str> {
    vec!["ssh", "ftp", "telnet", "smtp", "pop3", "rdp", "mysql", "postgres", "ldap", "redis", "http"]
}
