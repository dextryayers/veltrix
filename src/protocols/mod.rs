pub mod activemq;
pub mod cassandra;
pub mod conn;
pub mod firebird;
pub mod ftp;
pub mod http;
pub mod imap;
pub mod irc;
pub mod kafka;
pub mod ldap;
pub mod mongodb;
pub mod mssql;
pub mod mysql;
pub mod oracle;
pub mod pop3;
pub mod postgres;
pub mod rabbitmq;
pub mod rdp;
pub mod redis;
pub mod rtsp;
pub mod sip;
pub mod smb;
pub mod smtp;
pub mod snmp;
pub mod ssh;
pub mod tcp;
pub mod telnet;
pub mod vnc;
pub mod xmpp;
pub mod http_auth;
pub mod couchdb;
pub mod elasticsearch;
pub mod tomcat;
pub mod jenkins;
pub mod gitlab;
pub mod sonarqube;
pub mod docker;
pub mod kubernetes;
pub mod vault;
pub mod consul;
pub mod vmware;
pub mod ilo;
pub mod ipmi;
pub mod nntp;
pub mod cvs;
pub mod svn;
pub mod rexec;
pub mod rlogin;
pub mod squid;
pub mod memcached;

use std::collections::HashSet;
use async_trait::async_trait;
use std::time::Duration;
use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;

#[async_trait]
pub trait Protocol: Send + Sync {
    #[allow(dead_code)]
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
    let lower = name.to_lowercase();
    match lower.as_str() {
        "activemq" => Some(Box::new(activemq::ActivemqProtocol)),
        "cassandra" => Some(Box::new(cassandra::CassandraProtocol)),
        "firebird" => Some(Box::new(firebird::FirebirdProtocol)),
        "irc" => Some(Box::new(irc::IrcProtocol)),
        "kafka" => Some(Box::new(kafka::KafkaProtocol)),
        "oracle" => Some(Box::new(oracle::OracleProtocol)),
        "rabbitmq" => Some(Box::new(rabbitmq::RabbitmqProtocol)),
        "rtsp" => Some(Box::new(rtsp::RtspProtocol)),
        "sip" => Some(Box::new(sip::SipProtocol)),
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
        "mongodb" => Some(Box::new(mongodb::MongoDbProtocol)),
        "mssql" => Some(Box::new(mssql::MssqlProtocol)),
        "smb" => Some(Box::new(smb::SmbProtocol)),
        "snmp" => Some(Box::new(snmp::SnmpProtocol)),
        "imap" => Some(Box::new(imap::ImapProtocol)),
        "vnc" => Some(Box::new(vnc::VncProtocol)),
        "xmpp" => Some(Box::new(xmpp::XmppProtocol)),
        "couchdb" => Some(Box::new(couchdb::CouchdbProtocol)),
        "elasticsearch" => Some(Box::new(elasticsearch::ElasticsearchProtocol)),
        "tomcat" => Some(Box::new(tomcat::TomcatProtocol)),
        "jenkins" => Some(Box::new(jenkins::JenkinsProtocol)),
        "gitlab" => Some(Box::new(gitlab::GitlabProtocol)),
        "sonarqube" => Some(Box::new(sonarqube::SonarqubeProtocol)),
        "docker" => Some(Box::new(docker::DockerProtocol)),
        "kubernetes" => Some(Box::new(kubernetes::KubernetesProtocol)),
        "vault" => Some(Box::new(vault::VaultProtocol)),
        "consul" => Some(Box::new(consul::ConsulProtocol)),
        "vmware" => Some(Box::new(vmware::VmwareProtocol)),
        "ilo" => Some(Box::new(ilo::IloProtocol)),
        "ipmi" => Some(Box::new(ipmi::IpmiProtocol)),
        "nntp" => Some(Box::new(nntp::NntpProtocol)),
        "cvs" => Some(Box::new(cvs::CvsProtocol)),
        "svn" => Some(Box::new(svn::SvnProtocol)),
        "rexec" => Some(Box::new(rexec::RexecProtocol)),
        "rlogin" => Some(Box::new(rlogin::RloginProtocol)),
        "squid" => Some(Box::new(squid::SquidProtocol)),
        "memcached" => Some(Box::new(memcached::MemcachedProtocol)),
        _ => {
            // Check external plugin registry
            if let Some(entry) = crate::core::plugin::get_plugin(&lower) {
                Some(Box::new(PluginProtocol { entry }))
            } else {
                None
            }
        }
    }
}

/// Wrapper that makes a PluginEntry implement the Protocol trait
struct PluginProtocol {
    entry: crate::core::plugin::PluginEntry,
}

#[async_trait]
impl Protocol for PluginProtocol {
    fn name(&self) -> &'static str {
        Box::leak(self.entry.name.clone().into_boxed_str())
    }

    fn default_port(&self) -> u16 {
        self.entry.default_port
    }

    async fn authenticate(
        &self,
        target: &Target,
        credential: &Credential,
        timeout: Duration,
        proxy: &Option<crate::proxy::ProxyConfig>,
    ) -> AuthResult {
        crate::core::plugin::execute_plugin(&self.entry, target, credential, timeout, proxy).await
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
    fn test_get_protocol_unknown() {
        assert!(get_protocol("unknown").is_none());
        assert!(get_protocol("smb").is_some());
        assert!(get_protocol("mongodb").is_some());
        assert!(get_protocol("snmp").is_some());
        assert!(get_protocol("imap").is_some());
        assert!(get_protocol("vnc").is_some());
        assert!(get_protocol("mssql").is_some());
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
        let protocols = list_protocols();
        assert_eq!(list_protocols(), protocols);
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn list_protocols() -> Vec<&'static str> {
    vec!["activemq", "cassandra", "couchdb", "docker", "elasticsearch", "firebird", "ftp", "gitlab", "http", "ilo", "imap", "ipmi", "irc", "jenkins", "kafka", "kubernetes", "ldap", "memcached", "mongodb", "mssql", "mysql", "nntp", "oracle", "pop3", "postgres", "rabbitmq", "rdp", "redis", "rexec", "rlogin", "rtsp", "sip", "smb", "smtp", "snmp", "sonarqube", "squid", "ssh", "svn", "telnet", "tomcat", "vault", "vmware", "vnc", "xmpp"]
}
