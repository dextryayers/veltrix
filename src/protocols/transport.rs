//! Fase 3.1: facade transport terpusat untuk semua protokol.
//!
//! Tujuan: hilangkan duplikasi 10-baris `match proxy { Some(p) => ...,
//! None => ... }` yang tersebar di 47 modul, dan jadikan satu jalur:
//! `transport::tcp_connect()` -> proxy-aware -> keepalive -> tuned.
//!
//! Semua protokol baru WAJIB memakai helper ini. Protokol lama dimigrasi
//! bertahap mulai dari 8 inti: ssh, ftp, smtp, mysql, smb, rdp, postgres, redis.

use std::time::Duration;
use tokio::net::TcpStream;

use super::conn;
use super::tcp::tune_tcp;
use crate::proxy::ProxyConfig;

/// Koneksi TCP terpusat: proxy-aware, timeout, keepalive, tuned.
/// Mengembalikan `String` error agar cocok dengan gaya existing protocol modules.
pub async fn tcp_connect(
    addr: &str,
    timeout_dur: Duration,
    proxy: &Option<ProxyConfig>,
) -> Result<TcpStream, String> {
    let stream = conn::tcp_connect(addr, timeout_dur, proxy).await?;
    tune_tcp(&stream);
    Ok(stream)
}

/// Baca satu baris CRLF dengan timeout eksplisit.
pub async fn read_crlf_line(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    timeout_dur: Duration,
) -> Result<String, String> {
    tokio::time::timeout(timeout_dur, conn::read_crlf_line(stream, buf))
        .await
        .map_err(|_| "Read timeout".to_string())?
}

/// Tulis satu baris + flush.
pub async fn write_line(stream: &mut TcpStream, line: &str) -> Result<(), String> {
    conn::write_line(stream, line).await
}

/// Konek + verifikasi banner prefix. Dipakai smtp, pop3, imap, ftp, dll.
pub async fn connect_and_banner(
    addr: &str,
    timeout_dur: Duration,
    proxy: &Option<ProxyConfig>,
    expected_prefix: &str,
) -> Result<(TcpStream, String), String> {
    conn::connect_and_banner(addr, timeout_dur, proxy, expected_prefix).await
}

/// Bangun reqwest client dengan proxy yang benar + warning chain.
/// F3.3: chain multi-hop TIDAK didukung reqwest (single-hop only).
/// Fungsi ini memakai hop pertama dan mengembalikan warning agar operator sadar.
pub fn build_reqwest_client(
    timeout_dur: Duration,
    proxy: &Option<ProxyConfig>,
    user_agent: &str,
) -> (Result<reqwest::Client, String>, Option<String>) {
    let mut builder = reqwest::Client::builder()
        .timeout(timeout_dur)
        .danger_accept_invalid_certs(true)
        .user_agent(user_agent.to_string())
        .redirect(reqwest::redirect::Policy::limited(5));

    let mut warning = None;
    if let Some(pc) = proxy {
        if let ProxyConfig::Chain { proxies } = pc {
            if proxies.len() > 1 {
                warning = Some(format!(
                    "Proxy chain with {} hops: reqwest path uses first hop only ({}). Raw TCP protocols use full chain.",
                    proxies.len(),
                    proxies.first().map(|p| p.display()).unwrap_or_default()
                ));
            }
        }
        if let Some(p) = pc.to_reqwest_proxy() {
            builder = builder.proxy(p);
        }
    }

    let client = builder.build().map_err(|e| format!("Client error: {}", e));
    (client, warning)
}

/// Validasi fingerprint sederhana untuk eliminasi false positive.
/// F3.4: tiap protokol mendaftarkan success marker dan fail marker.
#[derive(Debug, Clone)]
pub struct Fingerprint {
    pub protocol: &'static str,
    pub success_markers: Vec<&'static str>,
    pub fail_markers: Vec<&'static str>,
}

impl Fingerprint {
    pub fn check(&self, success_claim: bool, evidence: &str) -> FingerprintVerdict {
        let ev = evidence.to_lowercase();
        for m in &self.fail_markers {
            if ev.contains(&m.to_lowercase()) {
                if success_claim {
                    return FingerprintVerdict::Contradicted(format!(
                        "{} claims success but evidence contains fail marker '{}'",
                        self.protocol, m
                    ));
                }
                return FingerprintVerdict::ConsistentFail;
            }
        }
        if success_claim {
            for m in &self.success_markers {
                if ev.contains(&m.to_lowercase()) {
                    return FingerprintVerdict::Confirmed;
                }
            }
            // Tidak ada marker sukses bukan berarti gagal, hanya unverified.
            // Biarkan lolos tapi tandai agar --fp-check bisa re-verify.
            return FingerprintVerdict::Unverified;
        }
        FingerprintVerdict::ConsistentFail
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FingerprintVerdict {
    Confirmed,
    Unverified,
    ConsistentFail,
    Contradicted(String),
}

pub fn fingerprint_for(protocol: &str) -> Option<Fingerprint> {
    let p = protocol.to_lowercase();
    let fp = match p.as_str() {
        "ssh" => Fingerprint {
            protocol: "ssh",
            success_markers: vec!["authenticated", "success"],
            fail_markers: vec!["permission denied", "authentication failed", "too many authentication failures"],
        },
        "ftp" => Fingerprint {
            protocol: "ftp",
            success_markers: vec!["230 ", "login successful", "logged in"],
            fail_markers: vec!["530 ", "login incorrect", "authentication failed"],
        },
        "smtp" => Fingerprint {
            protocol: "smtp",
            success_markers: vec!["235 ", "authentication successful"],
            fail_markers: vec!["535 ", "authentication failed", "invalid credentials"],
        },
        "mysql" => Fingerprint {
            protocol: "mysql",
            success_markers: vec!["ok", "authenticated"],
            fail_markers: vec!["access denied", "invalid password"],
        },
        "postgres" | "postgresql" => Fingerprint {
            protocol: "postgres",
            success_markers: vec!["authenticationok", "readyforquery"],
            fail_markers: vec!["password authentication failed", "no password supplied"],
        },
        "smb" => Fingerprint {
            protocol: "smb",
            success_markers: vec!["session setup success", "status_success"],
            fail_markers: vec!["logon failure", "status_logon_failure", "access denied"],
        },
        "rdp" => Fingerprint {
            protocol: "rdp",
            success_markers: vec!["credssp success", "logon successful"],
            fail_markers: vec!["logon failure", "credssp failure", "access denied"],
        },
        "redis" => Fingerprint {
            protocol: "redis",
            success_markers: vec!["+ok"],
            fail_markers: vec!["invalid password", "noauth", "-err"],
        },
        "http" | "http-basic" | "http-digest" | "http-form" => Fingerprint {
            protocol: "http",
            success_markers: vec!["200", "dashboard", "welcome"],
            fail_markers: vec!["401", "403", "invalid login", "login failed"],
        },
        _ => return None,
    };
    Some(fp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fp_ssh_contradiction() {
        let fp = fingerprint_for("ssh").unwrap();
        let v = fp.check(true, "Permission denied, please try again");
        assert!(matches!(v, FingerprintVerdict::Contradicted(_)));
    }

    #[test]
    fn fp_ftp_confirmed() {
        let fp = fingerprint_for("ftp").unwrap();
        assert_eq!(fp.check(true, "230 Login successful"), FingerprintVerdict::Confirmed);
    }

    #[test]
    fn fp_unknown_none() {
        assert!(fingerprint_for("nonexistent-proto").is_none());
    }

    #[test]
    fn fp_fail_consistent() {
        let fp = fingerprint_for("mysql").unwrap();
        assert_eq!(
            fp.check(false, "Access denied for user"),
            FingerprintVerdict::ConsistentFail
        );
    }
}
