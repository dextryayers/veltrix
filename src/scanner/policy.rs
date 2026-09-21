//! F5.5: policy file untuk mode auto.
//! Membatasi protokol dan subnet yang boleh di-attack otomatis.
//! Contoh `config/auto-policy.example.toml`.
//!
//! ```toml
//! [policy]
//! allowed_protocols = ["ssh", "ftp", "http"]
//! allowed_subnets = ["192.168.0.0/16", "10.0.0.0/8"]
//! max_threads = 20
//! min_confidence = 50
//! ```

use std::net::IpAddr;
use std::path::Path;

use crate::core::error::AttackError;

#[derive(Debug, Clone, Default)]
pub struct AutoPolicy {
    pub allowed_protocols: Option<Vec<String>>,
    pub allowed_subnets: Option<Vec<String>>,
    pub max_threads: Option<usize>,
    pub min_confidence: Option<u8>,
}

impl AutoPolicy {
    pub fn load(path: &Path) -> Result<Self, AttackError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            AttackError::io("policy", format!("cannot read {}: {}", path.display(), e))
        })?;
        // Parse TOML minimal tanpa dependency baru: cari section [policy].
        let mut p = AutoPolicy::default();
        let mut in_policy = false;
        for raw in content.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with('[') {
                in_policy = line == "[policy]";
                continue;
            }
            if !in_policy {
                continue;
            }
            let (k, v) = match line.split_once('=') {
                Some(x) => (x.0.trim(), x.1.trim()),
                None => continue,
            };
            match k {
                "allowed_protocols" => p.allowed_protocols = Some(parse_str_list(v)),
                "allowed_subnets" => p.allowed_subnets = Some(parse_str_list(v)),
                "max_threads" => {
                    p.max_threads = v.parse::<usize>().ok();
                }
                "min_confidence" => {
                    p.min_confidence = v.parse::<u8>().ok().map(|n| n.min(100));
                }
                _ => {}
            }
        }
        Ok(p)
    }

    pub fn allows_protocol(&self, proto: &str) -> bool {
        match &self.allowed_protocols {
            None => true,
            Some(list) => list.iter().any(|p| p.eq_ignore_ascii_case(proto)),
        }
    }

    pub fn allows_host(&self, host: &str) -> bool {
        let nets = match &self.allowed_subnets {
            None => return true,
            Some(n) => n,
        };
        let ip: IpAddr = match host.parse() {
            Ok(ip) => ip,
            Err(_) => return false, // hostname tak dikenal = tolak (konservatif)
        };
        nets.iter().any(|n| subnet_contains(n, &ip))
    }

    pub fn min_confidence(&self) -> u8 {
        self.min_confidence.unwrap_or(50)
    }
}

fn parse_str_list(v: &str) -> Vec<String> {
    let t = v.trim().trim_start_matches('[').trim_end_matches(']');
    t.split(',')
        .map(|s| {
            s.trim()
                .trim_matches('"')
                .trim_matches('\'')
                .to_string()
        })
        .filter(|s| !s.is_empty())
        .collect()
}

/// Cek keanggotaan subnet untuk IPv4 CIDR "a.b.c.d/p".
/// Format tak dikenal = false (konservatif).
pub fn subnet_contains(cidr: &str, ip: &IpAddr) -> bool {
    let (net_str, prefix) = match cidr.split_once('/') {
        Some((n, p)) => (n.trim(), p.trim().parse::<u8>().unwrap_or(255)),
        None => return false,
    };
    if prefix > 32 {
        return false;
    }
    let net: std::net::Ipv4Addr = match net_str.parse() {
        Ok(a) => a,
        Err(_) => return false, // IPv6 subnet belum didukung = tolak
    };
    let target = match ip {
        IpAddr::V4(v4) => *v4,
        IpAddr::V6(_) => return false,
    };
    let mask: u32 = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
    (u32::from(net) & mask) == (u32::from(target) & mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn subnet_membership() {
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        assert!(subnet_contains("192.168.0.0/16", &ip));
        assert!(subnet_contains("192.168.1.0/24", &ip));
        assert!(!subnet_contains("10.0.0.0/8", &ip));
        assert!(!subnet_contains("bogus", &ip));
        assert!(!subnet_contains("192.168.1.0/33", &ip));
    }

    #[test]
    fn policy_parse_example() {
        let dir = std::env::temp_dir();
        let path = dir.join("veltrix_policy_test.toml");
        std::fs::write(
            &path,
            "# comment\n[policy]\nallowed_protocols = [\"ssh\", \"ftp\"]\nallowed_subnets = [\"10.0.0.0/8\"]\nmax_threads = 20\nmin_confidence = 75\n",
        )
        .unwrap();
        let p = AutoPolicy::load(&path).unwrap();
        assert!(p.allows_protocol("SSH"));
        assert!(!p.allows_protocol("rdp"));
        assert!(p.allows_host("10.1.2.3"));
        assert!(!p.allows_host("192.168.1.1"));
        assert!(!p.allows_host("example.com"));
        assert_eq!(p.max_threads, Some(20));
        assert_eq!(p.min_confidence(), 75);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn empty_policy_allows_all() {
        let p = AutoPolicy::default();
        assert!(p.allows_protocol("anything"));
        assert!(p.allows_host("8.8.8.8"));
        assert_eq!(p.min_confidence(), 50);
    }
}
