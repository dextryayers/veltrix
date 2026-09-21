use std::net::Ipv4Addr;

use super::error::AttackError;

#[derive(Debug, Clone)]
pub enum TargetSpec {
    Single { host: String, port: Option<u16> },
    Cidr { network: Ipv4Addr, prefix: u8, port: Option<u16> },
    Range { start: Ipv4Addr, end: Ipv4Addr, port: Option<u16> },
}

impl TargetSpec {
    pub fn parse(input: &str) -> Result<Self, AttackError> {
        let input = input.trim();

        let (addr_part, port) = if let Some(pos) = input.rfind(':') {
            let after = &input[pos + 1..];
            if let Ok(p) = after.parse::<u16>() {
                if p > 0 {
                    (&input[..pos], Some(p))
                } else {
                    (input, None)
                }
            } else {
                (input, None)
            }
        } else {
            (input, None)
        };

        if addr_part.contains('/') {
            let parts: Vec<&str> = addr_part.splitn(2, '/').collect();
            let network: Ipv4Addr = parts[0].parse()
                .map_err(|_| AttackError::config(format!("Invalid IP address: {}", parts[0])))?;
            let prefix: u8 = parts[1].parse()
                .map_err(|_| AttackError::config(format!("Invalid CIDR prefix: {}", parts[1])))?;
            if prefix > 32 {
                return Err(AttackError::config("CIDR prefix must be 0-32"));
            }
            Ok(TargetSpec::Cidr { network, prefix, port })
        } else if addr_part.contains('-') {
            let parts: Vec<&str> = addr_part.splitn(2, '-').collect();
            let start: Ipv4Addr = parts[0].parse()
                .map_err(|_| AttackError::config(format!("Invalid start IP: {}", parts[0])))?;
            let end: Ipv4Addr = parts[1].parse()
                .map_err(|_| AttackError::config(format!("Invalid end IP: {}", parts[1])))?;
            if u32_from_ip(end) < u32_from_ip(start) {
                return Err(AttackError::config("End IP must be >= start IP"));
            }
            Ok(TargetSpec::Range { start, end, port })
        } else {
            Ok(TargetSpec::Single { host: addr_part.to_string(), port })
        }
    }

    pub fn expand(&self) -> Vec<(String, Option<u16>)> {
        match self {
            TargetSpec::Single { host, port } => {
                vec![(host.clone(), *port)]
            }
            TargetSpec::Cidr { network, prefix, port } => {
                expand_cidr(*network, *prefix, *port)
            }
            TargetSpec::Range { start, end, port } => {
                expand_range(*start, *end, *port)
            }
        }
    }

}

fn u32_from_ip(ip: Ipv4Addr) -> u32 {
    u32::from(ip)
}

fn ip_from_u32(val: u32) -> Ipv4Addr {
    Ipv4Addr::from(val)
}

fn expand_cidr(network: Ipv4Addr, prefix: u8, port: Option<u16>) -> Vec<(String, Option<u16>)> {
    let net_u32 = u32_from_ip(network);
    let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
    let network_start = net_u32 & mask;
    let host_bits = 32 - prefix;

    if host_bits == 0 {
        return vec![(network.to_string(), port)];
    }

    let total = 2u64.pow(host_bits as u32);
    let mut hosts = Vec::with_capacity(total as usize - 2);

    let start = if prefix < 31 { 1 } else { 0 };
    let end = if prefix < 31 { total - 1 } else { total };

    for i in start..end {
        let ip = ip_from_u32(network_start | (i as u32));
        hosts.push((ip.to_string(), port));
    }

    hosts
}

fn expand_range(start: Ipv4Addr, end: Ipv4Addr, port: Option<u16>) -> Vec<(String, Option<u16>)> {
    let start_u32 = u32_from_ip(start);
    let end_u32 = u32_from_ip(end);
    let count = (end_u32 - start_u32 + 1) as usize;

    let mut hosts = Vec::with_capacity(count);
    for val in start_u32..=end_u32 {
        hosts.push((ip_from_u32(val).to_string(), port));
    }
    hosts
}

pub fn expand_targets(inputs: &[String]) -> Vec<(String, Option<u16>)> {
    let mut results = Vec::new();
    for input in inputs {
        if let Ok(spec) = TargetSpec::parse(input) {
            results.extend(spec.expand());
        }
    }
    results
}

/// F4.6: true jika spec menunjuk ke lab lokal (RFC1918, loopback, link-local).
/// Hostname yang tidak bisa di-parse sebagai IP dianggap NON-lab (konservatif).
/// IPv6: loopback ::1, link-local fe80::/10, unique-local fc00::/7.
pub fn spec_is_lab(spec: &str) -> bool {
    use std::net::IpAddr;
    let s = spec.trim();
    // Pisahkan port opsional "host:port" dan CIDR "net/prefix".
    let host_part = if let Some(slash) = s.find('/') {
        &s[..slash]
    } else if let Some(pos) = s.rfind(':') {
        let after = &s[pos + 1..];
        // Port numerik atau range "a-b" dengan port? Range IPv4 "1.2.3.1-1.2.3.5".
        if after.parse::<u16>().is_ok() && !s[..pos].contains('-') {
            &s[..pos]
        } else if s.contains('-') {
            // Range: cek kedua ujung.
            let mut parts = s.splitn(2, '-');
            let a = parts.next().unwrap_or("");
            let b = parts.next().unwrap_or("");
            return host_is_lab_ip(a) && host_is_lab_ip(b.trim_start_matches(|c: char| c == '['));
        } else {
            s
        }
    } else {
        s
    };
    let host_part = host_part.trim_matches(|c| c == '[' || c == ']');
    host_is_lab_ip(host_part)
}

fn host_is_lab_ip(host: &str) -> bool {
    use std::net::IpAddr;
    let host = host.trim().trim_matches(|c| c == '[' || c == ']');
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        Ok(IpAddr::V6(v6)) => {
            v6.is_loopback() || is_link_local_v6(&v6) || is_unique_local(&v6)
        }
        Err(_) => false,
    }
}

fn is_link_local_v6(v6: &std::net::Ipv6Addr) -> bool {
    // fe80::/10
    let o = v6.octets();
    o[0] == 0xfe && (o[1] & 0xc0) == 0x80
}

fn is_unique_local(v6: &std::net::Ipv6Addr) -> bool {
    // fc00::/7
    (v6.octets()[0] & 0xfe) == 0xfc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single() {
        let s = TargetSpec::parse("192.168.1.1").unwrap();
        match s {
            TargetSpec::Single { host, port } => {
                assert_eq!(host, "192.168.1.1");
                assert!(port.is_none());
            }
            _ => panic!("Expected Single"),
        }
    }

    #[test]
    fn test_parse_single_with_port() {
        let s = TargetSpec::parse("10.0.0.5:3389").unwrap();
        match s {
            TargetSpec::Single { host, port } => {
                assert_eq!(host, "10.0.0.5");
                assert_eq!(port, Some(3389));
            }
            _ => panic!("Expected Single"),
        }
    }

    #[test]
    fn test_parse_cidr() {
        let s = TargetSpec::parse("192.168.1.0/24").unwrap();
        match s {
            TargetSpec::Cidr { network, prefix, .. } => {
                assert_eq!(network.to_string(), "192.168.1.0");
                assert_eq!(prefix, 24);
            }
            _ => panic!("Expected Cidr"),
        }
    }

    #[test]
    fn test_parse_range() {
        let s = TargetSpec::parse("10.0.0.1-10.0.0.5").unwrap();
        match s {
            TargetSpec::Range { start, end, .. } => {
                assert_eq!(start.to_string(), "10.0.0.1");
                assert_eq!(end.to_string(), "10.0.0.5");
            }
            _ => panic!("Expected Range"),
        }
    }

    #[test]
    fn test_expand_cidr_29() {
        let hosts = expand_cidr("192.168.1.0".parse().unwrap(), 29, None);
        assert_eq!(hosts.len(), 6);
        assert_eq!(hosts[0].0, "192.168.1.1");
        assert_eq!(hosts[5].0, "192.168.1.6");
    }

    #[test]
    fn test_expand_range() {
        let hosts = expand_range(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.3".parse().unwrap(),
            Some(22),
        );
        assert_eq!(hosts.len(), 3);
        assert_eq!(hosts[0], ("10.0.0.1".into(), Some(22)));
        assert_eq!(hosts[2], ("10.0.0.3".into(), Some(22)));
    }

    #[test]
    fn test_invalid_cidr_prefix() {
        assert!(TargetSpec::parse("10.0.0.0/33").is_err());
    }

    #[test]
    fn test_invalid_range_order() {
        assert!(TargetSpec::parse("10.0.0.10-10.0.0.5").is_err());
    }

    #[test]
    fn test_spec_is_lab() {
        assert!(spec_is_lab("192.168.1.1"));
        assert!(spec_is_lab("10.0.0.5:3389"));
        assert!(spec_is_lab("172.16.0.1-172.16.0.9"));
        assert!(spec_is_lab("192.168.1.0/24"));
        assert!(spec_is_lab("127.0.0.1"));
        assert!(spec_is_lab("localhost") == false);
        assert!(spec_is_lab("::1"));
        assert!(!spec_is_lab("8.8.8.8"));
        assert!(!spec_is_lab("1.1.1.1:443"));
        assert!(!spec_is_lab("example.com"));
        assert!(!spec_is_lab("8.8.8.0/24"));
    }
}
