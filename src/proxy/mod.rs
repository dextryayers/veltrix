use std::fmt;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use crate::core::error::AttackError;

#[derive(Debug, Clone)]
pub enum ProxyConfig {
    Http {
        host: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
        connect: bool,
    },
    Socks4 {
        host: String,
        port: u16,
        #[allow(dead_code)]
        username: Option<String>,
    },
    Socks5 {
        host: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
    },
    None,
}

impl ProxyConfig {
    pub fn parse(input: &str) -> Result<Self, AttackError> {
        let input = input.trim();

        let colon_slash = input.find("://")
            .ok_or_else(|| AttackError::config("Invalid proxy format. Use type://host:port"))?;
        let type_str = input[..colon_slash].to_lowercase();
        let rest = &input[colon_slash + 3..];

        let (host_port, auth) = if let Some(pos) = rest.find('@') {
            let a = &rest[..pos];
            let hp = &rest[pos + 1..];
            (hp, Some(a))
        } else {
            (rest, None)
        };

        let colon_pos = host_port.rfind(':')
            .ok_or_else(|| AttackError::config("Proxy must specify port"))?;
        let host = host_port[..colon_pos].to_string();
        let port_str = &host_port[colon_pos + 1..];
        let port: u16 = port_str.parse()
            .map_err(|_| AttackError::config("Invalid proxy port"))?;

        match type_str.as_str() {
            "http" => {
                let (username, password) = parse_auth(auth);
                Ok(ProxyConfig::Http { host, port, username, password, connect: false })
            }
            "https" => {
                let (username, password) = parse_auth(auth);
                Ok(ProxyConfig::Http { host, port, username, password, connect: true })
            }
            "socks4" => {
                let username = auth.map(|a| a.to_string());
                Ok(ProxyConfig::Socks4 { host, port, username })
            }
            "socks5" => {
                let (username, password) = parse_auth(auth);
                Ok(ProxyConfig::Socks5 { host, port, username, password })
            }
            _ => Err(AttackError::config(
                format!("Unsupported proxy type: {}. Use http, socks4, or socks5.", type_str)
            )),
        }
    }

    pub fn display(&self) -> String {
        match self {
            ProxyConfig::Http { host, port, connect, .. } => {
                if *connect {
                    format!("https://{}:{}", host, port)
                } else {
                    format!("http://{}:{}", host, port)
                }
            }
            ProxyConfig::Socks4 { host, port, .. } => format!("socks4://{}:{}", host, port),
            ProxyConfig::Socks5 { host, port, .. } => format!("socks5://{}:{}", host, port),
            ProxyConfig::None => "none".into(),
        }
    }

    pub fn to_reqwest_proxy(&self) -> Option<reqwest::Proxy> {
        match self {
            ProxyConfig::Http { host, port, username, password, connect: true } => {
                let url = format!("http://{}:{}", host, port);
                if let Ok(p) = reqwest::Proxy::https(&url) {
                    let p = if let (Some(u), Some(pw)) = (username, password) {
                        p.basic_auth(u, pw)
                    } else {
                        p
                    };
                    Some(p)
                } else {
                    None
                }
            }
            ProxyConfig::Http { host, port, username, password, connect: false } => {
                let url = format!("http://{}:{}", host, port);
                if let Ok(p) = reqwest::Proxy::http(&url) {
                    let p = if let (Some(u), Some(pw)) = (username, password) {
                        p.basic_auth(u, pw)
                    } else {
                        p
                    };
                    Some(p)
                } else {
                    None
                }
            }
            ProxyConfig::Socks5 { host, port, username, password } => {
                let url = format!("socks5://{}:{}", host, port);
                if let Ok(p) = reqwest::Proxy::all(&url) {
                    let p = if let (Some(u), Some(pw)) = (username, password) {
                        p.basic_auth(u, pw)
                    } else {
                        p
                    };
                    Some(p)
                } else {
                    None
                }
            }
            ProxyConfig::Socks4 { host, port, .. } => {
                let url = format!("socks4://{}:{}", host, port);
                reqwest::Proxy::all(&url).ok()
            }
            ProxyConfig::None => None,
        }
    }

    #[allow(dead_code)]
    pub fn connect_string(&self) -> Option<String> {
        match self {
            ProxyConfig::Http { host, port, username, password, .. } => {
                let auth = if let (Some(u), Some(p)) = (username, password) {
                    format!("{}:{}@", u, p)
                } else if let Some(u) = username {
                    format!("{}@", u)
                } else {
                    String::new()
                };
                Some(format!("{}://{}{}:{}",
                    if self.is_connect() { "https" } else { "http" },
                    auth, host, port))
            }
            ProxyConfig::Socks5 { host, port, username, password } => {
                let auth = if let (Some(u), Some(p)) = (username, password) {
                    format!("{}:{}@", u, p)
                } else if let Some(u) = username {
                    format!("{}@", u)
                } else {
                    String::new()
                };
                Some(format!("socks5://{}{}:{}", auth, host, port))
            }
            ProxyConfig::Socks4 { host, port, .. } => {
                Some(format!("socks4://{}:{}", host, port))
            }
            ProxyConfig::None => None,
        }
    }

    #[allow(dead_code)]
    pub fn is_connect(&self) -> bool {
        matches!(self, ProxyConfig::Http { connect: true, .. })
    }
}

fn parse_auth(auth: Option<&str>) -> (Option<String>, Option<String>) {
    if let Some(auth_str) = auth {
        if let Some(pos) = auth_str.find(':') {
            (Some(auth_str[..pos].to_string()), Some(auth_str[pos + 1..].to_string()))
        } else {
            (Some(auth_str.to_string()), None)
        }
    } else {
        (None, None)
    }
}

impl ProxyConfig {
    pub async fn tcp_connect(&self, addr: &str, timeout: Duration) -> Result<TcpStream, String> {
        match self {
            ProxyConfig::None => {
                tokio::time::timeout(timeout, TcpStream::connect(addr)).await
                    .map_err(|_| format!("Timeout connecting to {}", addr))?
                    .map_err(|e| format!("Failed to connect to {}: {}", addr, e))
            }
            ProxyConfig::Http { host, port, username, password, .. } => {
                let proxy_addr = format!("{}:{}", host, port);
                let mut stream = tokio::time::timeout(timeout, TcpStream::connect(&proxy_addr)).await
                    .map_err(|_| format!("Timeout connecting to proxy {}", proxy_addr))?
                    .map_err(|e| format!("Failed to connect to proxy {}: {}", proxy_addr, e))?;

                let auth_header = if let (Some(u), Some(p)) = (username, password) {
                    let credentials = base64_encode(&format!("{}:{}", u, p));
                    format!("Proxy-Authorization: Basic {}\r\n", credentials)
                } else {
                    String::new()
                };

                let connect_req = format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\n{}\r\n",
                    addr, addr, auth_header
                );
                stream.write_all(connect_req.as_bytes()).await
                    .map_err(|e| format!("Failed to send CONNECT: {}", e))?;
                stream.flush().await.ok();

                let mut buf = vec![0u8; 4096];
                let n = stream.read(&mut buf).await
                    .map_err(|e| format!("Failed to read CONNECT response: {}", e))?;
                let resp = String::from_utf8_lossy(&buf[..n]);

                if !resp.starts_with("HTTP/1.1 200") && !resp.starts_with("HTTP/1.0 200") {
                    return Err(format!("Proxy CONNECT failed: {}", resp.lines().next().unwrap_or("unknown")));
                }

                Ok(stream)
            }
            ProxyConfig::Socks5 { host, port, username, password } => {
                let proxy_addr = format!("{}:{}", host, port);
                let mut stream = tokio::time::timeout(timeout, TcpStream::connect(&proxy_addr)).await
                    .map_err(|_| format!("Timeout connecting to SOCKS5 proxy {}", proxy_addr))?
                    .map_err(|e| format!("Failed to connect to SOCKS5 proxy {}: {}", proxy_addr, e))?;

                // SOCKS5 greeting: no auth or username/password
                let auth_method = if username.is_some() { 0x02 } else { 0x00 };
                stream.write_all(&[0x05, 0x01, auth_method]).await
                    .map_err(|e| format!("SOCKS5 greeting send: {}", e))?;
                stream.flush().await.ok();

                let mut greeting_resp = [0u8; 2];
                stream.read_exact(&mut greeting_resp).await
                    .map_err(|e| format!("SOCKS5 greeting recv: {}", e))?;
                if greeting_resp[0] != 0x05 {
                    return Err("SOCKS5: invalid version".into());
                }
                if greeting_resp[1] == 0x02 {
                    // Username/password auth
                    let u = username.as_deref().unwrap_or("");
                    let p = password.as_deref().unwrap_or("");
                    let mut auth = vec![0x01, u.len() as u8];
                    auth.extend_from_slice(u.as_bytes());
                    auth.push(p.len() as u8);
                    auth.extend_from_slice(p.as_bytes());
                    stream.write_all(&auth).await
                        .map_err(|e| format!("SOCKS5 auth send: {}", e))?;
                    stream.flush().await.ok();

                    let mut auth_resp = [0u8; 2];
                    stream.read_exact(&mut auth_resp).await
                        .map_err(|e| format!("SOCKS5 auth recv: {}", e))?;
                    if auth_resp[1] != 0x00 {
                        return Err("SOCKS5: authentication failed".into());
                    }
                } else if greeting_resp[1] != 0x00 {
                    return Err("SOCKS5: no acceptable auth method".into());
                }

                // SOCKS5 connect request
                let (host_part, port_part) = addr.rsplit_once(':')
                    .ok_or_else(|| format!("Invalid address format: {}", addr))?;
                let port_num: u16 = port_part.parse()
                    .map_err(|_| format!("Invalid port: {}", port_part))?;

                let mut req = vec![0x05, 0x01, 0x00, 0x03, host_part.len() as u8];
                req.extend_from_slice(host_part.as_bytes());
                req.extend_from_slice(&port_num.to_be_bytes());

                stream.write_all(&req).await
                    .map_err(|e| format!("SOCKS5 connect send: {}", e))?;
                stream.flush().await.ok();

                let mut connect_resp = [0u8; 4];
                stream.read_exact(&mut connect_resp).await
                    .map_err(|e| format!("SOCKS5 connect recv: {}", e))?;
                if connect_resp[1] != 0x00 {
                    let err_msg = match connect_resp[1] {
                        0x01 => "general SOCKS server failure",
                        0x02 => "connection not allowed by ruleset",
                        0x03 => "network unreachable",
                        0x04 => "host unreachable",
                        0x05 => "connection refused",
                        0x06 => "TTL expired",
                        0x07 => "command not supported",
                        0x08 => "address type not supported",
                        _ => "unknown SOCKS error",
                    };
                    return Err(format!("SOCKS5: {}", err_msg));
                }

                // Read the rest of the BND.ADDR + BND.PORT
                let bnd_type = connect_resp[3];
                let rest_len = match bnd_type {
                    0x01 => 4 + 2,     // IPv4
                    0x03 => 1 + 2,     // Domain (skip len byte)
                    0x04 => 16 + 2,    // IPv6
                    _ => 2,
                };
                let mut rest = vec![0u8; rest_len];
                let _ = stream.read_exact(&mut rest).await;

                Ok(stream)
            }
            ProxyConfig::Socks4 { host, port, username } => {
                let proxy_addr = format!("{}:{}", host, port);
                let mut stream = tokio::time::timeout(timeout, TcpStream::connect(&proxy_addr)).await
                    .map_err(|_| format!("Timeout connecting to SOCKS4 proxy {}", proxy_addr))?
                    .map_err(|e| format!("Failed to connect to SOCKS4 proxy {}: {}", proxy_addr, e))?;

                let (host_part, port_part) = addr.rsplit_once(':')
                    .ok_or_else(|| format!("Invalid address format: {}", addr))?;
                let port_num: u16 = port_part.parse()
                    .map_err(|_| format!("Invalid port: {}", port_part))?;
                let ip_parts: Vec<&str> = host_part.split('.').collect();
                let user_id = username.as_deref().unwrap_or("");

                let mut req = Vec::with_capacity(9 + user_id.len());
                req.push(0x04); // SOCKS version
                req.push(0x01); // CONNECT
                req.extend_from_slice(&port_num.to_be_bytes());

                if ip_parts.len() == 4 {
                    // IPv4: resolve locally
                    for p in &ip_parts {
                        req.push(p.parse::<u8>().unwrap_or(0));
                    }
                } else {
                    // Domain name - use 0.0.0.x and send domain after userid
                    req.extend_from_slice(&[0, 0, 0, 1]);
                }
                req.extend_from_slice(user_id.as_bytes());
                req.push(0x00);

                if ip_parts.len() != 4 {
                    req.extend_from_slice(host_part.as_bytes());
                    req.push(0x00);
                }

                stream.write_all(&req).await
                    .map_err(|e| format!("SOCKS4 connect send: {}", e))?;
                stream.flush().await.ok();

                let mut resp = [0u8; 8];
                stream.read_exact(&mut resp).await
                    .map_err(|e| format!("SOCKS4 connect recv: {}", e))?;
                if resp[0] != 0x00 {
                    return Err("SOCKS4: invalid null byte".into());
                }
                if resp[1] != 0x5a {
                    let err_msg = match resp[1] {
                        0x5b => "request rejected or failed",
                        0x5c => "cannot connect to identd",
                        0x5d => "identd username mismatch",
                        _ => "unknown SOCKS4 error",
                    };
                    return Err(format!("SOCKS4: {}", err_msg));
                }

                Ok(stream)
            }
        }
    }
}

fn base64_encode(input: &str) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut result = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig::None
    }
}

impl fmt::Display for ProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http_proxy() {
        let p = ProxyConfig::parse("http://proxy.example.com:8080").unwrap();
        match p {
            ProxyConfig::Http { host, port, username, password, connect } => {
                assert_eq!(host, "proxy.example.com");
                assert_eq!(port, 8080);
                assert!(username.is_none());
                assert!(password.is_none());
                assert!(!connect);
            }
            _ => panic!("Expected Http variant"),
        }
    }

    #[test]
    fn test_parse_https_proxy() {
        let p = ProxyConfig::parse("https://proxy.example.com:8443").unwrap();
        match p {
            ProxyConfig::Http { host, port, connect, .. } => {
                assert_eq!(host, "proxy.example.com");
                assert_eq!(port, 8443);
                assert!(connect);
            }
            _ => panic!("Expected Http variant with connect=true"),
        }
    }

    #[test]
    fn test_parse_socks5_proxy() {
        let p = ProxyConfig::parse("socks5://127.0.0.1:9050").unwrap();
        match p {
            ProxyConfig::Socks5 { host, port, .. } => {
                assert_eq!(host, "127.0.0.1");
                assert_eq!(port, 9050);
            }
            _ => panic!("Expected Socks5 variant"),
        }
    }

    #[test]
    fn test_parse_socks4_proxy() {
        let p = ProxyConfig::parse("socks4://10.0.0.1:1080").unwrap();
        match p {
            ProxyConfig::Socks4 { host, port, .. } => {
                assert_eq!(host, "10.0.0.1");
                assert_eq!(port, 1080);
            }
            _ => panic!("Expected Socks4 variant"),
        }
    }

    #[test]
    fn test_parse_proxy_with_auth() {
        let p = ProxyConfig::parse("http://user:pass@proxy.com:3128").unwrap();
        match p {
            ProxyConfig::Http { username, password, .. } => {
                assert_eq!(username.unwrap(), "user");
                assert_eq!(password.unwrap(), "pass");
            }
            _ => panic!("Expected Http variant"),
        }
    }

    #[test]
    fn test_parse_proxy_invalid_format() {
        assert!(ProxyConfig::parse("not-a-proxy").is_err());
    }

    #[test]
    fn test_parse_proxy_unsupported_type() {
        assert!(ProxyConfig::parse("unknown://host:8080").is_err());
    }

    #[test]
    fn test_proxy_display() {
        let p = ProxyConfig::parse("http://proxy.com:8080").unwrap();
        assert_eq!(p.display(), "http://proxy.com:8080");

        let p = ProxyConfig::parse("socks5://10.0.0.1:9050").unwrap();
        assert_eq!(p.display(), "socks5://10.0.0.1:9050");
    }

    #[test]
    fn test_proxy_default() {
        let p = ProxyConfig::default();
        match p {
            ProxyConfig::None => {},
            _ => panic!("Expected None"),
        }
    }

    #[test]
    fn test_load_proxy_list() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_proxies.txt");
        std::fs::write(&path,
            "socks5://127.0.0.1:9050\nhttp://proxy.com:8080\n# comment\n\nsocks4://10.0.0.1:1080\n"
        ).unwrap();

        let proxies = load_proxy_list(&path).unwrap();
        assert_eq!(proxies.len(), 3);

        std::fs::remove_file(&path).ok();
    }
}

pub fn load_proxy_list(path: &std::path::Path) -> Result<Vec<ProxyConfig>, AttackError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| AttackError::io("proxy", format!("Failed to read proxy file: {}", e)))?;

    let mut proxies = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match ProxyConfig::parse(line) {
            Ok(p) => proxies.push(p),
            Err(e) => log::warn!("Skipping invalid proxy '{}': {}", line, e),
        }
    }
    Ok(proxies)
}
