use std::fmt;

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
    pub fn parse(input: &str) -> Result<Self, String> {
        let input = input.trim();

        let colon_slash = input.find("://")
            .ok_or_else(|| "Invalid proxy format. Use type://host:port".to_string())?;
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
            .ok_or_else(|| "Proxy must specify port".to_string())?;
        let host = host_port[..colon_pos].to_string();
        let port_str = &host_port[colon_pos + 1..];
        let port: u16 = port_str.parse()
            .map_err(|_| "Invalid proxy port".to_string())?;

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
            _ => Err(format!("Unsupported proxy type: {}. Use http, socks4, or socks5.", type_str)),
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

pub fn load_proxy_list(path: &std::path::Path) -> Result<Vec<ProxyConfig>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read proxy file: {}", e))?;

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
