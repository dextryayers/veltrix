use std::collections::HashMap;
use regex::Regex;

#[derive(Clone)]
pub struct ServiceDb {
    port_map: HashMap<u16, &'static str>,
    version_rules: Vec<VersionRule>,
    banner_rules: Vec<BannerRule>,
}

#[derive(Clone)]
struct VersionRule {
    port: u16,
    pattern: &'static str,
    product: &'static str,
    version_group: usize,
}

#[derive(Clone)]
struct BannerRule {
    pattern: &'static str,
    product: &'static str,
}

impl ServiceDb {
    pub fn new() -> Self {
        Self {
            port_map: build_port_map(),
            version_rules: build_version_rules(),
            banner_rules: build_banner_rules(),
        }
    }

    pub fn lookup(&self, port: u16) -> String {
        self.port_map
            .get(&port)
            .copied()
            .unwrap_or("unknown")
            .to_string()
    }

    pub fn identify(&self, port: u16, banner: &str) -> (Option<String>, Option<String>) {
        for rule in &self.version_rules {
            if rule.port != 0 && rule.port != port {
                continue;
            }
            if let Ok(re) = Regex::new(rule.pattern) {
                if let Some(caps) = re.captures(banner) {
                    let ver = caps.get(rule.version_group).map(|m| m.as_str().to_string());
                    return (Some(rule.product.to_string()), ver);
                }
            }
        }

        for rule in &self.banner_rules {
            if banner.to_lowercase().contains(rule.pattern) {
                return (Some(rule.product.to_string()), None);
            }
        }

        let port_lower = self.port_matches(port, banner);
        if let Some((p, v)) = port_lower {
            return (Some(p), v);
        }

        (None, None)
    }

    fn port_matches(&self, port: u16, banner: &str) -> Option<(String, Option<String>)> {
        let lower = banner.to_lowercase();
        match port {
            21 => {
                if lower.contains("pure-ftpd") {
                    if let Ok(re) = Regex::new(r"Pure-FTPd\s*(?:\[.*?\])?\s*v?([\d.]+)") {
                        if let Some(c) = re.captures(banner) {
                            return Some(("Pure-FTPd".to_string(), c.get(1).map(|m| m.as_str().to_string())));
                        }
                    }
                    return Some(("Pure-FTPd".to_string(), None));
                }
                if lower.contains("proftpd") {
                    if let Ok(re) = Regex::new(r"ProFTPD\s+([\d.]+)") {
                        if let Some(c) = re.captures(banner) {
                            return Some(("ProFTPD".to_string(), c.get(1).map(|m| m.as_str().to_string())));
                        }
                    }
                    return Some(("ProFTPD".to_string(), None));
                }
                if lower.contains("vsftpd") {
                    if let Ok(re) = Regex::new(r"vsFTPd\s+([\d.]+)") {
                        if let Some(c) = re.captures(banner) {
                            return Some(("vsFTPd".to_string(), c.get(1).map(|m| m.as_str().to_string())));
                        }
                    }
                    return Some(("vsFTPd".to_string(), None));
                }
                if lower.contains("filezilla") {
                    return Some(("FileZilla".to_string(), None));
                }
                if lower.contains("microsoft ftp") || lower.contains("microsoft-ftp") || lower.contains("msftp") {
                    if let Ok(re) = Regex::new(r"Microsoft[\s-]FTP[\s/]+([\d.]+)") {
                        if let Some(c) = re.captures(banner) {
                            return Some(("IIS FTP".to_string(), c.get(1).map(|m| m.as_str().to_string())));
                        }
                    }
                    return Some(("IIS FTP".to_string(), None));
                }
                if lower.contains("220") && (lower.contains("ftp") || banner.contains("FTP")) {
                    return Some(("FTP".to_string(), None));
                }
            }
            22 => {
                if let Ok(re) = Regex::new(r"SSH-([\d.]+)") {
                    if let Some(c) = re.captures(banner) {
                        let proto_ver = c.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
                        if lower.contains("openssh") {
                            if let Ok(re2) = Regex::new(r"OpenSSH[_-]([\w.]+)") {
                                if let Some(c2) = re2.captures(banner) {
                                    return Some(("OpenSSH".to_string(), Some(c2.get(1).map(|m| m.as_str().to_string()).unwrap_or_default())));
                                }
                            }
                            return Some(("OpenSSH".to_string(), Some(proto_ver)));
                        }
                        if lower.contains("dropbear") {
                            if let Ok(re2) = Regex::new(r"dropbear[_-]([\w.]+)") {
                                if let Some(c2) = re2.captures(banner) {
                                    return Some(("Dropbear".to_string(), Some(c2.get(1).map(|m| m.as_str().to_string()).unwrap_or_default())));
                                }
                            }
                            return Some(("Dropbear".to_string(), None));
                        }
                        if lower.contains("libssh") {
                            return Some(("libSSH".to_string(), Some(proto_ver)));
                        }
                        if lower.contains("tectia") {
                            return Some(("Tectia SSH".to_string(), Some(proto_ver)));
                        }
                        return Some(("SSH".to_string(), Some(proto_ver)));
                    }
                }
            }
            23 => {
                for line in banner.lines() {
                    let l = line.trim();
                    if !l.is_empty() {
                        let words: Vec<&str> = l.split_whitespace().collect();
                        if words.len() >= 1 {
                            let first = words[0].trim_end_matches(':');
                            if !first.contains("login") && !first.contains("password")
                                && !first.contains("user") && !first.contains("pass")
                            {
                                if first.len() >= 3 && first.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') {
                                    return Some((format!("telnet ({})", first), None));
                                }
                            }
                        }
                    }
                }
                if lower.contains("telnet") || lower.contains("telnetd") {
                    return Some(("Telnet".to_string(), None));
                }
                if lower.contains("linux") {
                    return Some(("Telnet (Linux)".to_string(), None));
                }
                if lower.contains("unix") {
                    return Some(("Telnet (Unix)".to_string(), None));
                }
                if lower.contains("windows") {
                    return Some(("Telnet (Windows)".to_string(), None));
                }
            }
            25 | 587 | 465 => {
                if lower.contains("postfix") {
                    if let Ok(re) = Regex::new(r"Postfix[\s/]+([\d.]+)") {
                        if let Some(c) = re.captures(banner) {
                            return Some(("Postfix".to_string(), c.get(1).map(|m| m.as_str().to_string())));
                        }
                    }
                    return Some(("Postfix".to_string(), None));
                }
                if lower.contains("exim") {
                    if let Ok(re) = Regex::new(r"Exim\s+([\d.]+)") {
                        if let Some(c) = re.captures(banner) {
                            return Some(("Exim".to_string(), c.get(1).map(|m| m.as_str().to_string())));
                        }
                    }
                    return Some(("Exim".to_string(), None));
                }
                if lower.contains("sendmail") {
                    if let Ok(re) = Regex::new(r"Sendmail\s+([\d.]+)") {
                        if let Some(c) = re.captures(banner) {
                            return Some(("Sendmail".to_string(), c.get(1).map(|m| m.as_str().to_string())));
                        }
                    }
                    return Some(("Sendmail".to_string(), None));
                }
                if lower.contains("microsoft") || lower.contains("exchange") {
                    return Some(("Microsoft Exchange".to_string(), None));
                }
                if lower.contains("qmail") {
                    return Some(("qmail".to_string(), None));
                }
                if lower.contains("esmtp") || lower.contains("smtp") {
                    if let Ok(re) = Regex::new(r"ESMTP\s+(?:[^\s]+\s+)?\(?([\w.]+)") {
                        if let Some(c) = re.captures(banner) {
                            let ver = c.get(1).map(|m| m.as_str().to_string());
                            return Some(("SMTP".to_string(), ver));
                        }
                    }
                    return Some(("SMTP".to_string(), None));
                }
            }
            80 | 443 | 8080 | 8443 | 8000 | 8008 | 8009 | 8001 | 8002 | 8003 | 8004 | 8005 | 8006 | 8007 | 8010 | 8888 | 9443 | 18080 | 16080 | 35000 | 35001 => {
                for line in banner.lines() {
                    if line.to_lowercase().starts_with("server:") {
                        let val = line[7..].trim();
                        if let Ok(re) = Regex::new(r"(?i)(apache)/([\d.]+)") {
                            if let Some(c) = re.captures(val) {
                                return Some(("Apache".to_string(), c.get(2).map(|m| m.as_str().to_string())));
                            }
                        }
                        if let Ok(re) = Regex::new(r"(?i)(nginx)[/ ]([\d.]+)") {
                            if let Some(c) = re.captures(val) {
                                return Some(("nginx".to_string(), c.get(2).map(|m| m.as_str().to_string())));
                            }
                        }
                        if let Ok(re) = Regex::new(r"(?i)IIS[ /]([\d.]+)") {
                            if let Some(c) = re.captures(val) {
                                return Some(("IIS".to_string(), c.get(1).map(|m| m.as_str().to_string())));
                            }
                        }
                        if val.to_lowercase().contains("iis") {
                            return Some(("IIS".to_string(), None));
                        }
                        if val.to_lowercase().contains("apache") {
                            return Some(("Apache".to_string(), None));
                        }
                        if val.to_lowercase().contains("nginx") {
                            return Some(("nginx".to_string(), None));
                        }
                        if val.to_lowercase().contains("lighttpd") {
                            if let Ok(re) = Regex::new(r"lighttpd/([\d.]+)") {
                                if let Some(c) = re.captures(val) {
                                    return Some(("lighttpd".to_string(), c.get(1).map(|m| m.as_str().to_string())));
                                }
                            }
                            return Some(("lighttpd".to_string(), None));
                        }
                        if val.to_lowercase().contains("caddy") {
                            if let Ok(re) = Regex::new(r"Caddy[/ ]([\d.]+)") {
                                if let Some(c) = re.captures(val) {
                                    return Some(("Caddy".to_string(), c.get(1).map(|m| m.as_str().to_string())));
                                }
                            }
                            return Some(("Caddy".to_string(), None));
                        }
                        if val.to_lowercase().contains("tomcat") {
                            if let Ok(re) = Regex::new(r"(?i)Tomcat[/ ]([\d.]+)") {
                                if let Some(c) = re.captures(val) {
                                    return Some(("Tomcat".to_string(), c.get(1).map(|m| m.as_str().to_string())));
                                }
                            }
                            return Some(("Tomcat".to_string(), None));
                        }
                        if val.to_lowercase().contains("gunicorn") {
                            return Some(("Gunicorn".to_string(), None));
                        }
                        if val.to_lowercase().contains("uvicorn") {
                            return Some(("Uvicorn".to_string(), None));
                        }
                        if val.to_lowercase().contains("node.js") || val.to_lowercase().contains("node") {
                            return Some(("Node.js".to_string(), None));
                        }
                        if val.to_lowercase().contains("express") {
                            return Some(("Express".to_string(), None));
                        }
                        if val.to_lowercase().contains("kestrel") {
                            if let Ok(re) = Regex::new(r"Kestrel[/\s]+([\d.]+)") {
                                if let Some(c) = re.captures(val) {
                                    return Some(("Kestrel".to_string(), c.get(1).map(|m| m.as_str().to_string())));
                                }
                            }
                            return Some(("Kestrel".to_string(), None));
                        }
                        if val.to_lowercase().contains("jetty") {
                            if let Ok(re) = Regex::new(r"Jetty[/]([\d.]+)") {
                                if let Some(c) = re.captures(val) {
                                    return Some(("Jetty".to_string(), c.get(1).map(|m| m.as_str().to_string())));
                                }
                            }
                            return Some(("Jetty".to_string(), None));
                        }
                        if val.to_lowercase().contains("python") {
                            return Some(("Python".to_string(), None));
                        }
                        let val_lower = val.to_lowercase();
                        if !val_lower.contains("server:") && !val.is_empty() {
                            return Some((val.to_string(), None));
                        }
                    }
                }
                if lower.contains("<html") || lower.contains("<!doctype") || lower.contains("<head") {
                    return Some(("HTTP".to_string(), None));
                }
                if let Ok(re) = Regex::new(r"HTTP/1\.[01] \d+") {
                    if re.is_match(banner) {
                        return Some(("HTTP".to_string(), None));
                    }
                }
            }
            110 | 995 => {
                if lower.contains("dovecot") {
                    return Some(("Dovecot POP3".to_string(), None));
                }
                if lower.contains("courier") {
                    return Some(("Courier POP3".to_string(), None));
                }
                if lower.contains("cyrus") {
                    return Some(("Cyrus POP3".to_string(), None));
                }
                if lower.contains("+ok") {
                    return Some(("POP3".to_string(), None));
                }
            }
            143 | 993 => {
                if lower.contains("dovecot") {
                    return Some(("Dovecot IMAP".to_string(), None));
                }
                if lower.contains("courier") {
                    return Some(("Courier IMAP".to_string(), None));
                }
                if lower.contains("cyrus") {
                    return Some(("Cyrus IMAP".to_string(), None));
                }
                if lower.contains("* ok") {
                    return Some(("IMAP".to_string(), None));
                }
            }
            3306 => {
                if lower.contains("mariadb") {
                    if let Ok(re) = Regex::new(r"([\d.]+)-MariaDB") {
                        if let Some(c) = re.captures(banner) {
                            return Some(("MariaDB".to_string(), c.get(1).map(|m| m.as_str().to_string())));
                        }
                    }
                    if let Ok(re) = Regex::new(r"(\d+\.\d+\.\d+)") {
                        if let Some(c) = re.captures(banner) {
                            let v = c.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
                            if v.starts_with("5.") || v.starts_with("10.") || v.starts_with("11.") {
                                return Some(("MariaDB".to_string(), Some(v)));
                            }
                        }
                    }
                    return Some(("MariaDB".to_string(), None));
                }
                if lower.contains("mysql") || lower.contains("native_password") || lower.contains("caching_sha2") {
                    if let Ok(re) = Regex::new(r"(\d+\.\d+\.\d+)\s*mysql") {
                        if let Some(c) = re.captures(banner) {
                            return Some(("MySQL".to_string(), c.get(1).map(|m| m.as_str().to_string())));
                        }
                    }
                    if let Ok(re) = Regex::new(r"(\d+\.\d+\.\d+)") {
                        if let Some(c) = re.captures(banner) {
                            let v = c.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
                            if v.starts_with("8.") || v.starts_with("5.") || v.starts_with("9.") {
                                return Some(("MySQL".to_string(), Some(v)));
                            }
                        }
                    }
                    return Some(("MySQL".to_string(), None));
                }
                if lower.chars().filter(|c| *c == '\0').count() > 10 {
                    return Some(("MySQL".to_string(), None));
                }
            }
            6379 | 6380 => {
                if let Ok(re) = Regex::new(r"redis_version[:\s]+([\d.]+)") {
                    if let Some(c) = re.captures(banner) {
                        return Some(("Redis".to_string(), c.get(1).map(|m| m.as_str().to_string())));
                    }
                }
                if let Ok(re) = Regex::new(r"redis_version:([\d.]+)") {
                    if let Some(c) = re.captures(banner) {
                        return Some(("Redis".to_string(), c.get(1).map(|m| m.as_str().to_string())));
                    }
                }
                if lower.contains("redis") || lower.contains("+ok") || lower.contains("-no") || lower.contains("-err") {
                    return Some(("Redis".to_string(), None));
                }
            }
            5432 => {
                if let Ok(re) = Regex::new(r"PostgreSQL[\s.]+([\d.]+)") {
                    if let Some(c) = re.captures(banner) {
                        return Some(("PostgreSQL".to_string(), c.get(1).map(|m| m.as_str().to_string())));
                    }
                }
                if let Ok(re) = Regex::new(r"backend_pid") {
                    if re.is_match(banner) {
                        return Some(("PostgreSQL".to_string(), None));
                    }
                }
                if lower.len() > 10 && lower.as_bytes()[0] == 0 {
                    return Some(("PostgreSQL".to_string(), None));
                }
            }
            27017 | 27018 => {
                if lower.contains("mongodb") {
                    if let Ok(re) = Regex::new(r"(\d+\.\d+\.\d+)") {
                        if let Some(c) = re.captures(banner) {
                            let v = c.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
                            if v.starts_with("2.") || v.starts_with("3.") || v.starts_with("4.") || v.starts_with("5.") || v.starts_with("6.") || v.starts_with("7.") || v.starts_with("8.") {
                                return Some(("MongoDB".to_string(), Some(v)));
                            }
                        }
                    }
                    return Some(("MongoDB".to_string(), None));
                }
                if lower.contains("ok: 1") || lower.contains("ismaster") || lower.contains("is_master") {
                    return Some(("MongoDB".to_string(), None));
                }
            }
            389 | 636 => {
                if lower.contains("openldap") {
                    if let Ok(re) = Regex::new(r"OpenLDAP:? ([\d.]+)") {
                        if let Some(c) = re.captures(banner) {
                            return Some(("OpenLDAP".to_string(), c.get(1).map(|m| m.as_str().to_string())));
                        }
                    }
                    return Some(("OpenLDAP".to_string(), None));
                }
                if lower.contains("microsoft") || lower.contains("windows") || lower.contains("active directory") {
                    return Some(("Active Directory".to_string(), None));
                }
                if lower.contains("389") {
                    return Some(("LDAP".to_string(), None));
                }
            }
            3389 => {
                if lower.contains("rdp") || lower.contains("terminal") || lower.contains("remote desktop") {
                    return Some(("RDP".to_string(), None));
                }
                if let Ok(re) = Regex::new(r"\x03\x00") {
                    if re.is_match(banner) {
                        return Some(("RDP".to_string(), None));
                    }
                }
            }
            5900 | 5901 | 5902 | 5903 => {
                if let Ok(re) = Regex::new(r"RFB ([\d.]+)") {
                    if let Some(c) = re.captures(banner) {
                        return Some(("VNC".to_string(), c.get(1).map(|m| m.as_str().to_string())));
                    }
                }
                if lower.contains("rfb") || lower.contains("vnc") {
                    return Some(("VNC".to_string(), None));
                }
            }
            1433 | 1434 => {
                if lower.contains("ms-sql") || lower.contains("microsoft sql") || lower.contains("sql server") {
                    return Some(("MSSQL".to_string(), None));
                }
            }
            1521 => {
                if lower.contains("oracle") || lower.contains("bequeath") || lower.contains("descriptions") {
                    return Some(("Oracle DB".to_string(), None));
                }
            }
            11211 => {
                if let Ok(re) = Regex::new(r"(\d+\.\d+\.\d+)") {
                    if let Some(c) = re.captures(banner) {
                        let v = c.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
                        if v.starts_with("1.") {
                            return Some(("Memcached".to_string(), Some(v)));
                        }
                    }
                }
                if lower.contains("stat") || lower.contains("version") || lower.contains("pid") {
                    return Some(("Memcached".to_string(), None));
                }
            }
            _ => {}
        }
        None
    }
}

fn build_version_rules() -> Vec<VersionRule> {
    vec![
        VersionRule { port: 0, pattern: r"OpenSSH[_-]([\w.]+)", product: "OpenSSH", version_group: 1 },
        VersionRule { port: 0, pattern: r"dropbear[_-]([\w.]+)", product: "Dropbear", version_group: 1 },
        VersionRule { port: 0, pattern: r"libssh[_-]([\w.]+)", product: "libSSH", version_group: 1 },
        VersionRule { port: 0, pattern: r"Apache/([\d.]+)", product: "Apache", version_group: 1 },
        VersionRule { port: 0, pattern: r"nginx/([\d.]+)", product: "nginx", version_group: 1 },
        VersionRule { port: 0, pattern: r"lighttpd/([\d.]+)", product: "lighttpd", version_group: 1 },
        VersionRule { port: 0, pattern: r"(?i)Caddy[/ ]([\d.]+)", product: "Caddy", version_group: 1 },
        VersionRule { port: 0, pattern: r"(?i)Tomcat[/ ]([\d.]+)", product: "Tomcat", version_group: 1 },
        VersionRule { port: 0, pattern: r"(\d+\.\d+\.\d+)[-\s]Tomcat", product: "Tomcat", version_group: 1 },
        VersionRule { port: 0, pattern: r"IIS[ /]([\d.]+)", product: "IIS", version_group: 1 },
        VersionRule { port: 0, pattern: r"Microsoft-IIS/([\d.]+)", product: "IIS", version_group: 1 },
        VersionRule { port: 0, pattern: r"vsFTPd\s+([\d.]+)", product: "vsFTPd", version_group: 1 },
        VersionRule { port: 0, pattern: r"ProFTPD\s+([\d.]+)", product: "ProFTPD", version_group: 1 },
        VersionRule { port: 0, pattern: r"Pure-FTPd.*?v?([\d.]+)", product: "Pure-FTPd", version_group: 1 },
        VersionRule { port: 0, pattern: r"FileZilla Server[\s/]*([\d.]+)", product: "FileZilla", version_group: 1 },
        VersionRule { port: 0, pattern: r"PostgreSQL[\s.]+([\d.]+)", product: "PostgreSQL", version_group: 1 },
        VersionRule { port: 0, pattern: r"mysql.*?([\d.]+)", product: "MySQL", version_group: 1 },
        VersionRule { port: 0, pattern: r"MariaDB.*?([\d.]+)", product: "MariaDB", version_group: 1 },
        VersionRule { port: 0, pattern: r"redis_version[:\s]+([\d.]+)", product: "Redis", version_group: 1 },
        VersionRule { port: 0, pattern: r"OpenLDAP:?\s+([\d.]+)", product: "OpenLDAP", version_group: 1 },
        VersionRule { port: 0, pattern: r"Squid[\s(]+([\d.]+)", product: "Squid", version_group: 1 },
        VersionRule { port: 0, pattern: r"Elasticsearch[\s/]+([\d.]+)", product: "Elasticsearch", version_group: 1 },
        VersionRule { port: 0, pattern: r"Docker/?([\d.]+)", product: "Docker", version_group: 1 },
        VersionRule { port: 0, pattern: r"Jenkins[/ ]?([\d.]+)", product: "Jenkins", version_group: 1 },
        VersionRule { port: 0, pattern: r"Exchange Server[\s/]*([\d.]+)", product: "Exchange", version_group: 1 },
        VersionRule { port: 0, pattern: r"OpenVPN[\s/]+([\d.]+)", product: "OpenVPN", version_group: 1 },
        VersionRule { port: 0, pattern: r"mongod.*?([\d.]+)", product: "MongoDB", version_group: 1 },
        VersionRule { port: 0, pattern: r"Postfix[\s/]+([\d.]+)", product: "Postfix", version_group: 1 },
        VersionRule { port: 0, pattern: r"Exim[\s/]+([\d.]+)", product: "Exim", version_group: 1 },
        VersionRule { port: 0, pattern: r"Sendmail[\s/]+([\d.]+)", product: "Sendmail", version_group: 1 },
        VersionRule { port: 0, pattern: r"Courier-IMAP[\s/]+([\d.]+)", product: "Courier IMAP", version_group: 1 },
        VersionRule { port: 0, pattern: r"Dovecot[\s(]+([\d.]+)", product: "Dovecot", version_group: 1 },
        VersionRule { port: 0, pattern: r"Zabbix[\s/]+([\d.]+)", product: "Zabbix", version_group: 1 },
        VersionRule { port: 0, pattern: r"Nessus[\s/]+([\d.]+)", product: "Nessus", version_group: 1 },
        VersionRule { port: 0, pattern: r"WebLogic[\s/]+([\d.]+)", product: "WebLogic", version_group: 1 },
        VersionRule { port: 0, pattern: r"Jetty[/]([\d.]+)", product: "Jetty", version_group: 1 },
        VersionRule { port: 0, pattern: r"Netty[/]([\d.]+)", product: "Netty", version_group: 1 },
        VersionRule { port: 0, pattern: r"Oracle\s*(?:Database|DB)?\s*([\d.]+)", product: "Oracle DB", version_group: 1 },
        VersionRule { port: 0, pattern: r"Cassandra[/\s]+([\d.]+)", product: "Cassandra", version_group: 1 },
        VersionRule { port: 0, pattern: r"RabbitMQ[/\s]+([\d.]+)", product: "RabbitMQ", version_group: 1 },
        VersionRule { port: 0, pattern: r"HAProxy[/\s]+([\d.]+)", product: "HAProxy", version_group: 1 },
        VersionRule { port: 0, pattern: r"Traefik[/\s]+([\d.]+)", product: "Traefik", version_group: 1 },
        VersionRule { port: 0, pattern: r"Microsoft-HTTPAPI[/\s]+([\d.]+)", product: "Microsoft HTTPAPI", version_group: 1 },
        VersionRule { port: 0, pattern: r"Kestrel[/\s]+([\d.]+)", product: "Kestrel", version_group: 1 },
        VersionRule { port: 0, pattern: r"Gunicorn[\s/]+([\d.]+)", product: "Gunicorn", version_group: 1 },
        VersionRule { port: 0, pattern: r"Node\.js[/\s]+([\d.]+)", product: "Node.js", version_group: 1 },
        VersionRule { port: 0, pattern: r"^SSH-([\d.]+)", product: "SSH", version_group: 1 },
        VersionRule { port: 0, pattern: r"220[-\s].*FTP", product: "FTP", version_group: 0 },
        VersionRule { port: 0, pattern: r"220[-\s].*vsFTPd", product: "vsFTPd", version_group: 0 },
        VersionRule { port: 0, pattern: r"220[-\s].*ProFTPD", product: "ProFTPD", version_group: 0 },
        VersionRule { port: 0, pattern: r"220[-\s].*Pure-FTPd", product: "Pure-FTPd", version_group: 0 },
        VersionRule { port: 0, pattern: r"220[-\s].*FileZilla", product: "FileZilla", version_group: 0 },
        VersionRule { port: 0, pattern: r"Microsoft ESMTP.*([\d.]+)", product: "Microsoft SMTP", version_group: 1 },
        VersionRule { port: 0, pattern: r"ESMTP Postfix", product: "Postfix", version_group: 0 },
        VersionRule { port: 0, pattern: r"Exim\s+([\d.]+)", product: "Exim", version_group: 1 },
        VersionRule { port: 0, pattern: r"Sendmail\s+([\d.]+)", product: "Sendmail", version_group: 1 },
        VersionRule { port: 0, pattern: r"220 .* ESMTP.*Server ESMTP", product: "SMTP", version_group: 0 },
        VersionRule { port: 0, pattern: r"\* OK.*Dovecot", product: "Dovecot", version_group: 0 },
        VersionRule { port: 0, pattern: r"\* OK.*Courier-IMAP", product: "Courier IMAP", version_group: 0 },
        VersionRule { port: 0, pattern: r"\* OK.*Cyrus", product: "Cyrus IMAP", version_group: 0 },
        VersionRule { port: 0, pattern: r"\+OK.*Courier", product: "Courier POP3", version_group: 0 },
        VersionRule { port: 0, pattern: r"\+OK.*Dovecot", product: "Dovecot POP3", version_group: 0 },
        VersionRule { port: 0, pattern: r"RFB ([\d.]+)", product: "VNC", version_group: 1 },
        VersionRule { port: 0, pattern: r"MySQL.*?([\d.]+)", product: "MySQL", version_group: 1 },
        VersionRule { port: 0, pattern: r"([\d.]+)-MariaDB", product: "MariaDB", version_group: 1 },
        VersionRule { port: 0, pattern: r"Memcached\s+([\d.]+)", product: "Memcached", version_group: 1 },
        VersionRule { port: 0, pattern: r"InfluxDB[\s/]+([\d.]+)", product: "InfluxDB", version_group: 1 },
        VersionRule { port: 0, pattern: r"Prometheus[/\s]+([\d.]+)", product: "Prometheus", version_group: 1 },
        VersionRule { port: 0, pattern: r"Grafana[/\s]+([\d.]+)", product: "Grafana", version_group: 1 },
        VersionRule { port: 0, pattern: r"Kibana[\s/]+([\d.]+)", product: "Kibana", version_group: 1 },
        VersionRule { port: 0, pattern: r"Splunk[\s/]+([\d.]+)", product: "Splunk", version_group: 1 },
        VersionRule { port: 0, pattern: r"Solr[\s/]+([\d.]+)", product: "Solr", version_group: 1 },
        VersionRule { port: 0, pattern: r"CouchDB[/\s]+([\d.]+)", product: "CouchDB", version_group: 1 },
        VersionRule { port: 0, pattern: r"Neo4j[/\s]+([\d.]+)", product: "Neo4j", version_group: 1 },
        VersionRule { port: 0, pattern: r"Consul[/\s]+([\d.]+)", product: "Consul", version_group: 1 },
        VersionRule { port: 0, pattern: r"Vault[/\s]+([\d.]+)", product: "HashiCorp Vault", version_group: 1 },
        VersionRule { port: 0, pattern: r"etcd[\s/]+([\d.]+)", product: "etcd", version_group: 1 },
        VersionRule { port: 0, pattern: r"Kubernetes[/\s]+([\d.]+)", product: "Kubernetes", version_group: 1 },
        VersionRule { port: 0, pattern: r"Docker Registry[/\s]+([\d.]+)", product: "Docker Registry", version_group: 1 },
        VersionRule { port: 0, pattern: r"GitLab[/\s]+([\d.]+)", product: "GitLab", version_group: 1 },
        VersionRule { port: 0, pattern: r"Bitbucket[/\s]+([\d.]+)", product: "Bitbucket", version_group: 1 },
        VersionRule { port: 0, pattern: r"Jira[/\s]+([\d.]+)", product: "Jira", version_group: 1 },
        VersionRule { port: 0, pattern: r"Confluence[/\s]+([\d.]+)", product: "Confluence", version_group: 1 },
        VersionRule { port: 0, pattern: r"SonarQube[/\s]+([\d.]+)", product: "SonarQube", version_group: 1 },
        VersionRule { port: 0, pattern: r"Nexus[/\s]+([\d.]+)", product: "Sonatype Nexus", version_group: 1 },
        VersionRule { port: 0, pattern: r"Artifactory[/\s]+([\d.]+)", product: "JFrog Artifactory", version_group: 1 },
        VersionRule { port: 0, pattern: r"Apache.*?Jserv", product: "Apache JServ", version_group: 0 },
        VersionRule { port: 0, pattern: r"Apache.*?Coyote", product: "Apache Coyote", version_group: 0 },
        VersionRule { port: 0, pattern: r"Envoy[/\s]+([\d.]+)", product: "Envoy", version_group: 1 },
        VersionRule { port: 0, pattern: r"Plex[/\s]+([\d.]+)", product: "Plex", version_group: 1 },
        VersionRule { port: 0, pattern: r"WordPress[/\s]+([\d.]+)", product: "WordPress", version_group: 1 },
        VersionRule { port: 0, pattern: r"Drupal[/\s]+([\d.]+)", product: "Drupal", version_group: 1 },
        VersionRule { port: 0, pattern: r"Joomla[/\s]+([\d.]+)", product: "Joomla", version_group: 1 },
        VersionRule { port: 0, pattern: r"Magento[/\s]+([\d.]+)", product: "Magento", version_group: 1 },
        VersionRule { port: 0, pattern: r"MediaWiki[/\s]+([\d.]+)", product: "MediaWiki", version_group: 1 },
        VersionRule { port: 0, pattern: r"phpMyAdmin[/\s]+([\d.]+)", product: "phpMyAdmin", version_group: 1 },
        VersionRule { port: 0, pattern: r"PHP[/\s]+([\d.]+)", product: "PHP", version_group: 1 },
        VersionRule { port: 0, pattern: r"Python[/\s]+([\d.]+)", product: "Python", version_group: 1 },
        VersionRule { port: 0, pattern: r"Go[/\s]+([\d.]+)", product: "Go net/http", version_group: 1 },
        VersionRule { port: 0, pattern: r"Ruby[/\s]+([\d.]+)", product: "Ruby", version_group: 1 },
        VersionRule { port: 0, pattern: r"Unicorn[/\s]+([\d.]+)", product: "Unicorn", version_group: 1 },
        VersionRule { port: 0, pattern: r"Thin[/\s]+([\d.]+)", product: "Thin", version_group: 1 },
        VersionRule { port: 0, pattern: r"Phusion Passenger[/\s]+([\d.]+)", product: "Passenger", version_group: 1 },
        VersionRule { port: 0, pattern: r"Puma[/\s]+([\d.]+)", product: "Puma", version_group: 1 },
        VersionRule { port: 0, pattern: r"WEBrick[/\s]+([\d.]+)", product: "WEBrick", version_group: 1 },
        VersionRule { port: 0, pattern: r"Tornado[/\s]+([\d.]+)", product: "Tornado", version_group: 1 },
        VersionRule { port: 0, pattern: r"CherryPy[/\s]+([\d.]+)", product: "CherryPy", version_group: 1 },
        VersionRule { port: 0, pattern: r"Twisted[/\s]+([\d.]+)", product: "Twisted", version_group: 1 },
        VersionRule { port: 0, pattern: r"aiohttp[/\s]+([\d.]+)", product: "aiohttp", version_group: 1 },
        VersionRule { port: 0, pattern: r"Werkzeug[/\s]+([\d.]+)", product: "Werkzeug", version_group: 1 },
        VersionRule { port: 0, pattern: r"Boa[/\s]+([\d.]+)", product: "Boa", version_group: 1 },
        VersionRule { port: 0, pattern: r"Thttpd[/\s]+([\d.]+)", product: "thttpd", version_group: 1 },
        VersionRule { port: 0, pattern: r"mini_httpd[/\s]+([\d.]+)", product: "mini_httpd", version_group: 1 },
        VersionRule { port: 0, pattern: r"Apache.*?\(.*?CentOS", product: "Apache (CentOS)", version_group: 0 },
        VersionRule { port: 0, pattern: r"Apache.*?\(.*?Debian", product: "Apache (Debian)", version_group: 0 },
        VersionRule { port: 0, pattern: r"Apache.*?\(.*?Ubuntu", product: "Apache (Ubuntu)", version_group: 0 },
        VersionRule { port: 0, pattern: r"Apache.*?\(.*?FreeBSD", product: "Apache (FreeBSD)", version_group: 0 },
        VersionRule { port: 0, pattern: r"Apache.*?\(.*?Win", product: "Apache (Windows)", version_group: 0 },
        VersionRule { port: 0, pattern: r"nginx.*?\(.*?Ubuntu", product: "nginx (Ubuntu)", version_group: 0 },
        VersionRule { port: 0, pattern: r"nginx.*?\(.*?Debian", product: "nginx (Debian)", version_group: 0 },
        VersionRule { port: 0, pattern: r"nginx.*?\(.*?CentOS", product: "nginx (CentOS)", version_group: 0 },
        VersionRule { port: 0, pattern: r"nginx.*?\(.*?FreeBSD", product: "nginx (FreeBSD)", version_group: 0 },
    ]
}

fn build_banner_rules() -> Vec<BannerRule> {
    vec![
        BannerRule { pattern: "pure-ftpd", product: "Pure-FTPd" },
        BannerRule { pattern: "proftpd", product: "ProFTPD" },
        BannerRule { pattern: "vsftpd", product: "vsFTPd" },
        BannerRule { pattern: "filezilla", product: "FileZilla" },
        BannerRule { pattern: "microsoft ftp", product: "IIS FTP" },
        BannerRule { pattern: "openssh", product: "OpenSSH" },
        BannerRule { pattern: "postfix", product: "Postfix" },
        BannerRule { pattern: "sendmail", product: "Sendmail" },
        BannerRule { pattern: "exim", product: "Exim" },
        BannerRule { pattern: "dovecot", product: "Dovecot" },
        BannerRule { pattern: "courier imap", product: "Courier IMAP" },
        BannerRule { pattern: "cyrus", product: "Cyrus IMAP" },
        BannerRule { pattern: "openldap", product: "OpenLDAP" },
        BannerRule { pattern: "mysql", product: "MySQL" },
        BannerRule { pattern: "mariadb", product: "MariaDB" },
        BannerRule { pattern: "redis", product: "Redis" },
        BannerRule { pattern: "mongodb", product: "MongoDB" },
        BannerRule { pattern: "postgresql", product: "PostgreSQL" },
        BannerRule { pattern: "memcached", product: "Memcached" },
        BannerRule { pattern: "squid", product: "Squid" },
        BannerRule { pattern: "docker", product: "Docker" },
        BannerRule { pattern: "couchdb", product: "CouchDB" },
        BannerRule { pattern: "elasticsearch", product: "Elasticsearch" },
        BannerRule { pattern: "cassandra", product: "Cassandra" },
        BannerRule { pattern: "kafka", product: "Kafka" },
        BannerRule { pattern: "activemq", product: "ActiveMQ" },
        BannerRule { pattern: "weblogic", product: "WebLogic" },
        BannerRule { pattern: "zabbix", product: "Zabbix" },
        BannerRule { pattern: "nessus", product: "Nessus" },
        BannerRule { pattern: "sap ", product: "SAP" },
        BannerRule { pattern: "hadoop", product: "Hadoop" },
        BannerRule { pattern: "rethinkdb", product: "RethinkDB" },
        BannerRule { pattern: "oracle", product: "Oracle DB" },
        BannerRule { pattern: "openvpn", product: "OpenVPN" },
        BannerRule { pattern: "winrm", product: "WinRM" },
        BannerRule { pattern: "jenkins", product: "Jenkins" },
        BannerRule { pattern: "plex", product: "Plex" },
        BannerRule { pattern: "ms-sql", product: "MSSQL" },
        BannerRule { pattern: "cisco", product: "Cisco IOS" },
        BannerRule { pattern: "pfsense", product: "pfSense" },
        BannerRule { pattern: "mikrotik", product: "MikroTik" },
        BannerRule { pattern: "dd-wrt", product: "DD-WRT" },
        BannerRule { pattern: "sonicwall", product: "SonicWall" },
        BannerRule { pattern: "fortinet", product: "Fortinet" },
        BannerRule { pattern: "palo alto", product: "Palo Alto" },
        BannerRule { pattern: "checkpoint", product: "Check Point" },
        BannerRule { pattern: "juniper", product: "Juniper" },
        BannerRule { pattern: "hp procurve", product: "HP ProCurve" },
        BannerRule { pattern: "brocade", product: "Brocade" },
        BannerRule { pattern: "extremeware", product: "Extreme Networks" },
        BannerRule { pattern: "gunicorn", product: "Gunicorn" },
        BannerRule { pattern: "uvicorn", product: "Uvicorn" },
        BannerRule { pattern: "node.js", product: "Node.js" },
        BannerRule { pattern: "express", product: "Express" },
        BannerRule { pattern: "jetty", product: "Jetty" },
        BannerRule { pattern: "netty", product: "Netty" },
        BannerRule { pattern: "rabbitmq", product: "RabbitMQ" },
        BannerRule { pattern: "haproxy", product: "HAProxy" },
        BannerRule { pattern: "traefik", product: "Traefik" },
        BannerRule { pattern: "envoy", product: "Envoy" },
        BannerRule { pattern: "kestrel", product: "Kestrel" },
        BannerRule { pattern: "iis", product: "IIS" },
        BannerRule { pattern: "apache", product: "Apache" },
        BannerRule { pattern: "nginx", product: "nginx" },
        BannerRule { pattern: "lighttpd", product: "lighttpd" },
        BannerRule { pattern: "caddy", product: "Caddy" },
        BannerRule { pattern: "tomcat", product: "Tomcat" },
        BannerRule { pattern: "prometheus", product: "Prometheus" },
        BannerRule { pattern: "grafana", product: "Grafana" },
        BannerRule { pattern: "vault", product: "HashiCorp Vault" },
        BannerRule { pattern: "consul", product: "Consul" },
        BannerRule { pattern: "etcd", product: "etcd" },
        BannerRule { pattern: "nomad", product: "Nomad" },
        BannerRule { pattern: "kubernetes", product: "Kubernetes" },
        BannerRule { pattern: "docker registry", product: "Docker Registry" },
        BannerRule { pattern: "gitlab", product: "GitLab" },
        BannerRule { pattern: "bitbucket", product: "Bitbucket" },
        BannerRule { pattern: "jira", product: "Jira" },
        BannerRule { pattern: "confluence", product: "Confluence" },
        BannerRule { pattern: "sonarqube", product: "SonarQube" },
        BannerRule { pattern: "nexus", product: "Sonatype Nexus" },
        BannerRule { pattern: "artifactory", product: "JFrog Artifactory" },
        BannerRule { pattern: "vnc", product: "VNC" },
        BannerRule { pattern: "rdp", product: "RDP" },
        BannerRule { pattern: "ms-wbt-server", product: "RDP" },
        BannerRule { pattern: "back orifice", product: "Back Orifice" },
    ]
}

fn build_port_map() -> HashMap<u16, &'static str> {
    let mut m = HashMap::new();
    m.insert(21, "ftp");
    m.insert(22, "ssh");
    m.insert(23, "telnet");
    m.insert(25, "smtp");
    m.insert(53, "dns");
    m.insert(69, "tftp");
    m.insert(80, "http");
    m.insert(81, "http");
    m.insert(88, "kerberos");
    m.insert(110, "pop3");
    m.insert(111, "rpcbind");
    m.insert(113, "ident");
    m.insert(119, "nntp");
    m.insert(123, "ntp");
    m.insert(135, "msrpc");
    m.insert(137, "netbios-ns");
    m.insert(139, "netbios-ssn");
    m.insert(143, "imap");
    m.insert(161, "snmp");
    m.insert(162, "snmptrap");
    m.insert(179, "bgp");
    m.insert(389, "ldap");
    m.insert(443, "https");
    m.insert(445, "microsoft-ds");
    m.insert(465, "smtps");
    m.insert(500, "ipsec");
    m.insert(514, "syslog");
    m.insert(515, "printer");
    m.insert(520, "rip");
    m.insert(521, "ripng");
    m.insert(546, "dhcpv6");
    m.insert(547, "dhcpv6");
    m.insert(554, "rtsp");
    m.insert(563, "nntps");
    m.insert(585, "imaps");
    m.insert(587, "submission");
    m.insert(593, "http-rpc-epmap");
    m.insert(636, "ldaps");
    m.insert(646, "ldp");
    m.insert(691, "msexch");
    m.insert(902, "vmware-server");
    m.insert(989, "ftps-data");
    m.insert(990, "ftps");
    m.insert(991, "nas");
    m.insert(992, "telnet-ssl");
    m.insert(993, "imaps");
    m.insert(994, "ircs");
    m.insert(995, "pop3s");
    m.insert(1025, "msrpc-nfs");
    m.insert(1026, "win-rpc");
    m.insert(1027, "win-rpc");
    m.insert(1080, "socks");
    m.insert(1099, "rmi");
    m.insert(1194, "openvpn");
    m.insert(1214, "kazaa");
    m.insert(1241, "nessus");
    m.insert(1311, "dell-openmanage");
    m.insert(1337, "waste");
    m.insert(1352, "lotus-notes");
    m.insert(1386, "checkpoint");
    m.insert(1414, "ibm-mqseries");
    m.insert(1433, "ms-sql-s");
    m.insert(1434, "ms-sql-m");
    m.insert(1494, "citrix-ica");
    m.insert(1521, "oracle");
    m.insert(1522, "oracle");
    m.insert(1524, "oracle");
    m.insert(1583, "pcanywhere");
    m.insert(1720, "h323");
    m.insert(1723, "pptp");
    m.insert(1741, "cisco-works");
    m.insert(1755, "wms");
    m.insert(1812, "radius");
    m.insert(1813, "radius-acct");
    m.insert(1883, "mqtt");
    m.insert(1900, "upnp");
    m.insert(1935, "rtmp");
    m.insert(1947, "sentinel-hasp");
    m.insert(1964, "candle");
    m.insert(1984, "bb");
    m.insert(1991, "gcp");
    m.insert(1999, "tcp-id-port");
    m.insert(2000, "cisco-scp");
    m.insert(2001, "dc");
    m.insert(2002, "globe");
    m.insert(2003, "gnutella");
    m.insert(2004, "emce");
    m.insert(2005, "bbn-mmx");
    m.insert(2006, "invokator");
    m.insert(2008, "conf");
    m.insert(2010, "pipe-server");
    m.insert(2011, "raid-cc");
    m.insert(2012, "ttyinfo");
    m.insert(2013, "raid-am");
    m.insert(2014, "troff");
    m.insert(2015, "erm");
    m.insert(2016, "talk");
    m.insert(2017, "mailbox");
    m.insert(2018, "inman");
    m.insert(2019, "il");

    // --- Extended web / app ports ---
    m.insert(2049, "nfs");
    m.insert(2082, "cpanel");
    m.insert(2083, "cpanel-ssl");
    m.insert(2086, "whm");
    m.insert(2087, "whm-ssl");
    m.insert(2095, "cpanel-webmail");
    m.insert(2096, "cpanel-webmail-ssl");
    m.insert(2100, "amqp");
    m.insert(2222, "directadmin");
    m.insert(2302, "halflife");
    m.insert(2375, "docker");
    m.insert(2376, "docker-ssl");
    m.insert(2379, "etcd");
    m.insert(2380, "etcd-peer");
    m.insert(2483, "oracle");
    m.insert(2484, "oracle-ssl");
    m.insert(2525, "smtp-alt");
    m.insert(2628, "dict");
    m.insert(2800, "spray");
    m.insert(2947, "gpsd");
    m.insert(3000, "ppp");
    m.insert(3001, "nexus");
    m.insert(3030, "ganglia");
    m.insert(3050, "interbase");
    m.insert(3074, "xbox-live");
    m.insert(3128, "squid");
    m.insert(3260, "iscsi");
    m.insert(3268, "ldap-global-catalog");
    m.insert(3269, "ldap-global-catalog-ssl");
    m.insert(3306, "mysql");
    m.insert(3307, "mysql");
    m.insert(3389, "ms-wbt-server");
    m.insert(3391, "savant");
    m.insert(3443, "pl-net");
    m.insert(3478, "stun");
    m.insert(3542, "haproxy-stats");
    m.insert(3632, "distcc");
    m.insert(3689, "daap");
    m.insert(3690, "svn");
    m.insert(3724, "wow");
    m.insert(3784, "vnc");
    m.insert(3785, "vnc");
    m.insert(4000, "icq");
    m.insert(4001, "icq");
    m.insert(4045, "nfs");
    m.insert(4080, "trojan");
    m.insert(4111, "xgrid");
    m.insert(4224, "hp-alarm");
    m.insert(4242, "grouter");
    m.insert(4321, "rwhois");
    m.insert(4333, "ahsp");
    m.insert(4443, "pharos");
    m.insert(4444, "nvram");
    m.insert(4445, "upnotify");
    m.insert(4500, "ipsec-nat-t");
    m.insert(4567, "sinatra");
    m.insert(4647, "teamtalk");
    m.insert(4662, "edonkey");
    m.insert(4711, "pulseway");
    m.insert(4712, "pulseway");
    m.insert(4730, "gear");
    m.insert(4786, "smart-install");
    m.insert(4840, "opc-ua");
    m.insert(4848, "appserver-admin");
    m.insert(4899, "radmin");
    m.insert(4949, "munin");
    m.insert(5000, "upnp");
    m.insert(5001, "iperf");
    m.insert(5003, "filemaker");
    m.insert(5004, "rtp");
    m.insert(5005, "rtp");
    m.insert(5010, "telepath");
    m.insert(5030, "mailproxy");
    m.insert(5038, "ami");
    m.insert(5050, "mmcc");
    m.insert(5051, "ida");
    m.insert(5060, "sip");
    m.insert(5061, "sips");
    m.insert(5093, "sentinel");
    m.insert(5099, "sentinel");
    m.insert(5104, "tinymail");
    m.insert(5120, "barracuda");
    m.insert(5190, "icq");
    m.insert(5222, "xmpp");
    m.insert(5223, "xmpp-ssl");
    m.insert(5269, "xmpp-server");
    m.insert(5349, "stuns");
    m.insert(5432, "postgresql");
    m.insert(5433, "postgresql");
    m.insert(5445, "smbdirect");
    m.insert(5500, "fcp");
    m.insert(5555, "freeciv");
    m.insert(5556, "freeciv");
    m.insert(5601, "kibana");
    m.insert(5631, "pcanywhere");
    m.insert(5666, "nrpe");
    m.insert(5667, "nsca");
    m.insert(5672, "amqp");
    m.insert(5673, "amqp");
    m.insert(5800, "vnc-http");
    m.insert(5801, "vnc-http");
    m.insert(5900, "vnc");
    m.insert(5901, "vnc-1");
    m.insert(5902, "vnc-2");
    m.insert(5903, "vnc-3");
    m.insert(5984, "couchdb");
    m.insert(5985, "winrm-http");
    m.insert(5986, "winrm-https");
    m.insert(6000, "x11");
    m.insert(6001, "x11-1");
    m.insert(6082, "apc-pdu");
    m.insert(6086, "apc-pdu");
    m.insert(6100, "gpsd");
    m.insert(6112, "dtspcd");
    m.insert(6123, "vnc");
    m.insert(6346, "gnutella");
    m.insert(6379, "redis");
    m.insert(6380, "redis-tls");
    m.insert(6389, "redis");
    m.insert(6443, "kubernetes");
    m.insert(6444, "kubernetes-ssl");
    m.insert(6481, "servicetags");
    m.insert(6514, "syslog-tls");
    m.insert(6515, "elipse");
    m.insert(6550, "vnc");
    m.insert(6556, "vnc");
    m.insert(6566, "sane");
    m.insert(6600, "msah");
    m.insert(6660, "irc");
    m.insert(6661, "irc");
    m.insert(6662, "irc");
    m.insert(6663, "irc");
    m.insert(6664, "irc");
    m.insert(6665, "irc");
    m.insert(6666, "irc");
    m.insert(6667, "irc");
    m.insert(6668, "irc");
    m.insert(6669, "irc");
    m.insert(6679, "irc-ssl");
    m.insert(6697, "irc-ssl");
    m.insert(6881, "bittorrent");
    m.insert(6969, "bittorrent-tracker");
    m.insert(7001, "weblogic");
    m.insert(7002, "weblogic-ssl");
    m.insert(7004, "afp");
    m.insert(7007, "afs3");
    m.insert(7010, "afs3");
    m.insert(7077, "mesos");
    m.insert(7100, "font-service");
    m.insert(7171, "tibia");
    m.insert(7200, "fodms");
    m.insert(7210, "fodms");
    m.insert(7443, "oracle-http");
    m.insert(7444, "oracle-http");
    m.insert(7474, "neo4j");
    m.insert(7475, "neo4j");
    m.insert(7496, "ovirt");
    m.insert(7547, "cwmp");
    m.insert(7675, "imq");
    m.insert(7676, "imq");
    m.insert(7777, "cbt");
    m.insert(7778, "cbt");
    m.insert(7831, "dvmrp");
    m.insert(7869, "mobile");
    m.insert(7870, "mobile");
    m.insert(7871, "mobile");
    m.insert(8000, "http-alt");
    m.insert(8001, "http-alt");
    m.insert(8002, "http-alt");
    m.insert(8003, "http-alt");
    m.insert(8004, "http-alt");
    m.insert(8005, "http-alt");
    m.insert(8006, "http-alt");
    m.insert(8007, "http-alt");
    m.insert(8008, "http-alt");
    m.insert(8009, "ajp13");
    m.insert(8010, "http-alt");
    m.insert(8011, "http-alt");
    m.insert(8012, "http-alt");
    m.insert(8013, "http-alt");
    m.insert(8014, "http-alt");
    m.insert(8015, "http-alt");
    m.insert(8016, "http-alt");
    m.insert(8017, "http-alt");
    m.insert(8018, "http-alt");
    m.insert(8019, "http-alt");
    m.insert(8020, "http-alt");
    m.insert(8080, "http-proxy");
    m.insert(8081, "http-proxy");
    m.insert(8082, "http-proxy");
    m.insert(8083, "http-proxy");
    m.insert(8084, "http-proxy");
    m.insert(8085, "http-proxy");
    m.insert(8086, "influxdb");
    m.insert(8087, "http-proxy");
    m.insert(8088, "http-proxy");
    m.insert(8089, "http-proxy");
    m.insert(8090, "http-proxy");
    m.insert(8091, "couchbase");
    m.insert(8092, "couchbase");
    m.insert(8093, "couchbase");
    m.insert(8096, "http-proxy");
    m.insert(8100, "http-proxy");
    m.insert(8181, "http-proxy");
    m.insert(8200, "vault");
    m.insert(8222, "http-proxy");
    m.insert(8243, "https-proxy");
    m.insert(8280, "http-proxy");
    m.insert(8281, "http-proxy");
    m.insert(8291, "winbox");
    m.insert(8300, "http-proxy");
    m.insert(8332, "bitcoin");
    m.insert(8333, "bitcoin");
    m.insert(8403, "http-proxy");
    m.insert(8443, "https-alt");
    m.insert(8444, "https-alt");
    m.insert(8445, "https-alt");
    m.insert(8446, "https-alt");
    m.insert(8447, "https-alt");
    m.insert(8448, "https-alt");
    m.insert(8449, "https-alt");
    m.insert(8472, "vxlan");
    m.insert(8500, "consul");
    m.insert(8501, "consul");
    m.insert(8530, "mcafee-epo");
    m.insert(8531, "mcafee-epo-ssl");
    m.insert(8600, "consul-dns");
    m.insert(8649, "ganglia");
    m.insert(8834, "nessus");
    m.insert(8843, "nessus");
    m.insert(8873, "nessus");
    m.insert(8880, "http-proxy");
    m.insert(8883, "mqtt-ssl");
    m.insert(8888, "sun-answerbook");
    m.insert(8889, "sun-answerbook");
    m.insert(8983, "solr");
    m.insert(8990, "http-proxy");
    m.insert(8991, "http-proxy");
    m.insert(8992, "http-proxy");
    m.insert(8993, "http-proxy");
    m.insert(8994, "http-proxy");
    m.insert(8995, "http-proxy");
    m.insert(8996, "http-proxy");
    m.insert(8997, "http-proxy");
    m.insert(8998, "http-proxy");
    m.insert(8999, "http-proxy");
    m.insert(9000, "cslistener");
    m.insert(9001, "tor-orport");
    m.insert(9002, "tor-dir");
    m.insert(9003, "tor");
    m.insert(9008, "http-alt");
    m.insert(9009, "pichat");
    m.insert(9010, "http-alt");
    m.insert(9042, "cassandra");
    m.insert(9043, "cassandra");
    m.insert(9050, "tor");
    m.insert(9051, "tor");
    m.insert(9060, "webmin");
    m.insert(9080, "glrpc");
    m.insert(9090, "websm");
    m.insert(9091, "websm");
    m.insert(9092, "kafka");
    m.insert(9093, "kafka-ssl");
    m.insert(9094, "kafka");
    m.insert(9095, "kafka");
    m.insert(9100, "jetdirect");
    m.insert(9101, "jetdirect");
    m.insert(9102, "jetdirect");
    m.insert(9103, "jetdirect");
    m.insert(9105, "jetdirect");
    m.insert(9119, "mxit");
    m.insert(9150, "tor");
    m.insert(9151, "tor");
    m.insert(9160, "cassandra");
    m.insert(9191, "cassandra");
    m.insert(9200, "elasticsearch");
    m.insert(9201, "elasticsearch");
    m.insert(9202, "elasticsearch");
    m.insert(9210, "elasticsearch");
    m.insert(9250, "elasticsearch");
    m.insert(9300, "elasticsearch-cluster");
    m.insert(9301, "elasticsearch-cluster");
    m.insert(9302, "elasticsearch-cluster");
    m.insert(9303, "elasticsearch-cluster");
    m.insert(9304, "elasticsearch-cluster");
    m.insert(9305, "elasticsearch-cluster");
    m.insert(9306, "elasticsearch-cluster");
    m.insert(9307, "elasticsearch-cluster");
    m.insert(9308, "elasticsearch-cluster");
    m.insert(9309, "elasticsearch-cluster");
    m.insert(9310, "elasticsearch-cluster");
    m.insert(9418, "git");
    m.insert(9443, "https-alt");
    m.insert(9500, "nfs");
    m.insert(9535, "man");
    m.insert(9594, "messageway");
    m.insert(9595, "messageway");
    m.insert(9600, "micromuse");
    m.insert(9876, "sd");
    m.insert(9877, "sd");
    m.insert(9878, "sd");
    m.insert(9898, "monkeycom");
    m.insert(9900, "iua");
    m.insert(9981, "http-alt");
    m.insert(9987, "dsm");
    m.insert(9993, "zero");
    m.insert(9994, "dsm");
    m.insert(9995, "dsm");
    m.insert(9996, "dsm");
    m.insert(9997, "splunk");
    m.insert(9998, "http-alt");
    m.insert(9999, "abyss");
    m.insert(10000, "snet-sensor-mgmt");
    m.insert(10001, "snet-sensor-mgmt");
    m.insert(10008, "http-alt");
    m.insert(10009, "http-alt");
    m.insert(10010, "http-alt");
    m.insert(10050, "zabbix-agent");
    m.insert(10051, "zabbix-trapper");
    m.insert(10113, "netiq");
    m.insert(10114, "netiq");
    m.insert(10115, "netiq");
    m.insert(10116, "netiq");
    m.insert(10117, "netiq");
    m.insert(10162, "snmp-trap");
    m.insert(10200, "ris");
    m.insert(10389, "sap");
    m.insert(10566, "sap");
    m.insert(10616, "sap");
    m.insert(10617, "sap");
    m.insert(10618, "sap");
    m.insert(10619, "sap");
    m.insert(10620, "sap");
    m.insert(10626, "sap");
    m.insert(10627, "sap");
    m.insert(10880, "sap");
    m.insert(10990, "sap");
    m.insert(11000, "sap");
    m.insert(11211, "memcached");
    m.insert(11214, "memcached");
    m.insert(11215, "memcached");
    m.insert(11371, "pgp-keyserver");
    m.insert(11433, "sap");
    m.insert(11434, "sap");
    m.insert(11877, "x2go");
    m.insert(12000, "cc");
    m.insert(12012, "viadeo");
    m.insert(12013, "viadeo");
    m.insert(12109, "rets");
    m.insert(12345, "netbus");
    m.insert(12975, "logmein");
    m.insert(12976, "logmein");
    m.insert(13337, "sap");
    m.insert(13338, "sap");
    m.insert(13722, "sap");
    m.insert(14500, "vci");
    m.insert(14567, "battlefield");
    m.insert(15000, "sap");
    m.insert(15118, "sap");
    m.insert(15119, "sap");
    m.insert(15345, "xpilot");
    m.insert(16000, "shoutcast");
    m.insert(16080, "http-alt");
    m.insert(16161, "sap");
    m.insert(16379, "redis");
    m.insert(16380, "redis");
    m.insert(16400, "sap");
    m.insert(16509, "xen");
    m.insert(16680, "sap");
    m.insert(16992, "amt");
    m.insert(16993, "amt");
    m.insert(16994, "amt");
    m.insert(16995, "amt");
    m.insert(17000, "dvr-proxy");
    m.insert(18080, "http-alt");
    m.insert(18081, "http-alt");
    m.insert(18082, "http-alt");
    m.insert(18083, "http-alt");
    m.insert(18084, "http-alt");
    m.insert(18085, "http-alt");
    m.insert(18086, "http-alt");
    m.insert(18087, "http-alt");
    m.insert(18088, "http-alt");
    m.insert(18089, "http-alt");
    m.insert(18090, "http-alt");
    m.insert(18181, "opc-ua");
    m.insert(18200, "sap");
    m.insert(18201, "sap");
    m.insert(18202, "sap");
    m.insert(18203, "sap");
    m.insert(18204, "sap");
    m.insert(18205, "sap");
    m.insert(18206, "sap");
    m.insert(18207, "sap");
    m.insert(18208, "sap");
    m.insert(18209, "sap");
    m.insert(18210, "sap");
    m.insert(18333, "bitcoin-testnet");
    m.insert(18412, "sap");
    m.insert(18413, "sap");
    m.insert(18414, "sap");
    m.insert(18609, "sap");
    m.insert(18734, "sap");
    m.insert(19000, "sap");
    m.insert(19001, "sap");
    m.insert(19101, "sap");
    m.insert(19111, "sap");
    m.insert(19131, "sap");
    m.insert(19132, "sap");
    m.insert(19133, "sap");
    m.insert(19283, "sap");
    m.insert(19315, "sap");
    m.insert(19399, "sap");
    m.insert(19999, "dnp-sec");
    m.insert(20000, "dnp-sec");
    m.insert(20001, "dnp-sec");
    m.insert(20002, "dns-alt");
    m.insert(20101, "sap");
    m.insert(20480, "emtu");
    m.insert(21025, "starbound");
    m.insert(21322, "sap");
    m.insert(21502, "sap");
    m.insert(21503, "sap");
    m.insert(21504, "sap");
    m.insert(21505, "sap");
    m.insert(21506, "sap");
    m.insert(21507, "sap");
    m.insert(21508, "sap");
    m.insert(21509, "sap");
    m.insert(21510, "sap");
    m.insert(21511, "sap");
    m.insert(21512, "sap");
    m.insert(21513, "sap");
    m.insert(21514, "sap");
    m.insert(21515, "sap");
    m.insert(21516, "sap");
    m.insert(21517, "sap");
    m.insert(21518, "sap");
    m.insert(21519, "sap");
    m.insert(21520, "sap");
    m.insert(21521, "sap");
    m.insert(21522, "sap");
    m.insert(21523, "sap");
    m.insert(21524, "sap");
    m.insert(22222, "easyengine");
    m.insert(22273, "wnn6");
    m.insert(22305, "wnn6");
    m.insert(22986, "milter");
    m.insert(23000, "inova-discover");
    m.insert(23399, "skype");
    m.insert(23424, "firemon");
    m.insert(24554, "binkp");
    m.insert(24800, "synergy");
    m.insert(25734, "sap");
    m.insert(25735, "sap");
    m.insert(26000, "quake");
    m.insert(26257, "cockroachdb");
    m.insert(27015, "hlserver");
    m.insert(27017, "mongodb");
    m.insert(27018, "mongodb");
    m.insert(27019, "mongodb");
    m.insert(27020, "mongodb");
    m.insert(27272, "sap");
    m.insert(27960, "quake3");
    m.insert(27992, "nfs");
    m.insert(28000, "sap");
    m.insert(28001, "sap");
    m.insert(28015, "rethinkdb");
    m.insert(28017, "mongodb-http");
    m.insert(28115, "rethinkdb");
    m.insert(28200, "voxel");
    m.insert(28455, "sap");
    m.insert(28777, "sap");
    m.insert(28778, "sap");
    m.insert(28804, "sap");
    m.insert(30000, "ndmp");
    m.insert(30303, "ethereum");
    m.insert(30718, "sap");
    m.insert(31337, "back-orifice");
    m.insert(31516, "sap");
    m.insert(31517, "sap");
    m.insert(31518, "sap");
    m.insert(31519, "sap");
    m.insert(31520, "sap");
    m.insert(31521, "sap");
    m.insert(31522, "sap");
    m.insert(31523, "sap");
    m.insert(31524, "sap");
    m.insert(31525, "sap");
    m.insert(31526, "sap");
    m.insert(31527, "sap");
    m.insert(31528, "sap");
    m.insert(31529, "sap");
    m.insert(31530, "sap");
    m.insert(31531, "sap");
    m.insert(31532, "sap");
    m.insert(31533, "sap");
    m.insert(31534, "sap");
    m.insert(31535, "sap");
    m.insert(31536, "sap");
    m.insert(31537, "sap");
    m.insert(31538, "sap");
    m.insert(31539, "sap");
    m.insert(31540, "sap");
    m.insert(31541, "sap");
    m.insert(31542, "sap");
    m.insert(31543, "sap");
    m.insert(31544, "sap");
    m.insert(31545, "sap");
    m.insert(31546, "sap");
    m.insert(31547, "sap");
    m.insert(31548, "sap");
    m.insert(31549, "sap");
    m.insert(31550, "sap");
    m.insert(31551, "sap");
    m.insert(31552, "sap");
    m.insert(31553, "sap");
    m.insert(31554, "sap");
    m.insert(31555, "sap");
    m.insert(31556, "sap");
    m.insert(31557, "sap");
    m.insert(31558, "sap");
    m.insert(31559, "sap");
    m.insert(31560, "sap");
    m.insert(31685, "sap");
    m.insert(31765, "sap");
    m.insert(31794, "sap");
    m.insert(31929, "sap");
    m.insert(32261, "sap");
    m.insert(32375, "sap");
    m.insert(32764, "backdoor");
    m.insert(32768, "filenet-tms");
    m.insert(32769, "filenet-rpc");
    m.insert(32771, "filenet-cs");
    m.insert(32801, "sap");
    m.insert(33060, "mysql-x");
    m.insert(33061, "mysql-x");
    m.insert(33434, "traceroute");
    m.insert(33656, "sap");
    m.insert(33848, "jenkins");
    m.insert(34324, "sap");
    m.insert(34443, "sap");
    m.insert(34444, "sap");
    m.insert(34567, "edi");
    m.insert(34577, "sap");
    m.insert(34972, "sap");
    m.insert(35000, "http-alt");
    m.insert(35001, "http-alt");
    m.insert(35002, "http-alt");
    m.insert(35003, "http-alt");
    m.insert(35004, "http-alt");
    m.insert(35005, "http-alt");
    m.insert(35006, "http-alt");
    m.insert(35007, "http-alt");
    m.insert(35008, "http-alt");
    m.insert(35009, "http-alt");
    m.insert(35010, "http-alt");
    m.insert(35011, "http-alt");
    m.insert(35012, "http-alt");
    m.insert(35013, "http-alt");
    m.insert(35014, "http-alt");
    m.insert(35015, "http-alt");
    m.insert(35016, "http-alt");
    m.insert(35017, "http-alt");
    m.insert(35018, "http-alt");
    m.insert(35019, "http-alt");
    m.insert(35020, "http-alt");
    m.insert(35021, "http-alt");
    m.insert(35022, "http-alt");
    m.insert(35023, "http-alt");
    m.insert(35024, "http-alt");
    m.insert(35025, "http-alt");
    m.insert(35026, "http-alt");
    m.insert(35027, "http-alt");
    m.insert(35028, "http-alt");
    m.insert(35029, "http-alt");
    m.insert(35030, "http-alt");
    m.insert(35432, "sap");
    m.insert(35555, "sap");
    m.insert(35800, "sap");
    m.insert(36789, "sap");
    m.insert(36885, "sap");
    m.insert(36886, "sap");
    m.insert(36887, "sap");
    m.insert(36888, "sap");
    m.insert(37008, "sap");
    m.insert(37333, "sap");
    m.insert(37434, "sap");
    m.insert(37537, "sap");
    m.insert(37777, "sap");
    m.insert(37877, "sap");
    m.insert(37978, "sap");
    m.insert(38001, "sap");
    m.insert(38005, "sap");
    m.insert(38009, "sap");
    m.insert(38013, "sap");
    m.insert(38017, "sap");
    m.insert(38021, "sap");
    m.insert(38584, "sap");
    m.insert(38891, "sap");
    m.insert(40000, "safetynet");
    m.insert(40001, "sap");
    m.insert(40080, "sap");
    m.insert(40125, "sap");
    m.insert(40827, "sap");
    m.insert(41111, "sap");
    m.insert(41529, "sap");
    m.insert(41530, "sap");
    m.insert(41531, "sap");
    m.insert(41532, "sap");
    m.insert(41770, "sap");
    m.insert(42510, "sap");
    m.insert(43000, "sap");
    m.insert(43120, "sap");
    m.insert(43556, "sap");
    m.insert(43668, "sap");
    m.insert(44311, "sap");
    m.insert(44444, "sap");
    m.insert(45555, "sap");
    m.insert(45678, "sap");
    m.insert(47100, "sap");
    m.insert(47101, "sap");
    m.insert(47102, "sap");
    m.insert(47103, "sap");
    m.insert(47549, "sap");
    m.insert(47550, "sap");
    m.insert(47623, "sap");
    m.insert(47624, "sap");
    m.insert(47806, "sap");
    m.insert(48000, "sap");
    m.insert(48001, "sap");
    m.insert(48002, "sap");
    m.insert(48003, "sap");
    m.insert(48004, "sap");
    m.insert(48005, "sap");
    m.insert(48006, "sap");
    m.insert(48007, "sap");
    m.insert(48008, "sap");
    m.insert(48009, "sap");
    m.insert(48010, "sap");
    m.insert(48543, "sap");
    m.insert(49152, "unknown");
    m.insert(49153, "unknown");
    m.insert(49154, "unknown");
    m.insert(49155, "unknown");
    m.insert(49156, "unknown");
    m.insert(49157, "unknown");
    m.insert(49158, "unknown");
    m.insert(49159, "unknown");
    m.insert(49160, "unknown");
    m.insert(49161, "unknown");
    m.insert(49162, "unknown");
    m.insert(49163, "unknown");
    m.insert(49164, "unknown");
    m.insert(49165, "unknown");
    m.insert(49166, "unknown");
    m.insert(49167, "unknown");
    m.insert(49168, "unknown");
    m.insert(49169, "unknown");
    m.insert(49170, "unknown");
    m.insert(49171, "unknown");
    m.insert(49172, "unknown");
    m.insert(49173, "unknown");
    m.insert(49174, "unknown");
    m.insert(49175, "unknown");
    m.insert(49176, "unknown");
    m.insert(49177, "unknown");
    m.insert(49178, "unknown");
    m.insert(49179, "unknown");
    m.insert(49180, "unknown");
    m.insert(49181, "unknown");
    m.insert(49182, "unknown");
    m.insert(49183, "unknown");
    m.insert(49184, "unknown");
    m.insert(49185, "unknown");
    m.insert(49186, "unknown");
    m.insert(49187, "unknown");
    m.insert(49188, "unknown");
    m.insert(49189, "unknown");
    m.insert(49190, "unknown");
    m.insert(49191, "unknown");
    m.insert(49192, "unknown");
    m.insert(49193, "unknown");
    m.insert(49194, "unknown");
    m.insert(49195, "unknown");
    m.insert(49196, "unknown");
    m.insert(49197, "unknown");
    m.insert(49198, "unknown");
    m.insert(49199, "unknown");
    m.insert(49200, "unknown");
    m.insert(49201, "unknown");
    m.insert(49202, "unknown");
    m.insert(49203, "unknown");
    m.insert(49204, "unknown");
    m.insert(49205, "unknown");
    m.insert(49206, "unknown");
    m.insert(49207, "unknown");
    m.insert(49208, "unknown");
    m.insert(49209, "unknown");
    m.insert(49210, "unknown");
    m.insert(50000, "sap");
    m.insert(50001, "sap");
    m.insert(50002, "sap");
    m.insert(50003, "sap");
    m.insert(50004, "sap");
    m.insert(50005, "sap");
    m.insert(50006, "sap");
    m.insert(50007, "sap");
    m.insert(50008, "sap");
    m.insert(50009, "sap");
    m.insert(50010, "sap");
    m.insert(50011, "sap");
    m.insert(50012, "sap");
    m.insert(50013, "sap");
    m.insert(50014, "sap");
    m.insert(50015, "sap");
    m.insert(50016, "sap");
    m.insert(50017, "sap");
    m.insert(50018, "sap");
    m.insert(50019, "sap");
    m.insert(50020, "sap");
    m.insert(50021, "sap");
    m.insert(50022, "sap");
    m.insert(50023, "sap");
    m.insert(50024, "sap");
    m.insert(50025, "sap");
    m.insert(50026, "sap");
    m.insert(50027, "sap");
    m.insert(50028, "sap");
    m.insert(50029, "sap");
    m.insert(50030, "sap");
    m.insert(50031, "sap");
    m.insert(50032, "sap");
    m.insert(50033, "sap");
    m.insert(50034, "sap");
    m.insert(50035, "sap");
    m.insert(50036, "sap");
    m.insert(50037, "sap");
    m.insert(50038, "sap");
    m.insert(50039, "sap");
    m.insert(50040, "sap");
    m.insert(50041, "sap");
    m.insert(50042, "sap");
    m.insert(50043, "sap");
    m.insert(50044, "sap");
    m.insert(50045, "sap");
    m.insert(50046, "sap");
    m.insert(50047, "sap");
    m.insert(50048, "sap");
    m.insert(50049, "sap");
    m.insert(50050, "sap");
    m.insert(50070, "hadoop");
    m.insert(50075, "hadoop");
    m.insert(50090, "hadoop");
    m.insert(50100, "sap");
    m.insert(50200, "sap");
    m.insert(50300, "sap");
    m.insert(50400, "sap");
    m.insert(50500, "sap");
    m.insert(50600, "sap");
    m.insert(50700, "sap");
    m.insert(50800, "sap");
    m.insert(50900, "sap");
    m.insert(51000, "sap");
    m.insert(51111, "sap");
    m.insert(51234, "sap");
    m.insert(51515, "sap");
    m.insert(51666, "sap");
    m.insert(51777, "sap");
    m.insert(51888, "sap");
    m.insert(51999, "sap");
    m.insert(52000, "sap");
    m.insert(52001, "sap");
    m.insert(52002, "sap");
    m.insert(52003, "sap");
    m.insert(52004, "sap");
    m.insert(52005, "sap");
    m.insert(52006, "sap");
    m.insert(52007, "sap");
    m.insert(52008, "sap");
    m.insert(52009, "sap");
    m.insert(52010, "sap");
    m.insert(52100, "sap");
    m.insert(52200, "sap");
    m.insert(52299, "sap");
    m.insert(52300, "sap");
    m.insert(52400, "sap");
    m.insert(52500, "sap");
    m.insert(52600, "sap");
    m.insert(52700, "sap");
    m.insert(52800, "sap");
    m.insert(52900, "sap");
    m.insert(53000, "sap");
    m.insert(53100, "sap");
    m.insert(53200, "sap");
    m.insert(53300, "sap");
    m.insert(53400, "sap");
    m.insert(53500, "sap");
    m.insert(53600, "sap");
    m.insert(53700, "sap");
    m.insert(53800, "sap");
    m.insert(53900, "sap");
    m.insert(54000, "sap");
    m.insert(54100, "sap");
    m.insert(54200, "sap");
    m.insert(54300, "sap");
    m.insert(54400, "sap");
    m.insert(54500, "sap");
    m.insert(54600, "sap");
    m.insert(54700, "sap");
    m.insert(54800, "sap");
    m.insert(54900, "sap");
    m.insert(55000, "sap");
    m.insert(55001, "sap");
    m.insert(55002, "sap");
    m.insert(55003, "sap");
    m.insert(55004, "sap");
    m.insert(55005, "sap");
    m.insert(55006, "sap");
    m.insert(55100, "sap");
    m.insert(55200, "sap");
    m.insert(55300, "sap");
    m.insert(55400, "sap");
    m.insert(55500, "sap");
    m.insert(55600, "sap");
    m.insert(55700, "sap");
    m.insert(55800, "sap");
    m.insert(55900, "sap");
    m.insert(56000, "sap");
    m.insert(56100, "sap");
    m.insert(56200, "sap");
    m.insert(56300, "sap");
    m.insert(56400, "sap");
    m.insert(56500, "sap");
    m.insert(56600, "sap");
    m.insert(56700, "sap");
    m.insert(56800, "sap");
    m.insert(56900, "sap");
    m.insert(57000, "sap");
    m.insert(57100, "sap");
    m.insert(57200, "sap");
    m.insert(57300, "sap");
    m.insert(57400, "sap");
    m.insert(57500, "sap");
    m.insert(57600, "sap");
    m.insert(57700, "sap");
    m.insert(57800, "sap");
    m.insert(57900, "sap");
    m.insert(58000, "sap");
    m.insert(58100, "sap");
    m.insert(58200, "sap");
    m.insert(58300, "sap");
    m.insert(58400, "sap");
    m.insert(58500, "sap");
    m.insert(58600, "sap");
    m.insert(58700, "sap");
    m.insert(58800, "sap");
    m.insert(58900, "sap");
    m.insert(59000, "sap");
    m.insert(59100, "sap");
    m.insert(59200, "sap");
    m.insert(59300, "sap");
    m.insert(59400, "sap");
    m.insert(59500, "sap");
    m.insert(59600, "sap");
    m.insert(59700, "sap");
    m.insert(59800, "sap");
    m.insert(59900, "sap");
    m.insert(60000, "sap");
    m.insert(60100, "sap");
    m.insert(60200, "sap");
    m.insert(60300, "sap");
    m.insert(60400, "sap");
    m.insert(60500, "sap");
    m.insert(60600, "sap");
    m.insert(60700, "sap");
    m.insert(60800, "sap");
    m.insert(60900, "sap");
    m.insert(61000, "sap");
    m.insert(61616, "activemq");
    m
}   
