use async_trait::async_trait;
use std::time::{Duration, Instant};
use tokio::time::timeout;

use crate::core::credential::Credential;
use crate::core::engine::connect_tcp;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

pub struct SipProtocol;

fn build_register_request(host: &str, user: &str) -> String {
    format!(
        "REGISTER sip:{} SIP/2.0\r\n\
         Via: SIP/2.0/TCP client\r\n\
         From: <sip:{}@{}>\r\n\
         To: <sip:{}@{}>\r\n\
         Call-ID: 1\r\n\
         CSeq: 1 REGISTER\r\n\
         Max-Forwards: 70\r\n\
         Content-Length: 0\r\n\
         \r\n",
        host, user, host, user, host
    )
}

fn build_register_with_auth(host: &str, user: &str, realm: &str, nonce: &str) -> String {
    let response = "xxx";
    format!(
        "REGISTER sip:{} SIP/2.0\r\n\
         Via: SIP/2.0/TCP client\r\n\
         From: <sip:{}@{}>\r\n\
         To: <sip:{}@{}>\r\n\
         Call-ID: 1\r\n\
         CSeq: 2 REGISTER\r\n\
         Authorization: Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"sip:{}\", response=\"{}\"\r\n\
         Max-Forwards: 70\r\n\
         Content-Length: 0\r\n\
         \r\n",
        host, user, host, user, host,
        user, realm, nonce, host, response
    )
}

fn extract_param(header: &str, name: &str) -> Option<String> {
    let lower = header.to_lowercase();
    let search = format!("{}=", name);
    if let Some(pos) = lower.find(&search) {
        let start = pos + search.len();
        let rest = &header[start..];
        let val = if rest.starts_with('"') {
            let end = rest[1..].find('"').map(|i| i + 1).unwrap_or(rest.len());
            &rest[1..end]
        } else {
            let end = rest.find(|c: char| c == ',' || c == ' ' || c == '\r' || c == '\n').unwrap_or(rest.len());
            &rest[..end]
        };
        Some(val.to_string())
    } else {
        None
    }
}

#[async_trait]
impl Protocol for SipProtocol {
    fn name(&self) -> &'static str {
        "sip"
    }

    fn default_port(&self) -> u16 {
        5060
    }

    async fn authenticate(
        &self,
        target: &Target,
        credential: &Credential,
        timeout_dur: Duration,
        proxy: &Option<ProxyConfig>,
    ) -> AuthResult {
        let start = Instant::now();
        match timeout(timeout_dur, async {
            let mut stream = connect_tcp(&target.addr_string(), timeout_dur, proxy).await?;
            let register = build_register_request(&target.host, &credential.username);
            stream.write_str(&register).await.map_err(|e| format!("Write REGISTER: {}", e))?;
            let mut line_buf = Vec::new();
            let status_line = stream.read_line(&mut line_buf, timeout_dur).await?;
            let status_upper = status_line.to_uppercase();
            if status_upper.contains("200 OK") {
                return Ok(AuthResult::new(
                    target.host.clone(), target.port, "sip",
                    credential.username.clone(), credential.password.clone(),
                    true, start.elapsed(), None,
                ));
            }
            if status_upper.contains("401 UNAUTHORIZED") || status_upper.contains("403 FORBIDDEN") {
                let mut _realm = String::new();
                let mut _nonce = String::new();
                loop {
                    let hdr = stream.read_line(&mut line_buf, timeout_dur).await?;
                    if hdr.is_empty() || hdr == "\r" {
                        break;
                    }
                    if hdr.to_lowercase().starts_with("www-authenticate") {
                        if let Some(r) = extract_param(&hdr, "realm") {
                            _realm = r;
                        }
                        if let Some(n) = extract_param(&hdr, "nonce") {
                            _nonce = n;
                        }
                    }
                }
                let auth_reg = build_register_with_auth(
                    &target.host, &credential.username,
                    &_realm, &_nonce,
                );
                stream.write_str(&auth_reg).await.map_err(|e| format!("Write auth REGISTER: {}", e))?;
                let auth_status = stream.read_line(&mut line_buf, timeout_dur).await?;
                if auth_status.to_uppercase().contains("200 OK") {
                    return Ok(AuthResult::new(
                        target.host.clone(), target.port, "sip",
                        credential.username.clone(), credential.password.clone(),
                        true, start.elapsed(), None,
                    ));
                }
                return Ok(AuthResult::new(
                    target.host.clone(), target.port, "sip",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(),
                    Some(format!("Auth response: {}", auth_status)),
                ));
            }
            Ok(AuthResult::new(
                target.host.clone(), target.port, "sip",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(),
                Some(format!("Status: {}", status_line)),
            ))
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(target.host.clone(), target.port, "sip",
                credential.username.clone(), credential.password.clone(), false, start.elapsed(), Some(e)),
            Err(_) => AuthResult::new(target.host.clone(), target.port, "sip",
                credential.username.clone(), credential.password.clone(), false, start.elapsed(), Some("Timeout".into())),
        }
    }
}
