pub mod negotiation;

use async_trait::async_trait;
use std::time::{Duration, Instant};
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::time::timeout;

use crate::core::credential::Credential;
use crate::core::engine::{connect_tcp, ResponseBuffer};
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

pub struct TelnetProtocol;

const SUCCESS_INDICATORS: &[&str] = &[
    "last login", "$ ", "# ", "> ", "~$ ",
    "welcome", "shell", "successful", "logged in",
];
const FAILURE_INDICATORS: &[&str] = &[
    "incorrect", "invalid", "failed", "denied", "wrong",
    "error", "try again", "unauthorized", "rejected",
    "bad", "failed login", "login failed", "not found",
    "password:", "login:", "user:", "username:",
];

async fn read_with_negotiation(
    stream: &mut tokio::net::TcpStream,
    timeout_dur: Duration,
    stop_chars: &[char],
) -> Result<ResponseBuffer, String> {
    let start = tokio::time::Instant::now();
    let mut resp = ResponseBuffer::new();
    loop {
        let elapsed = start.elapsed();
        if elapsed >= timeout_dur { break; }
        let remaining = timeout_dur - elapsed;
        let mut byte = [0u8; 1];
        match timeout(remaining, stream.read(&mut byte)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(_)) => {
                if byte[0] == 255 {
                    let mut iac = [0u8; 2];
                    if stream.read_exact(&mut iac).await.is_ok() {
                        match iac[0] {
                            253 | 251 => {
                                let resp_bytes = [255, if iac[0] == 253 { 252 } else { 254 }, iac[1]];
                                stream.write_all(&resp_bytes).await.ok();
                            }
                            _ => {}
                        }
                    }
                } else {
                    resp.extend(&byte);
                    let c = byte[0] as char;
                    if stop_chars.contains(&c) {
                        break;
                    }
                }
            }
            Ok(Err(_)) | Err(_) => break,
        }
    }
    Ok(resp)
}

#[async_trait]
impl Protocol for TelnetProtocol {
    fn name(&self) -> &'static str { "telnet" }
    fn default_port(&self) -> u16 { 23 }

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

            let banner = read_with_negotiation(
                stream.get_mut(), Duration::from_secs(3), &[':'],
            ).await?;

            let initial = banner.as_str().to_lowercase();

            if initial.contains("password:") {
                stream.write_line(&format!("{}\r\n", credential.password)).await?;
            } else {
                stream.write_line(&format!("{}\r\n", credential.username)).await?;

                let pw_prompt = read_with_negotiation(
                    stream.get_mut(), Duration::from_millis(1500), &[':'],
                ).await?;

                let pw_text = pw_prompt.as_str().to_lowercase();
                if !pw_text.contains("assword") && !pw_text.contains(':') {
                    return Ok(AuthResult::new(target.host.clone(), target.port, "telnet",
                        credential.username.clone(), credential.password.clone(),
                        false, start.elapsed(), Some("No password prompt".into())));
                }

                stream.write_line(&format!("{}\r\n", credential.password)).await?;
            }

            // Read response
            let mut resp = ResponseBuffer::new();
            let response_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
            loop {
                let remaining = response_deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() { break; }
                let mut byte = [0u8; 1];
                match timeout(remaining, stream.get_mut().read(&mut byte)).await {
                    Ok(Ok(n)) if n > 0 => {
                        if byte[0] != 255 {
                            resp.extend(&byte);
                        }
                        let text = resp.as_str().to_lowercase();

                        let has_success = SUCCESS_INDICATORS.iter().any(|s| text.contains(s));
                        let has_failure = FAILURE_INDICATORS.iter().any(|s| text.contains(s));

                        if has_success && !has_failure {
                            return Ok(AuthResult::new(target.host.clone(), target.port, "telnet",
                                credential.username.clone(), credential.password.clone(),
                                true, start.elapsed(), None));
                        }
                        if has_failure {
                            return Ok(AuthResult::new(target.host.clone(), target.port, "telnet",
                                credential.username.clone(), credential.password.clone(),
                                false, start.elapsed(), Some(resp.as_str().to_string())));
                        }
                    }
                    _ => break,
                }
            }

            let text = resp.as_str().to_lowercase();
            let has_failure = FAILURE_INDICATORS.iter().any(|s| text.contains(s));
            let has_shell = text.contains("last login") || text.contains("$ ")
                || text.contains("# ") || text.contains("> ");
            let success = has_shell || (text.contains("welcome") && !has_failure);

            Ok(AuthResult::new(target.host.clone(), target.port, "telnet",
                credential.username.clone(), credential.password.clone(),
                success, start.elapsed(),
                if success { None } else { Some(resp.as_str().to_string()) }))
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(target.host.clone(), target.port, "telnet",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(e)),
            Err(_) => AuthResult::new(target.host.clone(), target.port, "telnet",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("Timeout".into())),
        }
    }
}
